package aegis

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/internal/aegis/authenticate"
	"github.com/heliannuuthus/helios/internal/aegis/authorize"
	"github.com/heliannuuthus/helios/internal/aegis/cache"
	"github.com/heliannuuthus/helios/internal/aegis/challenge"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/idp"
	"github.com/heliannuuthus/helios/internal/aegis/token"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	// AuthSessionCookie Auth 会话 Cookie 名称
	AuthSessionCookie = "aegis-session"
)

// AuthStage 认证阶段
type AuthStage string

const (
	StageLogin    AuthStage = "login"    // 登录阶段
	StageConsent  AuthStage = "consent"  // 授权同意阶段
	StageMFA      AuthStage = "mfa"      // MFA 验证阶段
	StageCallback AuthStage = "callback" // IDP 回调阶段
	StageComplete AuthStage = "complete" // 完成阶段（重定向回应用）
	StageError    AuthStage = "error"    // 错误阶段
)

// Handler 认证处理器（编排层）
type Handler struct {
	authenticateSvc *authenticate.Service
	authorizeSvc    *authorize.Service
	challengeSvc    *challenge.Service
	cache           *cache.Manager
	tokenSvc        *token.Service
}

// HandlerConfig Handler 配置
type HandlerConfig struct {
	AuthenticateSvc *authenticate.Service
	AuthorizeSvc    *authorize.Service
	ChallengeSvc    *challenge.Service
	Cache           *cache.Manager
	TokenSvc        *token.Service
}

// NewHandler 创建认证处理器
func NewHandler(cfg *HandlerConfig) *Handler {
	return &Handler{
		authenticateSvc: cfg.AuthenticateSvc,
		authorizeSvc:    cfg.AuthorizeSvc,
		challengeSvc:    cfg.ChallengeSvc,
		cache:           cfg.Cache,
		tokenSvc:        cfg.TokenSvc,
	}
}

// CacheManager 返回缓存管理器（用于 CORS 中间件等）
func (h *Handler) CacheManager() *cache.Manager {
	return h.cache
}

// Authorize POST /auth/authorize
// 创建认证会话
func (h *Handler) Authorize(c *gin.Context) {
	var req types.AuthRequest
	if err := c.ShouldBind(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	logger.Infof("[Handler] Authorize request: %+v", req)

	// 创建 AuthFlow
	// 前置检查错误直接返回 error，流程内错误通过 flow.Error 返回
	flow, err := h.authenticateSvc.CreateFlow(c, &req)
	if err != nil {
		// 前置检查失败，直接返回错误（不设置 Cookie，不重定向）
		h.errorResponse(c, err)
		return
	}

	// 设置 Cookie（flowID 作为 session）
	setAuthSessionCookie(c, flow.ID)

	// 根据 flow 状态决定下一步（包括错误处理）
	forwardNext(c, flow)
}

// GetConnections GET /auth/connections
// 获取可用的 Connection 配置（按类别分类：idp, vchan, mfa）
func (h *Handler) GetConnections(c *gin.Context) {
	// 从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("missing aegis-session cookie"))
		return
	}

	// 获取 AuthFlow
	flow := h.authenticateSvc.GetAndValidateFlow(c.Request.Context(), flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	// 获取可用的 ConnectionsMap
	connectionsMap := h.authenticateSvc.GetAvailableConnections(flow)

	c.JSON(http.StatusOK, connectionsMap)
}

// ApplicationInfo 应用信息
type ApplicationInfo struct {
	AppID   string  `json:"app_id"`
	Name    string  `json:"name"`
	LogoURL *string `json:"logo_url,omitempty"`
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	ServiceID   string  `json:"service_id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// AuthContextResponse 认证上下文响应（/auth/context 接口返回给前端的公开信息）
type AuthContextResponse struct {
	Application *ApplicationInfo `json:"application,omitempty"`
	Service     *ServiceInfo     `json:"service,omitempty"`
}

// GetFlowInfo GET /auth/context
// 获取当前认证流程的应用和服务信息
func (h *Handler) GetFlowInfo(c *gin.Context) {
	// 从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("missing aegis-session cookie"))
		return
	}

	// 获取 AuthFlow
	flow := h.authenticateSvc.GetAndValidateFlow(c.Request.Context(), flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	// 构建响应
	resp := &AuthContextResponse{}

	if flow.Application != nil {
		resp.Application = &ApplicationInfo{
			AppID:   flow.Application.AppID,
			Name:    flow.Application.Name,
			LogoURL: flow.Application.LogoURL,
		}
	}

	if flow.Service != nil {
		resp.Service = &ServiceInfo{
			ServiceID:   flow.Service.ServiceID,
			Name:        flow.Service.Name,
			Description: flow.Service.Description,
		}
	}

	c.JSON(http.StatusOK, resp)
}

// Login POST /auth/login
// 处理登录
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// 从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("missing aegis-session cookie"))
		return
	}

	ctx := c.Request.Context()

	// 1. 获取 AuthFlow
	flow := h.authenticateSvc.GetAndValidateFlow(ctx, flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	// 2. 执行认证 - 构建 data map
	data := map[string]any{
		"principal": req.Principal,
		"proof":     req.Proof,
		"strategy":  req.Strategy,
	}

	authResult, err := h.authenticateSvc.Authenticate(ctx, flow, req.Connection, data)
	if err != nil {
		logger.Errorf("[Handler] 认证失败: %v", err)
		h.errorResponse(c, autherrors.NewAccessDenied(err.Error()))
		return
	}

	// 3. 根据 IDP 类型决定用户处理逻辑
	var user *models.UserWithDecrypted
	var isNewUser bool

	if idp.SupportsAutoCreate(req.Connection) {
		// CIAM 社交登录：自动创建用户
		userReq := &models.FindOrCreateUserRequest{
			DomainID:   string(idp.GetDomain(req.Connection)),
			IDP:        req.Connection,
			ProviderID: authResult.ProviderID,
			RawData:    authResult.RawData,
		}

		user, isNewUser, err = h.cache.FindOrCreateUser(ctx, userReq)
		if err != nil {
			logger.Errorf("[Handler] 查找/创建用户失败: %v", err)
			h.errorResponse(c, autherrors.NewServerError("user management failed"))
			return
		}
	} else {
		// PIAM 登录（邮箱/企业微信等）：用户必须已存在
		// 对于邮箱登录，authResult.ProviderID 已经是 OpenID（在 EmailAuthenticator 中查找过用户）
		// 对于其他 PIAM IDP，需要通过 identity 查找
		if req.Connection == idp.TypeEmail {
			// 邮箱登录：ProviderID 是 OpenID
			user, err = h.cache.GetUser(ctx, authResult.ProviderID)
		} else {
			// 其他 PIAM IDP：通过 identity 查找
			user, err = h.cache.GetUserByIdentity(ctx, req.Connection, authResult.ProviderID)
		}

		if err != nil {
			logger.Errorf("[Handler] PIAM 用户不存在: %v", err)
			h.errorResponse(c, autherrors.NewAccessDenied("user not found or not authorized"))
			return
		}

		isNewUser = false
	}

	// 4. 更新 flow
	flow.SetAuthenticated(req.Connection, authResult.ProviderID, user, isNewUser)

	// 5. 准备授权（检查身份要求）
	if err := h.authorizeSvc.PrepareAuthorization(ctx, flow); err != nil {
		logger.Errorf("[Handler] 准备授权失败: %v", err)
		h.errorResponse(c, err)
		return
	}

	// 6. 生成授权码
	authCode, err := h.authorizeSvc.GenerateAuthCode(ctx, flow)
	if err != nil {
		logger.Errorf("[Handler] 生成授权码失败: %v", err)
		h.errorResponse(c, autherrors.NewServerError(err.Error()))
		return
	}

	// 7. 保存更新后的 flow
	if err := h.authenticateSvc.SaveFlow(ctx, flow); err != nil {
		logger.Warnf("[Handler] 保存 flow 失败: %v", err)
	}

	// 8. 删除 flow（设置短 TTL）
	if err := h.authenticateSvc.DeleteFlow(ctx, flowID); err != nil {
		logger.Warnf("[Handler] 删除 flow 失败: %v", err)
	}

	// 9. 构建响应
	redirectURI := flow.Request.RedirectURI + "?code=" + authCode.Code
	if authCode.State != "" {
		redirectURI += "&state=" + authCode.State
	}

	// 清除 Cookie
	clearAuthSessionCookie(c)

	c.JSON(http.StatusOK, LoginResponse{
		Code:        authCode.Code,
		RedirectURI: redirectURI,
	})
}

// Token POST /auth/token
// 换取 Token
func (h *Handler) Token(c *gin.Context) {
	var req authorize.TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	resp, err := h.authorizeSvc.ExchangeToken(c.Request.Context(), &req)
	if err != nil {
		h.errorResponse(c, autherrors.NewInvalidGrant(err.Error()))
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Revoke POST /auth/revoke
// 撤销 Token
func (h *Handler) Revoke(c *gin.Context) {
	var req RevokeRequest
	if err := c.ShouldBind(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// RFC 7009: 即使 token 无效，也应返回 200
	if err := h.authorizeSvc.RevokeToken(c.Request.Context(), req.Token); err != nil {
		logger.Warnf("[Handler] revoke token failed: %v", err)
	}
	c.Status(http.StatusOK)
}

// Check POST /auth/check
// 关系检查接口（使用 CAT 认证）
// 检查指定主体是否具有指定的关系权限
// 返回：
//   - 200: 检查完成（permitted: true/false）
//   - 401: CAT 无效
func (h *Handler) Check(c *gin.Context) {
	// 1. 验证 CAT
	cat := c.GetHeader("Authorization")
	if cat == "" {
		c.JSON(http.StatusUnauthorized, CheckResponse{
			Permitted: false,
			Error:     "unauthorized",
			Message:   "missing CAT",
		})
		return
	}

	// 去掉 Bearer 前缀
	if len(cat) > 7 && cat[:7] == "Bearer " {
		cat = cat[7:]
	}

	ctx := c.Request.Context()

	// 验证 CAT
	catClaims, err := h.tokenSvc.VerifyCAT(ctx, cat)
	if err != nil {
		logger.Debugf("[Handler] verify CAT failed: %v", err)
		c.JSON(http.StatusUnauthorized, CheckResponse{
			Permitted: false,
			Error:     "unauthorized",
			Message:   "invalid CAT",
		})
		return
	}

	// 2. 解析请求
	var req CheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// 3. 获取 serviceID（使用 CAT 签发者的 clientID 查询其所属服务）
	serviceID := catClaims.ClientID

	// 4. 设置默认值
	objectType := req.ObjectType
	if objectType == "" {
		objectType = "*"
	}
	objectID := req.ObjectID
	if objectID == "" {
		objectID = "*"
	}

	// 5. 检查关系
	hasRelation, err := h.checkRelation(ctx, serviceID, req.SubjectID, req.Relation, objectType, objectID)
	if err != nil {
		logger.Warnf("[Handler] check relation failed: %v", err)
		c.JSON(http.StatusInternalServerError, CheckResponse{
			Permitted: false,
			Error:     "internal_error",
			Message:   "check relation failed",
		})
		return
	}

	c.JSON(http.StatusOK, CheckResponse{
		Permitted: hasRelation,
	})
}

// checkRelation 检查用户是否具有指定的关系
func (h *Handler) checkRelation(ctx context.Context, serviceID, subjectID, relation, objectType, objectID string) (bool, error) {
	// 从 hermes 查询关系
	relationships, err := h.cache.ListRelationships(ctx, serviceID, "user", subjectID)
	if err != nil {
		return false, err
	}

	// 检查是否有匹配的关系
	for _, rel := range relationships {
		// 检查关系类型匹配
		if rel.Relation != relation && rel.Relation != "*" {
			continue
		}

		// 检查资源类型匹配
		if objectType != "*" && rel.ObjectType != objectType && rel.ObjectType != "*" {
			continue
		}

		// 检查资源 ID 匹配
		if objectID != "*" && rel.ObjectID != objectID && rel.ObjectID != "*" {
			continue
		}

		return true, nil
	}

	return false, nil
}

// Logout POST /auth/logout
// 登出
func (h *Handler) Logout(c *gin.Context) {
	claims := GetClaims(c)
	if claims == nil {
		h.errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	if err := h.authorizeSvc.RevokeAllTokens(c.Request.Context(), claims.Subject); err != nil {
		h.errorResponse(c, autherrors.NewServerError("failed to revoke tokens"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// UserInfo GET /auth/userinfo
// 获取用户信息
func (h *Handler) UserInfo(c *gin.Context) {
	claims := GetClaims(c)
	if claims == nil {
		h.errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	resp, err := h.authorizeSvc.GetUserInfo(c.Request.Context(), claims.Subject, claims.Scope)
	if err != nil {
		h.errorResponse(c, autherrors.NewUserNotFound("user not found"))
		return
	}

	c.JSON(http.StatusOK, resp)
}

// UpdateUserInfo PUT /auth/userinfo
// 更新用户信息
func (h *Handler) UpdateUserInfo(c *gin.Context) {
	claims := GetClaims(c)
	if claims == nil {
		h.errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	var req UpdateUserInfoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// TODO: 实现用户信息更新（通过 CacheManager 调用 UserService）

	// 返回更新后的用户信息
	resp, err := h.authorizeSvc.GetUserInfo(c.Request.Context(), claims.Subject, claims.Scope)
	if err != nil {
		h.errorResponse(c, autherrors.NewServerError(err.Error()))
		return
	}

	c.JSON(http.StatusOK, resp)
}

// JWKS GET /.well-known/jwks.json
// 获取 JWKS
func (h *Handler) JWKS(c *gin.Context) {
	clientID := c.Query("client_id")
	if clientID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("client_id is required"))
		return
	}

	jwks, err := h.authorizeSvc.GetJWKS(c.Request.Context(), clientID)
	if err != nil {
		h.errorResponse(c, autherrors.NewClientNotFound(err.Error()))
		return
	}

	c.JSON(http.StatusOK, jwks)
}

// SendEmailCode POST /auth/email/code
// 发送邮箱验证码
func (h *Handler) SendEmailCode(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	if err := h.authenticateSvc.SendEmailCode(c.Request.Context(), req.Email); err != nil {
		h.errorResponse(c, autherrors.NewServerError(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// InitiateChallenge POST /auth/challenge
// 发起 Challenge
func (h *Handler) InitiateChallenge(c *gin.Context) {
	if h.challengeSvc == nil {
		h.errorResponse(c, autherrors.NewServerError("challenge service not configured"))
		return
	}

	var req challenge.CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// 获取客户端 IP
	remoteIP := c.ClientIP()

	resp, err := h.challengeSvc.Create(c.Request.Context(), &req, remoteIP)
	if err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ContinueChallenge PUT /auth/challenge
// 继续 Challenge（提交验证）
func (h *Handler) ContinueChallenge(c *gin.Context) {
	if h.challengeSvc == nil {
		h.errorResponse(c, autherrors.NewServerError("challenge service not configured"))
		return
	}

	// 从 query 获取 challenge_id
	challengeID := c.Query("challenge_id")
	if challengeID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("challenge_id is required"))
		return
	}

	var req challenge.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// 获取客户端 IP
	remoteIP := c.ClientIP()

	resp, err := h.challengeSvc.Verify(c.Request.Context(), challengeID, &req, remoteIP)
	if err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	c.JSON(http.StatusOK, resp)
}

// IDPs GET /idps
// 获取可用的身份提供方列表（旧接口，返回 ConnectionsMap）
func (h *Handler) IDPs(c *gin.Context) {
	// 尝试从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil {
		flowID = "" // Cookie 不存在时使用空字符串
	}

	var connectionsMap *types.ConnectionsMap

	if flowID != "" {
		// 如果有 flow，从 flow 获取
		flow := h.authenticateSvc.GetAndValidateFlow(c.Request.Context(), flowID)
		if !flow.HasError() {
			connectionsMap = h.authenticateSvc.GetAvailableConnections(flow)
		}
	}

	if connectionsMap == nil {
		// 如果没有 flow，返回空结构
		connectionsMap = &types.ConnectionsMap{
			IDP:   make([]*types.ConnectionConfig, 0),
			VChan: make([]*types.VChanConfig, 0),
			MFA:   make([]string, 0),
		}
	}

	// 返回 ConnectionsMap（兼容新格式）
	c.JSON(http.StatusOK, connectionsMap)
}

// LoginWithPreCheck POST /auth/login/check
// 带前置检查的登录
func (h *Handler) LoginWithPreCheck(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// 从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("missing aegis-session cookie"))
		return
	}

	ctx := c.Request.Context()

	// 1. 获取 AuthFlow
	flow := h.authenticateSvc.GetAndValidateFlow(ctx, flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	// 2. 获取 connection 配置
	connectionConfig := flow.ConnectionMap[req.Connection]
	if connectionConfig == nil {
		h.errorResponse(c, autherrors.NewInvalidRequest("invalid connection"))
		return
	}

	// 3. 检查前置认证需求 - 构建 data map
	data := map[string]any{
		"principal": req.Principal,
		"proof":     req.Proof,
		"strategy":  req.Strategy,
	}

	if require := checkPreAuthRequirement(req.Connection, data, connectionConfig); require != "" {
		h.handleInteractionRequired(c, require, connectionConfig)
		return
	}

	// 4. 继续正常登录流程
	h.Login(c)
}

// errorResponse 统一错误响应
func (h *Handler) errorResponse(c *gin.Context, err error) {
	authErr := autherrors.ToAuthError(err)
	c.JSON(authErr.HTTPStatus, authErr)
}

// flowErrorResponse 从 AuthFlow 中提取错误并响应
func (h *Handler) flowErrorResponse(c *gin.Context, flow *types.AuthFlow) {
	if flow.Error == nil {
		h.errorResponse(c, autherrors.NewServerError("unknown error"))
		return
	}
	c.JSON(flow.Error.HTTPStatus, map[string]any{
		"error":             flow.Error.Code,
		"error_description": flow.Error.Description,
		"data":              flow.Error.Data,
	})
}

// checkPreAuthRequirement 检查前置认证需求
func checkPreAuthRequirement(_ string, data map[string]any, connectionConfig *types.ConnectionConfig) string {
	if connectionConfig == nil || connectionConfig.Require == nil {
		return ""
	}

	// 检查是否需要 captcha
	for _, vchan := range connectionConfig.Require.VChan {
		if vchan == "captcha" {
			// 如果需要 captcha 但 data 中没有验证结果，返回 require
			if _, ok := data["captcha_token"]; !ok {
				return "captcha"
			}
		}
	}

	return ""
}

// handleInteractionRequired 处理需要交互的情况
func (h *Handler) handleInteractionRequired(c *gin.Context, require string, _ *types.ConnectionConfig) {
	// captcha site_key 从 vchan 配置获取，这里暂时返回空
	// 前端应该从 /auth/connections 接口获取完整的 vchan 配置

	c.JSON(http.StatusOK, InteractionRequiredResponse{
		Error:          ErrInteractionRequired,
		ErrorDesc:      "Human verification required",
		Require:        require,
		CaptchaSiteKey: "",
	})
}

// ==================== 辅助函数 ====================

// setAuthSessionCookie 设置 Auth 会话 Cookie
func setAuthSessionCookie(c *gin.Context, value string) {
	c.SetCookie(AuthSessionCookie, value,
		config.GetAegisCookieMaxAge(),
		config.GetAegisCookiePath(),
		config.GetAegisCookieDomain(),
		config.GetAegisCookieSecure(),
		config.GetAegisCookieHTTPOnly())
}

// clearAuthSessionCookie 清除 Auth 会话 Cookie
func clearAuthSessionCookie(c *gin.Context) {
	c.SetCookie(AuthSessionCookie, "", -1,
		config.GetAegisCookiePath(),
		config.GetAegisCookieDomain(),
		config.GetAegisCookieSecure(),
		config.GetAegisCookieHTTPOnly())
}

// getAuthSessionCookie 获取 Auth 会话 Cookie
func getAuthSessionCookie(c *gin.Context) (string, error) {
	return c.Cookie(AuthSessionCookie)
}

// ==================== 重定向控制 ====================

// forwardNext 根据 AuthFlow 状态决定下一步重定向
//
// OAuth 2.0 重定向状态码规范 (RFC 6749):
//   - 302 Found: 临时重定向，用于 GET 请求后的重定向（如 /authorize -> /login）
//   - 303 See Other: POST 请求后重定向到 GET（如表单提交后跳转，防止重复提交）
//
// 根据 flow.State 决定跳转目标:
//   - initialized -> login（需要登录）
//   - authenticated -> consent（需要授权同意，如果需要的话）
//   - authorized -> complete（跳转回应用）
//   - failed -> error（显示错误）
//
// prompt 参数处理:
//   - prompt=none: 静默认证，如果未登录或未授权，返回错误
//   - prompt=login: 强制重新登录（忽略现有 SSO 会话）
//   - prompt=consent: 强制显示授权页面
//
// 注意: 301 永久重定向不应用于 OAuth，会被浏览器缓存导致问题
func forwardNext(c *gin.Context, flow *types.AuthFlow) {
	var targetURL string

	// 如果有错误，跳转到错误页面
	if flow.HasError() {
		targetURL = config.GetAegisEndpointError()
		targetURL += "?error=" + flow.Error.Code
		if flow.Error.Description != "" {
			targetURL += "&error_description=" + flow.Error.Description
		}
		redirect(c, targetURL)
		return
	}

	// 处理 prompt=none：静默认证
	if flow.Request != nil && flow.Request.HasPrompt(types.PromptNone) {
		// 如果是 prompt=none 但用户未登录，返回错误
		if flow.State == types.FlowStateInitialized {
			targetURL = config.GetAegisEndpointError()
			targetURL += "?error=login_required&error_description=User+is+not+authenticated"
			redirect(c, targetURL)
			return
		}
	}

	// 根据 flow 状态决定下一步
	switch flow.State {
	case types.FlowStateInitialized:
		// 需要登录
		targetURL = config.GetAegisEndpointLogin()

	case types.FlowStateAuthenticated:
		// 已认证，检查是否需要授权同意
		// 如果 prompt=consent，强制显示授权页面
		if flow.Request != nil && flow.Request.HasPrompt(types.PromptConsent) {
			targetURL = config.GetAegisEndpointConsent()
		} else {
			// 默认跳转到 consent 页面（由前端决定是否显示）
			targetURL = config.GetAegisEndpointConsent()
		}

	case types.FlowStateAuthorized, types.FlowStateCompleted:
		// 已授权/已完成，准备跳转回应用
		// 这种情况通常由 forwardToApp 处理，这里作为兜底
		targetURL = flow.Request.RedirectURI

	default:
		// 默认跳转到登录
		targetURL = config.GetAegisEndpointLogin()
	}

	redirect(c, targetURL)
}

// ForwardToStage 跳转到指定阶段（用于强制跳转到特定页面）
func ForwardToStage(c *gin.Context, stage AuthStage) {
	var targetURL string
	switch stage {
	case StageLogin:
		targetURL = config.GetAegisEndpointLogin()
	case StageConsent:
		targetURL = config.GetAegisEndpointConsent()
	case StageMFA:
		targetURL = config.GetAegisEndpointMFA()
	case StageCallback:
		targetURL = config.GetAegisEndpointCallback()
	case StageError:
		targetURL = config.GetAegisEndpointError()
	default:
		targetURL = config.GetAegisEndpointLogin()
	}
	redirect(c, targetURL)
}

// redirect 执行重定向，根据请求方法选择状态码
func redirect(c *gin.Context, targetURL string) {
	// 根据请求方法选择合适的重定向状态码
	// GET 请求 -> 302 Found
	// POST/PUT/DELETE 请求 -> 303 See Other（防止表单重复提交）
	statusCode := http.StatusFound // 302
	if c.Request.Method != http.MethodGet {
		statusCode = http.StatusSeeOther // 303
	}
	c.Redirect(statusCode, targetURL)
}

// ForwardToApp 重定向回应用（授权完成后）
//
// 使用 302 Found 重定向回 redirect_uri，携带授权码和 state
func ForwardToApp(c *gin.Context, redirectURI, code, state string) {
	targetURL := redirectURI + "?code=" + code
	if state != "" {
		targetURL += "&state=" + state
	}

	// 授权完成后始终使用 302，因为这是从 POST /login 完成后的跳转
	// 但实际返回给前端的是 JSON，前端再执行跳转
	// 如果是服务端直接重定向，使用 302
	c.Redirect(http.StatusFound, targetURL)
}

// ForwardError 重定向到错误页面
func ForwardError(c *gin.Context, errorCode, errorDesc string) {
	targetURL := config.GetAegisEndpointError() + "?error=" + errorCode
	if errorDesc != "" {
		targetURL += "&error_description=" + errorDesc
	}
	redirect(c, targetURL)
}

// GetClaims 从上下文获取用户 Claims
func GetClaims(c *gin.Context) *token.Claims {
	if claims, exists := c.Get("user"); exists {
		if cl, ok := claims.(*token.Claims); ok {
			return cl
		}
	}
	return nil
}

// MarshalAuthFlow 序列化 AuthFlow
func MarshalAuthFlow(flow *types.AuthFlow) ([]byte, error) {
	return json.Marshal(flow)
}

// UnmarshalAuthFlow 反序列化 AuthFlow
func UnmarshalAuthFlow(data []byte) (*types.AuthFlow, error) {
	var flow types.AuthFlow
	if err := json.Unmarshal(data, &flow); err != nil {
		return nil, err
	}
	return &flow, nil
}

// ==================== 类型转换辅助 ====================
// 注意：以下函数已移除，因为它们未被使用
// convertLoginData, toStringMap, splitConnection

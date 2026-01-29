package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/internal/auth/authenticate"
	"github.com/heliannuuthus/helios/internal/auth/authorize"
	"github.com/heliannuuthus/helios/internal/auth/cache"
	autherrors "github.com/heliannuuthus/helios/internal/auth/errors"
	"github.com/heliannuuthus/helios/internal/auth/idp"
	"github.com/heliannuuthus/helios/internal/auth/token"
	"github.com/heliannuuthus/helios/internal/auth/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	// AuthSessionCookie Auth 会话 Cookie 名称
	AuthSessionCookie = "auth-session"
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
	cache           *cache.Manager
}

// HandlerConfig Handler 配置
type HandlerConfig struct {
	AuthenticateSvc *authenticate.Service
	AuthorizeSvc    *authorize.Service
	Cache           *cache.Manager
}

// NewHandler 创建认证处理器
func NewHandler(cfg *HandlerConfig) *Handler {
	return &Handler{
		authenticateSvc: cfg.AuthenticateSvc,
		authorizeSvc:    cfg.AuthorizeSvc,
		cache:           cfg.Cache,
	}
}

// Authorize GET /auth/authorize
// 创建认证会话
func (h *Handler) Authorize(c *gin.Context) {
	var req types.AuthRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// 创建 AuthFlow（错误存储在 flow.Error 中）
	flow := h.authenticateSvc.CreateFlow(c, &req)

	// 设置 Cookie（flowID 作为 session）
	setAuthSessionCookie(c, flow.ID)

	// 根据 flow 状态决定下一步（包括错误处理）
	forwardNext(c, flow)
}

// GetConnections GET /auth/connections
// 获取可用的 Connection 配置
func (h *Handler) GetConnections(c *gin.Context) {
	// 从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("missing auth-session cookie"))
		return
	}

	// 获取 AuthFlow
	flow := h.authenticateSvc.GetAndValidateFlow(c.Request.Context(), flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	// 获取可用的 Connections
	connections := h.authenticateSvc.GetAvailableConnections(flow)

	c.JSON(http.StatusOK, gin.H{
		"connections": connections,
	})
}

// Login POST /auth/login
// 处理登录
func (h *Handler) Login(c *gin.Context) {
	var req types.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// 从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("missing auth-session cookie"))
		return
	}

	ctx := c.Request.Context()

	// 1. 获取 AuthFlow
	flow := h.authenticateSvc.GetAndValidateFlow(ctx, flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	// 2. 执行认证
	data := make(map[string]any)
	for k, v := range req.Data {
		data[k] = v
	}

	authResult, err := h.authenticateSvc.Authenticate(ctx, flow, req.Connection, data)
	if err != nil {
		logger.Errorf("[Handler] 认证失败: %v", err)
		h.errorResponse(c, autherrors.NewAccessDenied(err.Error()))
		return
	}

	// 3. 查找或创建用户
	userReq := &models.FindOrCreateUserRequest{
		Domain:     string(idp.GetDomain(req.Connection)),
		IDP:        req.Connection,
		ProviderID: authResult.ProviderID,
		UnionID:    authResult.UnionID,
		RawData:    authResult.RawData,
	}

	user, isNewUser, err := h.cache.FindOrCreateUser(ctx, userReq)
	if err != nil {
		logger.Errorf("[Handler] 查找/创建用户失败: %v", err)
		h.errorResponse(c, autherrors.NewServerError("user management failed"))
		return
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

// Logout POST /auth/logout
// 登出
func (h *Handler) Logout(c *gin.Context) {
	claims := GetClaims(c)
	if claims == nil {
		h.errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	if err := h.authorizeSvc.RevokeAllTokens(c.Request.Context(), claims.OpenID); err != nil {
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

	resp, err := h.authorizeSvc.GetUserInfo(c.Request.Context(), claims.OpenID, claims.Scope)
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
	resp, err := h.authorizeSvc.GetUserInfo(c.Request.Context(), claims.OpenID, claims.Scope)
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

// IDPs GET /idps
// 获取可用的身份提供方列表
func (h *Handler) IDPs(c *gin.Context) {
	// 尝试从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil {
		flowID = "" // Cookie 不存在时使用空字符串
	}

	var connections []*types.ConnectionConfig

	if flowID != "" {
		// 如果有 flow，从 flow 获取
		flow := h.authenticateSvc.GetAndValidateFlow(c.Request.Context(), flowID)
		if !flow.HasError() {
			connections = h.authenticateSvc.GetAvailableConnections(flow)
		}
	}

	if connections == nil {
		// 如果没有 flow，根据 client_id 获取
		clientID := c.Query("client_id")
		if clientID == "" {
			h.errorResponse(c, autherrors.NewInvalidRequest("client_id is required"))
			return
		}

		// 获取应用信息
		app, err := h.cache.GetApplication(c.Request.Context(), clientID)
		if err != nil {
			h.errorResponse(c, autherrors.NewClientNotFound("application not found"))
			return
		}

		// 创建临时 flow 获取 connections
		tempReq := &types.AuthRequest{
			ResponseType:        "code",
			ClientID:            clientID,
			Audience:            clientID,
			RedirectURI:         "temp",
			CodeChallenge:       "temp",
			CodeChallengeMethod: "S256",
		}
		tempFlow := types.NewAuthFlow(tempReq, 0)
		tempFlow.Application = app

		connections = make([]*types.ConnectionConfig, 0)
	}

	// 构建响应
	idps := make([]types.ConnectionConfig, 0, len(connections))
	for _, conn := range connections {
		idps = append(idps, *conn)
	}

	c.JSON(http.StatusOK, IDPsResponse{IDPs: idps})
}

// LoginWithPreCheck POST /auth/login/check
// 带前置检查的登录
func (h *Handler) LoginWithPreCheck(c *gin.Context) {
	var req types.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// 从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("missing auth-session cookie"))
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

	// 3. 检查前置认证需求
	data := make(map[string]any)
	for k, v := range req.Data {
		data[k] = v
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
	if connectionConfig == nil || connectionConfig.Capture == nil || !connectionConfig.Capture.Required {
		return ""
	}

	// 如果配置了 Capture 但 data 中没有验证结果，返回 require
	if _, ok := data["capture_token"]; !ok {
		return "captcha"
	}

	return ""
}

// handleInteractionRequired 处理需要交互的情况
func (h *Handler) handleInteractionRequired(c *gin.Context, require string, connectionConfig *types.ConnectionConfig) {
	var siteKey string
	if connectionConfig != nil && connectionConfig.Capture != nil {
		siteKey = connectionConfig.Capture.SiteKey
	}

	c.JSON(http.StatusOK, InteractionRequiredResponse{
		Error:          ErrInteractionRequired,
		ErrorDesc:      "Human verification required",
		Require:        require,
		CaptchaSiteKey: siteKey,
	})
}

// ==================== 辅助函数 ====================

// setAuthSessionCookie 设置 Auth 会话 Cookie
func setAuthSessionCookie(c *gin.Context, value string) {
	c.SetCookie(AuthSessionCookie, value,
		config.GetAuthCookieMaxAge(),
		config.GetAuthCookiePath(),
		config.GetAuthCookieDomain(),
		config.GetAuthCookieSecure(),
		config.GetAuthCookieHTTPOnly())
}

// clearAuthSessionCookie 清除 Auth 会话 Cookie
func clearAuthSessionCookie(c *gin.Context) {
	c.SetCookie(AuthSessionCookie, "", -1,
		config.GetAuthCookiePath(),
		config.GetAuthCookieDomain(),
		config.GetAuthCookieSecure(),
		config.GetAuthCookieHTTPOnly())
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
// 注意: 301 永久重定向不应用于 OAuth，会被浏览器缓存导致问题
func forwardNext(c *gin.Context, flow *types.AuthFlow) {
	var targetURL string

	// 如果有错误，跳转到错误页面
	if flow.HasError() {
		targetURL = config.GetAuthEndpointError()
		targetURL += "?error=" + flow.Error.Code
		if flow.Error.Description != "" {
			targetURL += "&error_description=" + flow.Error.Description
		}
		redirect(c, targetURL)
		return
	}

	// 根据 flow 状态决定下一步
	switch flow.State {
	case types.FlowStateInitialized:
		// 需要登录
		targetURL = config.GetAuthEndpointLogin()

	case types.FlowStateAuthenticated:
		// 已认证，检查是否需要授权同意
		// TODO: 根据 prompt 参数和首次授权判断是否需要 consent 页面
		// 目前直接跳过 consent
		targetURL = config.GetAuthEndpointConsent()

	case types.FlowStateAuthorized, types.FlowStateCompleted:
		// 已授权/已完成，准备跳转回应用
		// 这种情况通常由 forwardToApp 处理，这里作为兜底
		targetURL = flow.Request.RedirectURI

	default:
		// 默认跳转到登录
		targetURL = config.GetAuthEndpointLogin()
	}

	redirect(c, targetURL)
}

// ForwardToStage 跳转到指定阶段（用于强制跳转到特定页面）
func ForwardToStage(c *gin.Context, stage AuthStage) {
	var targetURL string
	switch stage {
	case StageLogin:
		targetURL = config.GetAuthEndpointLogin()
	case StageConsent:
		targetURL = config.GetAuthEndpointConsent()
	case StageMFA:
		targetURL = config.GetAuthEndpointMFA()
	case StageCallback:
		targetURL = config.GetAuthEndpointCallback()
	case StageError:
		targetURL = config.GetAuthEndpointError()
	default:
		targetURL = config.GetAuthEndpointLogin()
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
	targetURL := config.GetAuthEndpointError() + "?error=" + errorCode
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

package aegis

import (
	"context"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/internal/aegis/authenticate"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/webauthn"
	"github.com/heliannuuthus/helios/internal/aegis/authorize"
	"github.com/heliannuuthus/helios/internal/aegis/cache"
	"github.com/heliannuuthus/helios/internal/aegis/challenge"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/token"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/aegis/user"
	"github.com/heliannuuthus/helios/internal/config"
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
)

// Handler 认证处理器（编排层）
type Handler struct {
	authenticateSvc *authenticate.Service
	authorizeSvc    *authorize.Service
	challengeSvc    *challenge.Service
	userSvc         *user.Service
	cache           *cache.Manager
	tokenSvc        *token.Service
	webauthnSvc     *webauthn.Service
}

// NewHandler 创建认证处理器
func NewHandler(
	authenticateSvc *authenticate.Service,
	authorizeSvc *authorize.Service,
	challengeSvc *challenge.Service,
	userSvc *user.Service,
	cache *cache.Manager,
	tokenSvc *token.Service,
	webauthnSvc *webauthn.Service,
) *Handler {
	return &Handler{
		authenticateSvc: authenticateSvc,
		authorizeSvc:    authorizeSvc,
		challengeSvc:    challengeSvc,
		userSvc:         userSvc,
		cache:           cache,
		tokenSvc:        tokenSvc,
		webauthnSvc:     webauthnSvc,
	}
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

// ==================== 公开方法（按登录认证流程顺序） ====================

// CacheManager 返回缓存管理器（用于 CORS 中间件等）
func (h *Handler) CacheManager() *cache.Manager {
	return h.cache
}

// WebAuthnSvc 返回 WebAuthn 服务（供 iris 等模块使用）
func (h *Handler) WebAuthnSvc() *webauthn.Service {
	return h.webauthnSvc
}

// ==================== 1. 认证会话创建 ====================

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

// ==================== 2. 获取上下文信息 ====================

// GetContext GET /auth/context
// 获取当前认证流程的应用和服务信息
func (h *Handler) GetContext(c *gin.Context) {
	// 从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewFlowNotFound("missing session"))
		return
	}

	// 获取 AuthFlow（内部会续期内存中的 ExpiresAt）
	flow := h.authenticateSvc.GetAndValidateFlow(c.Request.Context(), flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	// 持久化续期后的 Flow 到 Redis
	if err := h.authenticateSvc.SaveFlow(c.Request.Context(), flow); err != nil {
		logger.Errorf("[Handler] GetContext 保存续期 Flow 失败 - FlowID: %s, Error: %v", flowID, err)
	}

	// 为 aegis-session cookie 续期
	setAuthSessionCookie(c, flowID)

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

// GetConnections GET /auth/connections
// 获取可用的 Connection 配置（按类别分类：idp, vchan, mfa）
func (h *Handler) GetConnections(c *gin.Context) {
	// 从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewFlowNotFound("missing session"))
		return
	}

	// 获取 AuthFlow（内部会续期内存中的 ExpiresAt）
	flow := h.authenticateSvc.GetAndValidateFlow(c.Request.Context(), flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	// 持久化续期后的 Flow 到 Redis
	if err := h.authenticateSvc.SaveFlow(c.Request.Context(), flow); err != nil {
		logger.Errorf("[Handler] GetConnections 保存续期 Flow 失败 - FlowID: %s, Error: %v", flowID, err)
	}

	// 获取可用的 ConnectionsMap
	connectionsMap := h.authenticateSvc.GetAvailableConnections(flow)

	c.JSON(http.StatusOK, connectionsMap)
}

// ==================== 3. Challenge 验证 ====================

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

// ==================== 4. 登录 ====================

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
		h.errorResponse(c, autherrors.NewFlowNotFound("missing session"))
		return
	}

	ctx := c.Request.Context()

	// 1. 获取 AuthFlow
	flow := h.authenticateSvc.GetAndValidateFlow(ctx, flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	// 确保无论成功还是失败都保存 flow（续期已在 GetAndValidateFlow 中完成）
	var loginSuccess bool
	defer func() {
		h.authenticateSvc.CleanupFlow(ctx, flowID, flow, loginSuccess)
	}()

	// 2. 验证并设置当前 Connection
	if !authenticator.GlobalRegistry().Has(req.Connection) {
		h.errorResponse(c, autherrors.NewInvalidRequestf("unsupported connection: %s", req.Connection))
		return
	}
	flow.SetConnection(req.Connection)

	// 3. 执行认证（通过 Registry 统一分发）
	success, err := h.authenticateSvc.Authenticate(ctx, flow, req)
	if err != nil {
		logger.Errorf("[Handler] 认证失败: %v", err)
		h.errorResponse(c, autherrors.NewUnauthorized(err.Error()))
		return
	}
	if !success {
		h.errorResponse(c, autherrors.NewUnauthorized("authentication failed"))
		return
	}

	// 4. 检查前置验证和委托验证是否都通过
	// 如果当前 connection 有 require/delegate 依赖且未全部通过，返回 200 + pending
	if !flow.AllRequiredVerified() || !flow.AnyDelegateVerified() {
		// 保存 flow 后返回 pending 状态
		if err := h.authenticateSvc.SaveFlow(ctx, flow); err != nil {
			logger.Warnf("[Handler] 保存 flow 失败: %v", err)
		}
		c.JSON(http.StatusOK, gin.H{
			"status":  "pending",
			"message": "additional verification required",
		})
		return
	}

	// 5. 查找或创建用户，回写用户信息和全部身份到 flow
	if err := h.resolveUser(ctx, flow); err != nil {
		h.errorResponse(c, err)
		return
	}

	// 6. 完成登录流程
	authCode, err := h.completeLoginFlow(ctx, flow)
	if err != nil {
		h.errorResponse(c, err)
		return
	}

	// 标记登录成功
	loginSuccess = true

	// 7. 构建响应
	redirectURI := flow.Request.RedirectURI + "?code=" + url.QueryEscape(authCode.Code)
	if authCode.State != "" {
		redirectURI += "&state=" + url.QueryEscape(authCode.State)
	}

	clearAuthSessionCookie(c)
	c.JSON(http.StatusOK, LoginResponse{
		Code:        authCode.Code,
		RedirectURI: redirectURI,
	})
}

// resolveUser 解析用户信息并回写到 flow
func (h *Handler) resolveUser(ctx context.Context, flow *types.AuthFlow) error {
	connection := flow.Connection
	domain := flow.Application.DomainID

	identity := flow.GetIdentity(connection)
	if identity == nil {
		return autherrors.NewServerError("identity not found in flow")
	}

	// 1. 查询用户的全部身份
	allIdentities, err := h.userSvc.GetIdentities(ctx, identity)
	if err != nil {
		return err
	}

	if len(allIdentities) == 0 {
		// 用户不存在，检查当前域下该 IDP 是否允许注册
		if !idp.IsIDPAllowedForDomain(connection, idp.Domain(domain)) {
			return autherrors.NewUnauthorized("registration not allowed for this IDP")
		}

		// 创建用户及当前认证身份
		allIdentities, err = h.userSvc.CreateUser(ctx, identity, flow.GetUserInfo(connection))
		if err != nil {
			return err
		}
	}

	// 2. 获取用户信息
	u, err := h.userSvc.GetUser(ctx, allIdentities[0].UID)
	if err != nil {
		return autherrors.NewUnauthorized("user not found")
	}

	// 回写到 flow
	flow.Identities = allIdentities
	flow.SetAuthenticated(u)

	return nil
}

// completeLoginFlow 完成登录流程（准备授权、生成授权码）
// 调用前需确保 flow 已通过 resolveUser 设置好 User 和 Identities
func (h *Handler) completeLoginFlow(ctx context.Context, flow *types.AuthFlow) (*cache.AuthorizationCode, error) {
	// 准备授权（检查身份要求）
	if err := h.authorizeSvc.PrepareAuthorization(ctx, flow); err != nil {
		logger.Errorf("[Handler] 准备授权失败: %v", err)
		return nil, err
	}

	// 生成授权码
	authCode, err := h.authorizeSvc.GenerateAuthCode(ctx, flow)
	if err != nil {
		logger.Errorf("[Handler] 生成授权码失败: %v", err)
		return nil, autherrors.NewServerError(err.Error())
	}

	// 保存更新后的 flow
	if err := h.authenticateSvc.SaveFlow(ctx, flow); err != nil {
		logger.Warnf("[Handler] 保存 flow 失败: %v", err)
	}

	return authCode, nil
}

// ==================== 6. Token 换取 ====================

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

// ==================== 7. 权限检查 ====================

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
	serviceID := catClaims.GetClientID()

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
	hasRelation, err := h.authorizeSvc.CheckRelation(ctx, serviceID, req.SubjectID, req.Relation, objectType, objectID)
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

// ==================== 9. 登出与撤销 ====================

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
	claims := GetToken(c)
	if claims == nil {
		h.errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	if err := h.authorizeSvc.RevokeAllTokens(c.Request.Context(), getInternalUID(claims)); err != nil {
		h.errorResponse(c, autherrors.NewServerError("failed to revoke tokens"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// ==================== 10. 公钥 ====================

// PublicKeys GET /pubkeys
// 获取 PASETO 公钥
func (h *Handler) PublicKeys(c *gin.Context) {
	clientID := c.Query("client_id")
	if clientID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("client_id is required"))
		return
	}

	publicKey, err := h.authorizeSvc.GetPublicKey(c.Request.Context(), clientID)
	if err != nil {
		h.errorResponse(c, autherrors.NewClientNotFound(err.Error()))
		return
	}

	// 公钥不经常变化，设置缓存控制（3 小时）
	c.Header("Cache-Control", "public, max-age=10800")
	c.JSON(http.StatusOK, publicKey)
}

// ==================== 公开辅助函数（包级别） ====================

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
	default:
		targetURL = config.GetAegisEndpointLogin()
	}
	redirect(c, targetURL)
}

// ForwardToApp 重定向回应用（授权完成后）
//
// 使用 302 Found 重定向回 redirect_uri，携带授权码和 state
func ForwardToApp(c *gin.Context, redirectURI, code, state string) {
	targetURL := redirectURI + "?code=" + url.QueryEscape(code)
	if state != "" {
		targetURL += "&state=" + url.QueryEscape(state)
	}

	// 授权完成后始终使用 302，因为这是从 POST /login 完成后的跳转
	// 但实际返回给前端的是 JSON，前端再执行跳转
	// 如果是服务端直接重定向，使用 302
	c.Redirect(http.StatusFound, targetURL)
}

// GetToken 从上下文获取验证后的 Token
func GetToken(c *gin.Context) token.Token {
	if t, exists := c.Get("user"); exists {
		if tk, ok := t.(token.Token); ok {
			return tk
		}
	}
	return nil
}

// ==================== 私有方法（Handler） ====================

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

	resp := map[string]any{
		"error":             flow.Error.Code,
		"error_description": flow.Error.Description,
	}
	if flow.Error.Data != nil {
		resp["data"] = flow.Error.Data
	}

	// flow 失效时清除无效的 session cookie
	if flow.Error.Code == autherrors.CodeFlowNotFound || flow.Error.Code == autherrors.CodeFlowExpired {
		clearAuthSessionCookie(c)
	}

	c.JSON(flow.Error.HTTPStatus, resp)
}

// ==================== 私有辅助函数（包级别） ====================

// setAuthSessionCookie 设置 Auth 会话 Cookie
// 使用 http.SetCookie 以支持 SameSite 属性
// SameSite=None 允许跨站请求携带 Cookie（OAuth 场景需要），必须配合 Secure=true
func setAuthSessionCookie(c *gin.Context, value string) {
	cookie := &http.Cookie{
		Name:     AuthSessionCookie,
		Value:    value,
		MaxAge:   config.GetAegisCookieMaxAge(),
		Path:     config.GetAegisCookiePath(),
		Domain:   config.GetAegisCookieDomain(),
		Secure:   config.GetAegisCookieSecure(),
		HttpOnly: config.GetAegisCookieHTTPOnly(),
		SameSite: http.SameSiteNoneMode, // 跨站请求也携带 Cookie（OAuth 场景）
	}
	http.SetCookie(c.Writer, cookie)
}

// clearAuthSessionCookie 清除 Auth 会话 Cookie
func clearAuthSessionCookie(c *gin.Context) {
	cookie := &http.Cookie{
		Name:     AuthSessionCookie,
		Value:    "",
		MaxAge:   -1,
		Path:     config.GetAegisCookiePath(),
		Domain:   config.GetAegisCookieDomain(),
		Secure:   config.GetAegisCookieSecure(),
		HttpOnly: config.GetAegisCookieHTTPOnly(),
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(c.Writer, cookie)
}

// getAuthSessionCookie 获取 Auth 会话 Cookie
func getAuthSessionCookie(c *gin.Context) (string, error) {
	return c.Cookie(AuthSessionCookie)
}

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

	// 统一跳转到登录页面，前端根据 API 返回的状态码展示不同的交互逻辑
	// 错误、prompt=none 未登录等场景，前端通过调用 /auth/context 等接口获取状态

	// 根据 flow 状态决定下一步
	switch flow.State {
	case types.FlowStateAuthenticated:
		// 已认证，跳转到 consent 页面
		targetURL = config.GetAegisEndpointConsent()

	case types.FlowStateAuthorized, types.FlowStateCompleted:
		// 已授权/已完成，准备跳转回应用
		// 这种情况通常由 forwardToApp 处理，这里作为兜底
		targetURL = flow.Request.RedirectURI

	default:
		// 初始化、失败等状态统一跳到登录页面
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

// getInternalUID 从 Token 中获取内部用户 ID（t_user.openid，用于内部查询）
func getInternalUID(t token.Token) string {
	if uat, ok := token.AsUAT(t); ok && uat.HasUser() {
		return uat.GetInternalUID()
	}
	return ""
}

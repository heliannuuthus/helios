package aegis

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/aegis/config"
	autherrors "github.com/heliannuuthus/helios/aegis/errors"
	"github.com/heliannuuthus/helios/aegis/internal/authenticate"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp"
	"github.com/heliannuuthus/helios/aegis/internal/authorize"
	"github.com/heliannuuthus/helios/aegis/internal/cache"
	"github.com/heliannuuthus/helios/aegis/internal/challenge"
	"github.com/heliannuuthus/helios/aegis/internal/token"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/aegis/internal/user"
	"github.com/heliannuuthus/helios/hermes/models"
	pkgtoken "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/async"
	"github.com/heliannuuthus/helios/pkg/helpers"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// errIdentifiedUser 内部哨兵错误：resolveUser 识别到已有用户，需前端确认关联
var errIdentifiedUser = errors.New("identified existing user")

const (
	// AuthSessionCookie Auth 会话 Cookie 名称
	AuthSessionCookie = "aegis-session"
)

// Handler 认证处理器（编排层）
type Handler struct {
	authenticateSvc *authenticate.Service
	authorizeSvc    *authorize.Service
	challengeSvc    *challenge.Service
	userSvc         *user.Service
	cache           *cache.Manager
	tokenSvc        *token.Service
	mfaSvc          *MFAService
	pool            *async.Pool
}

// NewHandler 创建认证处理器
func NewHandler(
	authenticateSvc *authenticate.Service,
	authorizeSvc *authorize.Service,
	challengeSvc *challenge.Service,
	userSvc *user.Service,
	cache *cache.Manager,
	tokenSvc *token.Service,
	mfaSvc *MFAService,
	pool *async.Pool,
) *Handler {
	return &Handler{
		authenticateSvc: authenticateSvc,
		authorizeSvc:    authorizeSvc,
		challengeSvc:    challengeSvc,
		userSvc:         userSvc,
		cache:           cache,
		tokenSvc:        tokenSvc,
		mfaSvc:          mfaSvc,
		pool:            pool,
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

// MFASvc 返回 MFA 服务（供 iris 等模块使用）
func (h *Handler) MFASvc() *MFAService {
	return h.mfaSvc
}

// ==================== 1. 认证会话创建 ====================

// Authorize POST /auth/authorize
// 创建认证会话
func (h *Handler) Authorize(c *gin.Context) {
	var req types.AuthRequest
	if err := c.ShouldBind(&req); err != nil {
		h.authorizeErrorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()
	logger.Debugf("[Handler] Authorize request: %+v", req)

	// 1. 获取并验证 Application
	app, err := h.cache.GetApplication(ctx, req.ClientID)
	if err != nil {
		h.authorizeErrorResponse(c, autherrors.NewClientNotFoundf("application not found: %s", req.ClientID))
		return
	}
	if !app.ValidateRedirectURI(req.RedirectURI) {
		h.authorizeErrorResponse(c, autherrors.NewInvalidRequest("invalid redirect_uri"))
		return
	}

	// 2. 获取并验证 Service
	svc, err := h.cache.GetService(ctx, req.Audience)
	if err != nil {
		h.authorizeErrorResponse(c, autherrors.NewServiceNotFoundf("service not found: %s", req.Audience))
		return
	}

	// 3. 验证 Application-Service 关系
	hasRelation, err := h.cache.CheckAppServiceRelation(ctx, req.ClientID, req.Audience)
	if err != nil {
		h.authorizeErrorResponse(c, autherrors.NewServerError("check relation failed"))
		return
	}
	if !hasRelation {
		h.authorizeErrorResponse(c, autherrors.NewAccessDeniedf("application %s has no access to service %s", req.ClientID, req.Audience))
		return
	}

	// 4. 获取应用 IDP 配置
	idpConfigs, err := h.cache.GetApplicationIDPConfigs(ctx, req.ClientID)
	if err != nil {
		h.authorizeErrorResponse(c, autherrors.NewServerError("query idp configs failed"))
		return
	}
	if len(idpConfigs) == 0 {
		h.authorizeErrorResponse(c, autherrors.NewNoConnectionAvailable(""))
		return
	}

	// 5. 构建 AuthFlow
	flow := types.NewAuthFlow(&req, time.Duration(config.GetCookieMaxAge())*time.Second, config.GetAuthFlowMaxLifetime())
	flow.Application = app
	flow.Service = svc
	flow.SetConnectionMap(h.authenticateSvc.SetConnections(idpConfigs))

	// 6. SSO 快速路径
	if !req.Prompt.Contains(types.PromptLogin) {
		if ssoToken, user := h.resolveSSO(c, ctx, app); user != nil {
			flow.User = user
			flow.SetAuthenticated(user)

			for conn, cfg := range flow.ConnectionMap {
				if cfg.Type == types.ConnTypeIDP {
					flow.SetConnection(conn)
					break
				}
			}
			logger.Debugf("[Handler] SSO 快速路径 - Connection: %s, User: %s", flow.Connection, flow.User.OpenID)

			authCode, err := h.authorizeAndGenerateCode(ctx, flow)
			if err != nil {
				logger.Warnf("[Handler] SSO 授权失败: %v", err)
			} else {
				if err := h.authenticateSvc.SaveFlow(ctx, flow); err != nil {
					logger.Warnf("[Handler] SSO flow 保存失败: %v", err)
				} else {
					h.renewSSOCookie(c, ctx, ssoToken)
					actionRedirect(c, buildAuthCodeRedirectURL(flow.Request.RedirectURI, authCode))
					return
				}
			}
		}
	}

	// prompt=none 要求静默认证，但 SSO 不可用 → 返回错误
	if req.Prompt.Contains(types.PromptNone) {
		h.authorizeErrorResponse(c, autherrors.NewLoginRequired("no active SSO session"))
		return
	}

	// 7. 持久化 Flow
	if err := h.authenticateSvc.SaveFlow(ctx, flow); err != nil {
		h.authorizeErrorResponse(c, autherrors.NewServerError("save flow failed"))
		return
	}

	// 8. 设置 Cookie 并根据 flow 状态决定下一步
	setAuthSessionCookie(c, flow.ID)
	forwardNext(c, flow)
}

// resolveSSO 验证 SSO cookie 并恢复用户
// 返回 ssoToken 和 user，任一为 nil 表示 SSO 不可用
func (h *Handler) resolveSSO(c *gin.Context, ctx context.Context,
	app *models.ApplicationWithKey,
) (*token.SSOToken, *models.UserWithDecrypted) {
	ssoTokenString, err := getSSOCookie(c)
	if err != nil || ssoTokenString == "" {
		return nil, nil
	}

	if len(ssoTokenString) > 60 {
		logger.Debugf("[Handler] resolveSSO: cookie token prefix=%s...", ssoTokenString[:60])
	}

	t, err := h.tokenSvc.Verify(ctx, ssoTokenString)
	if err != nil {
		logger.Debugf("[Handler] SSO token 验证失败: %v", err)
		clearSSOCookie(c)
		return nil, nil
	}
	ssoToken, ok := t.(*token.SSOToken)
	if !ok {
		logger.Debugf("[Handler] SSO token 类型不匹配: %T", t)
		clearSSOCookie(c)
		return nil, nil
	}

	openID := ssoToken.GetOpenID(app.DomainID)
	if openID == "" {
		logger.Debugf("[Handler] SSO token 中无域 %s 的身份", app.DomainID)
		return nil, nil
	}

	user, err := h.userSvc.GetUser(ctx, openID)
	if err != nil {
		logger.Debugf("[Handler] SSO 用户查找失败: domain=%s, openID=%s, err=%v", app.DomainID, openID, err)
		return nil, nil
	}

	if !user.IsActive() {
		logger.Infof("[Handler] SSO 用户已禁用: domain=%s, openID=%s", app.DomainID, user.OpenID)
		return nil, nil
	}

	return ssoToken, user
}

// renewSSOCookie 续期 SSO Token（重新签发新 token 并更新 cookie，保留全部域身份）
func (h *Handler) renewSSOCookie(c *gin.Context, ctx context.Context, oldSSO *token.SSOToken) {
	sso := pkgtoken.NewClaimsBuilder().
		Issuer(token.SSOIssuer).
		ClientID(token.SSOIssuer).
		Audience(token.SSOAudience).
		ExpiresIn(config.GetSSOTTL()).
		Build(token.NewSSOTokenBuilder().
			Identities(oldSSO.GetIdentities()))

	tokenString, err := h.tokenSvc.Issue(ctx, sso)
	if err != nil {
		logger.Warnf("[Handler] SSO token 续期失败: %v", err)
		return
	}
	setSSOCookie(c, tokenString)
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
// 获取可用的 Connection 配置（按类型分类：idp, vchan, factor）
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
	c.JSON(http.StatusOK, flow.GetAvailableConnections())
}

// ==================== 3. Challenge 验证 ====================

// InitiateChallenge POST /auth/challenge
// Flow: query setting → create challenge → check prerequisite → initiate → save
func (h *Handler) InitiateChallenge(c *gin.Context) {
	var req challenge.InitiateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}
	logger.Infof("[发起 Challenge] 请求: %+v", req)

	ctx := helpers.WithRemoteIP(c.Request.Context(), c.ClientIP())

	// 1. 获取 ServiceChallengeSetting
	setting, err := h.cache.GetServiceChallengeSetting(ctx, req.Audience, req.Type)
	if err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequestf("challenge type %q is not configured for service %s", req.Type, req.Audience))
		return
	}

	// 2. 创建 Challenge（携带 Limits 和 IP）
	ch := req.NewChallenge(setting, c.ClientIP())

	// 3. 构建前置条件（如 captcha）
	if h.challengeSvc.BuildRequired(ch) {
		if err := h.challengeSvc.Save(ctx, ch); err != nil {
			h.errorResponse(c, err)
			return
		}
		c.JSON(http.StatusOK, &challenge.InitiateResponse{
			ChallengeID: ch.ID,
			Required:    ch.Required,
		})
		return
	}

	// 4. initiate challenge (限流 + send OTP, etc.) → save
	if err := h.initiateChallenge(ctx, ch); err != nil {
		h.errorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, &challenge.InitiateResponse{
		ChallengeID: ch.ID,
		RetryAfter:  ch.RetryAfter,
	})
}

// ContinueChallenge POST /auth/challenge/:cid
// Flow: load → prerequisite / main verify → issue token
func (h *Handler) ContinueChallenge(c *gin.Context) {
	challengeID := c.Param("cid")
	if challengeID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("challenge_id is required"))
		return
	}

	var req challenge.VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := helpers.WithRemoteIP(c.Request.Context(), c.ClientIP())

	// 1. load Challenge
	ch, err := h.challengeSvc.GetAndValidate(ctx, challengeID)
	if err != nil {
		h.errorResponse(c, err)
		return
	}

	// 2. prerequisite not fully met → verify prerequisite
	if ch.IsUnmet() {
		h.handlePrerequisiteVerification(c, ctx, ch, &req)
		return
	}

	// 3. main verification + token issuance
	h.handleMainVerification(c, ctx, ch, &req)
}

func (h *Handler) handlePrerequisiteVerification(c *gin.Context, ctx context.Context, ch *types.Challenge, req *challenge.VerifyRequest) {
	if !ch.Required.Contains(req.Type) {
		c.JSON(http.StatusPreconditionFailed, &challenge.VerifyResponse{
			Required: ch.Required,
		})
		return
	}

	verified, err := h.challengeSvc.Verify(ctx, ch, req)
	if err != nil {
		h.errorResponse(c, err)
		return
	}
	if !verified {
		h.errorResponse(c, autherrors.NewInvalidRequest("prerequisite verification failed"))
		return
	}

	if ch.IsUnmet() {
		if err := h.challengeSvc.Save(ctx, ch); err != nil {
			h.errorResponse(c, err)
			return
		}
		c.JSON(http.StatusOK, &challenge.VerifyResponse{
			Required: ch.Required,
		})
		return
	}

	if err := h.initiateChallenge(ctx, ch); err != nil {
		h.errorResponse(c, err)
		return
	}
	c.JSON(http.StatusOK, &challenge.VerifyResponse{
		RetryAfter: ch.RetryAfter,
	})
}

func (h *Handler) handleMainVerification(c *gin.Context, ctx context.Context, ch *types.Challenge, req *challenge.VerifyRequest) {
	verified, err := h.challengeSvc.Verify(ctx, ch, req)
	if err != nil {
		h.errorResponse(c, err)
		return
	}

	if !verified {
		h.errorResponse(c, autherrors.NewInvalidRequest("verification failed"))
		return
	}

	if err = h.challengeSvc.Delete(ctx, ch.ID); err != nil {
		logger.Warnf("[验证 Challenge] 删除 Challenge 失败: %v", err)
	}

	ct := pkgtoken.NewClaimsBuilder().
		Issuer(h.tokenSvc.GetIssuer()).
		ClientID(ch.ClientID).
		Audience(ch.Audience).
		ExpiresIn(ch.ExpiresIn()).
		Build(pkgtoken.NewChallengeTokenBuilder().
			Subject(ch.Channel).
			Type(ch.Type))

	tokenStr, err := h.tokenSvc.Issue(ctx, ct)
	if err != nil {
		logger.Errorf("[验证 Challenge] 签发 ChallengeToken 失败: %v", err)
		h.errorResponse(c, autherrors.NewServerErrorf("issue challenge token: %v", err))
		return
	}
	c.JSON(http.StatusOK, &challenge.VerifyResponse{
		Verified:       true,
		ChallengeToken: tokenStr,
		ExpiresIn:      int(ch.ExpiresIn().Seconds()),
	})
}

func (h *Handler) initiateChallenge(ctx context.Context, ch *types.Challenge) error {
	if err := h.challengeSvc.Initiate(ctx, ch); err != nil {
		return err
	}
	return h.challengeSvc.Save(ctx, ch)
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

	logger.Infof("[Login] 登录请求: %s", req)

	// 从 Cookie 获取 flowID
	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewFlowNotFound("missing session"))
		return
	}

	ctx := helpers.WithRemoteIP(c.Request.Context(), c.ClientIP())

	// 1. 获取 AuthFlow
	flow := h.authenticateSvc.GetAndValidateFlow(ctx, flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	// defer 统一持久化 flow（无论成功失败都保存最新状态）
	// flow 的最终清理由 token exchange 完成（ConsumeAuthCode 后删除 flow）
	defer func() {
		if err := h.authenticateSvc.SaveFlow(ctx, flow); err != nil {
			logger.Warnf("[Handler] 保存 flow 失败: %v", err)
		}
	}()

	// 2. 验证并设置当前 Connection
	if !authenticator.GlobalRegistry().Has(req.Connection) {
		h.errorResponse(c, autherrors.NewInvalidRequestf("unsupported connection: %s", req.Connection))
		return
	}
	flow.SetConnection(req.Connection)
	flow.SetExtra(types.ExtraKeyStrategy, req.Strategy)

	// 3. 已验证（如 delegate 完成时同步标记）则跳过认证流程
	connCfg := flow.GetCurrentConnConfig()
	if connCfg != nil && !connCfg.Verified {
		// 4. 前置检查：Require 中未 Verified 的 connection（仅 strategy 路径）
		if actions := unmetRequirements(flow); len(actions) > 0 {
			logger.Infof("[Login] 待满足的条件: %v", actions)
			actionRedirect(c, buildActionURL(actions))
			return
		}

		// 5. 执行认证（Strike 在 Authenticate 内部前置）
		success, err := h.authenticateSvc.Authenticate(ctx, flow, req.Proof, req.Principal, req.Strategy)
		if err != nil {
			logger.Errorf("[Handler] 认证失败 - FlowID: %s, Connection: %s, Error: %v", flow.ID, req.Connection, err)
			h.errorResponse(c, err)
			return
		}
		if !success {
			logger.Infof("[Handler] 认证未通过 - FlowID: %s, Connection: %s", flow.ID, req.Connection)
			if actions := unmetRequirements(flow); len(actions) > 0 {
				actionRedirect(c, buildActionURL(actions))
				return
			}
			h.errorResponse(c, autherrors.NewInvalidCredentials("authentication failed"))
			return
		}
		logger.Infof("[Handler] 认证通过 - FlowID: %s, Connection: %s", flow.ID, req.Connection)

		// 6. 辅助验证（vchan/factor）及前置条件检查
		if done := h.handlePostAuth(c, flow); done {
			return
		}
	} else {
		logger.Infof("[Handler] Login 跳过认证（已验证） - FlowID: %s, Connection: %s", flow.ID, req.Connection)
	}

	// 7. 查找或创建用户，回写用户信息和全部身份到 flow
	if err := h.resolveUser(ctx, flow); err != nil {
		if errors.Is(err, errIdentifiedUser) {
			actionRedirect(c, buildActionURL([]string{"identify"}))
			return
		}
		logger.Errorf("[Handler] 用户解析失败 - FlowID: %s, Error: %v", flow.ID, err)
		h.errorResponse(c, err)
		return
	}
	logger.Infof("[Handler] 用户解析完成 - FlowID: %s, UserID: %s", flow.ID, flow.User.OpenID)

	// 8. 授权并生成授权码
	authCode, err := h.authorizeAndGenerateCode(ctx, flow)
	if err != nil {
		logger.Errorf("[Handler] 授权签发失败 - FlowID: %s, Error: %v", flow.ID, err)
		h.errorResponse(c, err)
		return
	}
	logger.Infof("[Handler] Login 完成 - FlowID: %s, Connection: %s", flow.ID, req.Connection)

	// 9. 签发 SSO Token
	h.issueSSOCookie(c, ctx, flow)

	// 10. 构建最终重定向
	clearAuthSessionCookie(c)
	actionRedirect(c, buildAuthCodeRedirectURL(flow.Request.RedirectURI, authCode))
}

// issueSSOCookie 签发 SSO Token 并设置 cookie
// 合并已有 SSO 身份：如果用户已有其他域的 SSO 会话，保留并追加当前域身份
func (h *Handler) issueSSOCookie(c *gin.Context, ctx context.Context, flow *types.AuthFlow) {
	if flow.User == nil || flow.Application == nil {
		return
	}

	domainID := flow.Application.DomainID

	// 尝试读取已有 SSO Token 中的身份
	identities := make(map[string]string)
	if existingToken, err := getSSOCookie(c); err == nil && existingToken != "" {
		if t, err := h.tokenSvc.Verify(ctx, existingToken); err == nil {
			if oldSSO, ok := t.(*token.SSOToken); ok {
				identities = oldSSO.GetIdentities()
			}
		}
	}

	// 追加/覆盖当前域的身份
	identities[domainID] = flow.User.OpenID

	sso := pkgtoken.NewClaimsBuilder().
		Issuer(token.SSOIssuer).
		ClientID(token.SSOIssuer).
		Audience(token.SSOAudience).
		ExpiresIn(config.GetSSOTTL()).
		Build(token.NewSSOTokenBuilder().
			Identities(identities))

	tokenString, err := h.tokenSvc.Issue(ctx, sso)
	if err != nil {
		logger.Warnf("[Handler] SSO token 签发失败: %v", err)
		return
	}
	logger.Debugf("[Handler] SSO token 签发成功, domain=%s, identities=%v", domainID, identities)
	setSSOCookie(c, tokenString)
}

// handlePostAuth 处理认证成功后的辅助验证和前置条件检查
// 返回 true 表示已处理响应（辅助验证完成 / 前置条件未满足），Login 应 return
// flow 的持久化由 Login 的 defer 统一处理
func (h *Handler) handlePostAuth(c *gin.Context, flow *types.AuthFlow) bool {
	connCfg := flow.GetCurrentConnConfig()
	if connCfg == nil {
		return false
	}

	// 辅助验证（vchan / factor）：只标记 Verified，不产生 identity
	// 通过 300 告知前端回到登录页继续下一步
	if connCfg.Type != types.ConnTypeIDP {
		actionRedirect(c, config.GetEndpointLogin())
		return true
	}

	// 前置验证未全部通过 → 300 action redirect
	if actions := unmetRequirements(flow); len(actions) > 0 {
		actionRedirect(c, buildActionURL(actions))
		return true
	}

	return false
}

// resolveUser 解析用户信息并回写到 flow
// 返回 errIdentifiedUser 表示识别到已有用户，需前端确认关联
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
		// IDP 身份不存在，尝试通过邮箱/手机号查找已有用户（Account Linking）
		existingUser := h.findExistingUser(ctx, idp.Domain(domain), flow.Identify)

		if existingUser != nil {
			// 找到已有用户，直接设到 flow.User（State 保持 Initialized），由 actions 机制驱动前端
			flow.User = existingUser
			logger.Infof("[Handler] Account Linking: 识别到已有用户 - Domain: %s, OpenID: %s, Connection: %s",
				domain, existingUser.OpenID, connection)
			return errIdentifiedUser
		}

		// 未找到已有用户，检查是否允许注册
		if !idp.IsIDPAllowedForDomain(connection, idp.Domain(domain)) {
			return autherrors.NewAccessDenied("registration not allowed for this IDP")
		}

		// 创建新用户及当前认证身份
		allIdentities, err = h.userSvc.CreateUser(ctx, identity, flow.Identify)
		if err != nil {
			return err
		}
	}

	// 2. 找到当前域下的 global 身份，获取用户信息
	globalIdentity := allIdentities.FindByDomainAndIDP(domain, idp.TypeGlobal)
	if globalIdentity == nil {
		return autherrors.NewServerError("global identity not found for domain")
	}

	u, err := h.userSvc.GetUser(ctx, globalIdentity.OpenID)
	if err != nil {
		return autherrors.NewServerError("user not found after identity resolved")
	}

	// 回写到 flow
	flow.Identities = allIdentities
	flow.SetAuthenticated(u)

	// 异步更新最后登录时间
	openid := u.OpenID
	h.pool.GoWithContext(ctx, func(ctx context.Context) {
		if err := h.userSvc.UpdateLastLogin(ctx, openid); err != nil {
			logger.Warnf("[Handler] 异步更新登录时间失败: %v", err)
		}
	})

	return nil
}

// findExistingUser 根据域类型查找已有用户
// platform 域通过邮箱查找，consumer 域通过手机号查找
func (h *Handler) findExistingUser(ctx context.Context, domain idp.Domain, userInfo *models.TUserInfo) *models.UserWithDecrypted {
	if userInfo == nil {
		return nil
	}

	switch domain {
	case idp.DomainPlatform:
		if userInfo.Email == "" {
			return nil
		}
		user, err := h.userSvc.FindUserByEmail(ctx, userInfo.Email)
		if err != nil {
			return nil
		}
		return user

	case idp.DomainConsumer:
		if userInfo.Phone == "" {
			return nil
		}
		user, err := h.userSvc.FindUserByPhone(ctx, userInfo.Phone)
		if err != nil {
			return nil
		}
		return user
	}

	return nil
}

// ==================== 5. 账户关联（Account Linking） ====================

// GetIdentifyContext GET /auth/binding
// 获取识别到的已有用户信息（前端关联确认页展示用）
func (h *Handler) GetIdentifyContext(c *gin.Context) {
	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewFlowNotFound("missing session"))
		return
	}

	ctx := c.Request.Context()

	flow := h.authenticateSvc.GetAndValidateFlow(ctx, flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	if !flow.HasIdentifiedUser() {
		h.errorResponse(c, autherrors.NewInvalidRequest("no identified user"))
		return
	}

	resp := &IdentifyResponse{
		Connection: flow.Connection,
		User: &IdentifiedUser{
			Nickname: flow.User.GetNickname(),
			Picture:  flow.User.GetPicture(),
		},
	}

	c.JSON(http.StatusOK, resp)
}

// ConfirmIdentify POST /auth/binding
// 用户确认或取消账户关联
func (h *Handler) ConfirmIdentify(c *gin.Context) {
	var req ConfirmIdentifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	flowID, err := getAuthSessionCookie(c)
	if err != nil || flowID == "" {
		h.errorResponse(c, autherrors.NewFlowNotFound("missing session"))
		return
	}

	ctx := c.Request.Context()

	flow := h.authenticateSvc.GetAndValidateFlow(ctx, flowID)
	if flow.HasError() {
		h.flowErrorResponse(c, flow)
		return
	}

	// defer 统一持久化 flow
	defer func() {
		if err := h.authenticateSvc.SaveFlow(ctx, flow); err != nil {
			logger.Warnf("[Handler] 保存 flow 失败: %v", err)
		}
	}()

	if !flow.HasIdentifiedUser() {
		h.errorResponse(c, autherrors.NewInvalidRequest("no identified user"))
		return
	}

	if !req.Confirm {
		// 用户取消关联 → 清除中间态，回到登录页重新选择
		flow.User = nil
		actionRedirect(c, buildActionURL(nil))
		return
	}

	// 用户确认关联 → 将新 IDP 身份关联到已有用户
	connection := flow.Connection
	identity := flow.GetIdentity(connection)
	if identity == nil {
		h.errorResponse(c, autherrors.NewServerError("identity not found in flow"))
		return
	}

	identifiedUser := flow.User

	now := time.Now()
	newIdentity := &models.UserIdentity{
		Domain:    identity.Domain,
		IDP:       identity.IDP,
		TOpenID:   identity.TOpenID,
		OpenID:    identifiedUser.OpenID,
		RawData:   identity.RawData,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := h.userSvc.LinkIdentity(ctx, newIdentity); err != nil {
		logger.Errorf("[Handler] Account Linking 失败: %v", err)
		h.errorResponse(c, autherrors.NewServerError("identity linking failed"))
		return
	}

	logger.Infof("[Handler] Account Linking 成功 - OpenID: %s, Connection: %s", identifiedUser.OpenID, connection)

	// 获取关联后的全部身份，完成登录流程
	allIdentities, err := h.userSvc.GetIdentities(ctx, newIdentity)
	if err != nil {
		h.errorResponse(c, autherrors.NewServerError("failed to load identities"))
		return
	}

	// 回写到 flow，设置为已认证
	flow.Identities = allIdentities
	flow.SetAuthenticated(identifiedUser)

	// 授权并生成授权码
	authCode, err := h.authorizeAndGenerateCode(ctx, flow)
	if err != nil {
		h.errorResponse(c, err)
		return
	}

	// 异步更新最后登录时间
	openid := identifiedUser.OpenID
	h.pool.GoWithContext(ctx, func(ctx context.Context) {
		if err := h.userSvc.UpdateLastLogin(ctx, openid); err != nil {
			logger.Warnf("[Handler] 异步更新登录时间失败: %v", err)
		}
	})

	// 签发 SSO Token
	h.issueSSOCookie(c, ctx, flow)

	// 构建最终重定向
	clearAuthSessionCookie(c)
	actionRedirect(c, buildAuthCodeRedirectURL(flow.Request.RedirectURI, authCode))
}

// authorizeAndGenerateCode 准备授权并生成授权码
// 调用前需确保 flow 已通过 resolveUser 设置好 User 和 Identities
func (h *Handler) authorizeAndGenerateCode(ctx context.Context, flow *types.AuthFlow) (*cache.AuthorizationCode, error) {
	// 1. 检查服务的身份要求
	if err := h.authorizeSvc.CheckIdentityRequirements(ctx, flow); err != nil {
		logger.Errorf("[Handler] 身份要求检查失败: %v", err)
		return nil, err
	}

	// 2. 计算 scope 交集
	grantedScopes, err := h.authorizeSvc.ComputeGrantedScopes(flow)
	if err != nil {
		logger.Errorf("[Handler] 计算 scope 失败: %v", err)
		return nil, err
	}
	flow.SetAuthorized(grantedScopes)

	// 3. 生成授权码
	authCode, err := h.authorizeSvc.GenerateAuthCode(ctx, flow)
	if err != nil {
		logger.Errorf("[Handler] 生成授权码失败: %v", err)
		return nil, autherrors.NewServerError(err.Error())
	}

	return authCode, nil
}

func buildAuthCodeRedirectURL(redirectURI string, authCode *cache.AuthorizationCode) string {
	location := redirectURI + "?code=" + url.QueryEscape(authCode.Code)
	if authCode.State != "" {
		location += "&state=" + url.QueryEscape(authCode.State)
	}
	return location
}

// ==================== 6. Token 换取 ====================

// Token POST /auth/token
// 换取 Token
// Content-Type: application/x-www-form-urlencoded → 标准单 audience
// Content-Type: application/json → 多 audience
func (h *Handler) Token(c *gin.Context) {
	if c.ContentType() == "application/json" {
		h.tokenMultiAudience(c)
		return
	}
	h.tokenSingleAudience(c)
}

// tokenSingleAudience 标准 OAuth2 单 audience token 交换
func (h *Handler) tokenSingleAudience(c *gin.Context) {
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

	logger.Debugf("[Handler] Token response - ClientID: %s, ExpiresIn: %d, Scope: %s, HasRefreshToken: %v",
		req.ClientID, resp.ExpiresIn, resp.Scope, resp.RefreshToken != "")

	c.JSON(http.StatusOK, resp)
}

// tokenMultiAudience 多 audience token 交换
func (h *Handler) tokenMultiAudience(c *gin.Context) {
	var req authorize.MultiAudienceTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	resp, err := h.authorizeSvc.ExchangeMultiAudienceToken(c.Request.Context(), &req)
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
	cat := c.GetHeader(HeaderAuthorization)
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
	t, err := h.tokenSvc.Verify(ctx, cat)
	if err != nil {
		logger.Debugf("[Handler] verify CAT failed: %v", err)
		c.JSON(http.StatusUnauthorized, CheckResponse{
			Permitted: false,
			Error:     "unauthorized",
			Message:   "invalid CAT",
		})
		return
	}
	catClaims, ok := t.(*token.ClientAccessToken)
	if !ok {
		c.JSON(http.StatusUnauthorized, CheckResponse{
			Permitted: false,
			Error:     "unauthorized",
			Message:   "expected CAT token",
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
	if err := h.cache.RevokeRefreshToken(c.Request.Context(), req.Token); err != nil {
		logger.Warnf("[Handler] revoke token failed: %v", err)
	}
	c.Status(http.StatusOK)
}

// Logout POST /auth/logout
// 登出（撤销 refresh token + 清除 SSO cookie）
func (h *Handler) Logout(c *gin.Context) {
	claims := GetToken(c)
	if claims == nil {
		// 即使没有 access token，也可以清除 SSO cookie（全局登出）
		clearSSOCookie(c)
		c.Status(http.StatusOK)
		return
	}

	if err := h.cache.RevokeUserRefreshTokens(c.Request.Context(), GetOpenIDFromToken(claims)); err != nil {
		h.errorResponse(c, autherrors.NewServerError("failed to revoke tokens"))
		return
	}

	clearSSOCookie(c)
	c.Status(http.StatusOK)
}

// ==================== 10. 公钥 ====================

// PublicKeys GET /pubkeys
// 获取 PASETO 公钥
func (h *Handler) PublicKeys(c *gin.Context) {
	clientID := c.Query(QueryClientID)
	if clientID == "" {
		h.errorResponse(c, autherrors.NewInvalidRequest("client_id is required"))
		return
	}

	publicKey, err := h.authorizeSvc.GetPublicKey(c.Request.Context(), clientID)
	if err != nil {
		h.errorResponse(c, autherrors.NewClientNotFound(err.Error()))
		return
	}

	maxAge := int(config.GetPublicKeyCacheMaxAge().Seconds())
	c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	c.JSON(http.StatusOK, publicKey)
}

// ==================== 11. 用户信息 ====================

// GetToken 从上下文获取验证后的 Token
func GetToken(c *gin.Context) token.Token {
	if t, exists := c.Get(ContextKeyUser); exists {
		if tk, ok := t.(token.Token); ok {
			return tk
		}
	}
	return nil
}

// ==================== 私有方法（Handler） ====================

// errorResponse 统一错误响应
// 仅返回 HTTP status code；有附加数据时（429 retry_after、428 required）发送 data
func (h *Handler) errorResponse(c *gin.Context, err error) {
	authErr := autherrors.ToAuthError(err)
	if len(authErr.Data) > 0 {
		c.JSON(authErr.HTTPStatus, authErr.Data)
	} else {
		c.Status(authErr.HTTPStatus)
	}
}

// authorizeErrorResponse authorize 接口专用错误响应
// 返回 {"error": "...", "error_description": "..."}，符合 OAuth 2.0 规范
func (h *Handler) authorizeErrorResponse(c *gin.Context, err error) {
	authErr := autherrors.ToAuthError(err)
	c.JSON(authErr.HTTPStatus, gin.H{
		"error":             authErr.Code,
		"error_description": authErr.Description,
	})
}

// flowErrorResponse 从 AuthFlow 中提取错误并响应
func (h *Handler) flowErrorResponse(c *gin.Context, flow *types.AuthFlow) {
	if flow.Error == nil {
		h.errorResponse(c, autherrors.NewServerError("unknown error"))
		return
	}

	// flow 失效时清除无效的 session cookie
	if flow.Error.Code == autherrors.CodeFlowNotFound || flow.Error.Code == autherrors.CodeFlowExpired {
		clearAuthSessionCookie(c)
	}

	if len(flow.Error.Data) > 0 {
		c.JSON(flow.Error.HTTPStatus, flow.Error.Data)
	} else {
		c.Status(flow.Error.HTTPStatus)
	}
}

// ==================== 私有辅助函数（包级别） ====================

// setAuthSessionCookie 设置 Auth 会话 Cookie
// 使用 http.SetCookie 以支持 SameSite 属性
// SameSite=None 允许跨站请求携带 Cookie（OAuth 场景需要），必须配合 Secure=true
func setAuthSessionCookie(c *gin.Context, value string) {
	cookie := &http.Cookie{
		Name:     AuthSessionCookie,
		Value:    value,
		MaxAge:   config.GetCookieMaxAge(),
		Path:     config.GetCookiePath(),
		Domain:   config.GetCookieDomain(),
		Secure:   config.GetCookieSecure(),
		HttpOnly: config.GetCookieHTTPOnly(),
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
		Path:     config.GetCookiePath(),
		Domain:   config.GetCookieDomain(),
		Secure:   config.GetCookieSecure(),
		HttpOnly: config.GetCookieHTTPOnly(),
		SameSite: http.SameSiteNoneMode,
	}
	http.SetCookie(c.Writer, cookie)
}

// getAuthSessionCookie 获取 Auth 会话 Cookie
func getAuthSessionCookie(c *gin.Context) (string, error) {
	return c.Cookie(AuthSessionCookie)
}

// ==================== SSO Cookie 辅助函数 ====================

func setSSOCookie(c *gin.Context, value string) {
	cookie := &http.Cookie{
		Name:     config.GetSSOCookieName(),
		Value:    value,
		MaxAge:   config.GetSSOCookieMaxAge(),
		Path:     config.GetCookiePath(),
		Domain:   config.GetCookieDomain(),
		Secure:   config.GetCookieSecure(),
		HttpOnly: config.GetCookieHTTPOnly(),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(c.Writer, cookie)
}

func clearSSOCookie(c *gin.Context) {
	cookie := &http.Cookie{
		Name:     config.GetSSOCookieName(),
		Value:    "",
		MaxAge:   -1,
		Path:     config.GetCookiePath(),
		Domain:   config.GetCookieDomain(),
		Secure:   config.GetCookieSecure(),
		HttpOnly: config.GetCookieHTTPOnly(),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(c.Writer, cookie)
}

func getSSOCookie(c *gin.Context) (string, error) {
	return c.Cookie(config.GetSSOCookieName())
}

// forwardNext 根据 AuthFlow 状态决定下一步重定向（统一使用 300 Multiple Choices）
//
// 根据 flow.State 决定跳转目标:
//   - initialized -> login（需要登录）
//   - authenticated -> consent（需要授权同意）
//   - authorized/completed -> 跳转回应用
//   - failed -> login（前端通过 /auth/context 获取错误状态）
func forwardNext(c *gin.Context, flow *types.AuthFlow) {
	var targetURL string

	switch flow.State {
	case types.FlowStateAuthenticated:
		targetURL = config.GetEndpointConsent()

	case types.FlowStateAuthorized, types.FlowStateCompleted:
		targetURL = flow.Request.RedirectURI

	case types.FlowStateFailed:
		targetURL = config.GetEndpointLogin()

	default:
		targetURL = config.GetEndpointLogin()
	}

	actionRedirect(c, targetURL)
}

// ==================== 300 Action Redirect 辅助函数 ====================

// actionRedirect 发送 HTTP 300 Multiple Choices 指令式重定向
// AJAX 请求不会自动跟随 300，前端通过 Location header 获取下一步指令
func actionRedirect(c *gin.Context, location string) {
	c.Header("Location", location)
	c.Header("Access-Control-Expose-Headers", "Location")
	c.Status(http.StatusMultipleChoices)
}

// unmetRequirements 返回当前 Connection 的 Require 中未验证通过的 connection 列表
// 空切片表示所有前置条件已满足
func unmetRequirements(flow *types.AuthFlow) []string {
	connCfg := flow.GetCurrentConnConfig()
	if connCfg == nil {
		return nil
	}
	// require 只作用于 strategy 路径
	if !connCfg.ContainsStrategy(flow.GetExtra(types.ExtraKeyStrategy)) {
		return nil
	}
	var actions []string
	for _, reqConn := range connCfg.Require {
		if cfg, ok := flow.ConnectionMap[reqConn]; !ok || !cfg.Verified {
			actions = append(actions, reqConn)
		}
	}
	return actions
}

// buildActionURL 基于配置的前端登录端点构建 action URL
// actions 以逗号分隔写入 ?action= 参数
// 使用配置端点而非 Referer/Origin，防止 open redirect
func buildActionURL(actions []string) string {
	base := config.GetEndpointLogin()
	u, err := url.Parse(base)
	if err != nil {
		u = &url.URL{}
	}
	q := u.Query()
	if len(actions) > 0 {
		q.Set("actions", strings.Join(actions, ","))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

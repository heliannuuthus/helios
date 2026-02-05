package iris

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/internal/aegis/authenticate/authenticator/webauthn"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Handler 用户信息处理器
type Handler struct {
	userSvc       *hermes.UserService
	credentialSvc *hermes.CredentialService
	webauthnSvc   *webauthn.Service
}

// NewHandler 创建用户信息处理器
func NewHandler(userSvc *hermes.UserService, credentialSvc *hermes.CredentialService) *Handler {
	return &Handler{
		userSvc:       userSvc,
		credentialSvc: credentialSvc,
	}
}

// SetWebAuthnService 设置 WebAuthn 服务（可选）
func (h *Handler) SetWebAuthnService(svc *webauthn.Service) {
	h.webauthnSvc = svc
}

// getToken 从上下文获取验证后的 Token
func getToken(c *gin.Context) token.Token {
	if vt, exists := c.Get("user"); exists {
		if t, ok := vt.(token.Token); ok {
			return t
		}
	}
	return nil
}

// getOpenID 从 Token 中获取 OpenID
func getOpenID(t token.Token) string {
	if uat, ok := token.AsUAT(t); ok && uat.HasUser() {
		return uat.GetOpenID()
	}
	return ""
}

// errorResponse 统一错误响应
func errorResponse(c *gin.Context, err error) {
	authErr := autherrors.ToAuthError(err)
	c.JSON(authErr.HTTPStatus, authErr)
}

// ==================== 用户信息 ====================

// ProfileResponse 用户信息响应
type ProfileResponse struct {
	OpenID        string  `json:"id"`
	Nickname      *string `json:"nickname,omitempty"`
	Picture       *string `json:"picture,omitempty"`
	Email         *string `json:"email,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Phone         string  `json:"phone,omitempty"`
}

// GetProfile GET /user/profile
// 获取当前用户信息
func (h *Handler) GetProfile(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	user, err := h.userSvc.GetUserWithDecrypted(c.Request.Context(), getOpenID(claims))
	if err != nil {
		errorResponse(c, autherrors.NewNotFound("user not found"))
		return
	}

	c.JSON(http.StatusOK, &ProfileResponse{
		OpenID:        user.OpenID,
		Nickname:      user.Nickname,
		Picture:       user.Picture,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Phone:         user.Phone,
	})
}

// UpdateProfileRequest 更新用户信息请求
type UpdateProfileRequest struct {
	Nickname *string `json:"nickname,omitempty"`
	Picture  *string `json:"picture,omitempty"`
}

// UpdateProfile PUT /user/profile
// 更新用户信息
func (h *Handler) UpdateProfile(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	updates := make(map[string]any)
	if req.Nickname != nil {
		updates["nickname"] = *req.Nickname
	}
	if req.Picture != nil {
		updates["picture"] = *req.Picture
	}

	if len(updates) == 0 {
		errorResponse(c, autherrors.NewInvalidRequest("no fields to update"))
		return
	}

	if err := h.userSvc.Update(c.Request.Context(), getOpenID(claims), updates); err != nil {
		errorResponse(c, autherrors.NewServerError(err.Error()))
		return
	}

	// 返回更新后的信息
	h.GetProfile(c)
}

// UploadAvatar POST /user/profile/avatar
// 上传头像
func (h *Handler) UploadAvatar(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	// TODO: 实现头像上传（使用 OSS）
	errorResponse(c, autherrors.NewServerError("not implemented"))
}

// UpdateEmailRequest 更新邮箱请求
type UpdateEmailRequest struct {
	Email string `json:"email" binding:"required,email"`
	Code  string `json:"code" binding:"required"` // 验证码
}

// UpdateEmail PUT /user/profile/email
// 绑定/更新邮箱
func (h *Handler) UpdateEmail(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	var req UpdateEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// TODO: 验证邮箱验证码后更新
	// 1. 验证 code
	// 2. 更新 email 和 email_verified

	errorResponse(c, autherrors.NewServerError("not implemented"))
}

// UpdatePhoneRequest 更新手机号请求
type UpdatePhoneRequest struct {
	Phone string `json:"phone" binding:"required"`
	Code  string `json:"code" binding:"required"` // 验证码
}

// UpdatePhone PUT /user/profile/phone
// 绑定/更新手机号
func (h *Handler) UpdatePhone(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	var req UpdatePhoneRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	// TODO: 验证手机验证码后更新
	errorResponse(c, autherrors.NewServerError("not implemented"))
}

// ==================== 第三方身份 ====================

// IdentityResponse 身份响应
type IdentityResponse struct {
	IDP       string `json:"idp"`
	CreatedAt string `json:"created_at"`
}

// ListIdentities GET /user/identities
// 获取绑定的第三方身份列表
func (h *Handler) ListIdentities(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	identities, err := h.userSvc.GetIdentities(c.Request.Context(), getOpenID(claims))
	if err != nil {
		errorResponse(c, autherrors.NewServerError(err.Error()))
		return
	}

	resp := make([]IdentityResponse, len(identities))
	for i, id := range identities {
		resp[i] = IdentityResponse{
			IDP:       id.IDP,
			CreatedAt: id.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	c.JSON(http.StatusOK, gin.H{"identities": resp})
}

// BindIdentity POST /user/identities/:idp
// 绑定第三方身份
func (h *Handler) BindIdentity(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	idp := c.Param("idp")
	if idp == "" {
		errorResponse(c, autherrors.NewInvalidRequest("idp is required"))
		return
	}

	// TODO: 实现第三方身份绑定
	// 1. 重定向到 OAuth 授权页面
	// 2. 回调处理绑定
	errorResponse(c, autherrors.NewServerError("not implemented"))
}

// UnbindIdentity DELETE /user/identities/:idp
// 解绑第三方身份
func (h *Handler) UnbindIdentity(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	idp := c.Param("idp")
	if idp == "" {
		errorResponse(c, autherrors.NewInvalidRequest("idp is required"))
		return
	}

	// TODO: 实现解绑（需要检查是否还有其他登录方式）
	errorResponse(c, autherrors.NewServerError("not implemented"))
}

// ==================== MFA 设置 ====================

// GetMFAStatus GET /user/mfa
// 获取 MFA 状态
func (h *Handler) GetMFAStatus(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	ctx := c.Request.Context()

	status, err := h.credentialSvc.GetUserMFAStatus(ctx, getOpenID(claims))
	if err != nil {
		errorResponse(c, autherrors.NewServerError(err.Error()))
		return
	}

	summaries, err := h.credentialSvc.GetUserCredentialSummaries(ctx, getOpenID(claims))
	if err != nil {
		errorResponse(c, autherrors.NewServerError(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      status,
		"credentials": summaries,
	})
}

// SetupMFARequest 设置 MFA 请求
type SetupMFARequest struct {
	Type   string `json:"type" binding:"required,oneof=totp webauthn passkey"`
	Action string `json:"action,omitempty"` // "begin" 或 "finish"（WebAuthn 专用）

	// TOTP 专用
	AppName string `json:"app_name,omitempty"`

	// WebAuthn finish 阶段专用
	ChallengeID string `json:"challenge_id,omitempty"` // begin 返回的 challenge_id
}

// SetupMFA POST /user/mfa
// 设置 MFA
// - TOTP: 直接返回 secret 和 otpauth_uri
// - WebAuthn: action=begin 返回 options，action=finish 完成注册
func (h *Handler) SetupMFA(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	var req SetupMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		resp, err := h.credentialSvc.SetupTOTP(ctx, &hermes.TOTPSetupRequest{
			OpenID:  getOpenID(claims),
			AppName: req.AppName,
		})
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"type":          "totp",
			"credential_id": resp.CredentialID,
			"secret":        resp.Secret,
			"otpauth_uri":   resp.OTPAuthURI,
		})

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		h.setupWebAuthn(c, getOpenID(claims), req.Type, req.Action, req.ChallengeID)

	default:
		errorResponse(c, autherrors.NewInvalidRequest("unsupported credential type"))
	}
}

// setupWebAuthn 处理 WebAuthn 设置流程
func (h *Handler) setupWebAuthn(c *gin.Context, openID, credType, action, challengeID string) {
	if h.webauthnSvc == nil {
		errorResponse(c, autherrors.NewServerError("webauthn not enabled"))
		return
	}

	ctx := c.Request.Context()

	switch action {
	case "", "begin":
		// 开始注册
		user, err := h.userSvc.GetUserWithDecrypted(ctx, openID)
		if err != nil {
			errorResponse(c, autherrors.NewNotFound("user not found"))
			return
		}

		existingCredentials, err := h.webauthnSvc.ListCredentials(ctx, user.OpenID)
		if err != nil {
			// 列出凭证失败时，使用空列表继续（新用户可能没有凭证）
			existingCredentials = nil
		}
		resp, err := h.webauthnSvc.BeginRegistration(ctx, user, existingCredentials)
		if err != nil {
			errorResponse(c, autherrors.NewServerError(err.Error()))
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"type":         credType,
			"action":       "begin",
			"options":      resp.Options,
			"challenge_id": resp.ChallengeID,
		})

	case "finish":
		if challengeID == "" {
			errorResponse(c, autherrors.NewInvalidRequest("challenge_id is required for finish"))
			return
		}

		credential, err := h.webauthnSvc.FinishRegistration(ctx, challengeID, c.Request)
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}

		if err := h.webauthnSvc.SaveCredential(ctx, openID, credential); err != nil {
			errorResponse(c, autherrors.NewServerError("save credential failed"))
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"type":          credType,
			"action":        "finish",
			"success":       true,
			"credential_id": encodeCredentialID(credential.ID),
		})

	default:
		errorResponse(c, autherrors.NewInvalidRequest("invalid action, must be 'begin' or 'finish'"))
	}
}

// VerifyMFARequest 验证 MFA 请求
type VerifyMFARequest struct {
	Type   string `json:"type" binding:"required,oneof=totp webauthn passkey"`
	Action string `json:"action,omitempty"` // "begin" 或 "finish"（WebAuthn 专用）

	// TOTP 专用
	CredentialID uint   `json:"credential_id,omitempty"`
	Code         string `json:"code,omitempty"`
	Confirm      bool   `json:"confirm,omitempty"` // 首次绑定确认

	// WebAuthn finish 阶段专用
	ChallengeID string `json:"challenge_id,omitempty"`
}

// VerifyMFA PUT /user/mfa
// 验证 MFA
// - TOTP: 直接验证 code
// - WebAuthn: action=begin 返回 options，action=finish 完成验证
func (h *Handler) VerifyMFA(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	var req VerifyMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		if req.Code == "" {
			errorResponse(c, autherrors.NewInvalidRequest("code is required"))
			return
		}

		if req.Confirm {
			if req.CredentialID == 0 {
				errorResponse(c, autherrors.NewInvalidRequest("credential_id is required for confirm"))
				return
			}
			err := h.credentialSvc.ConfirmTOTP(ctx, &hermes.ConfirmTOTPRequest{
				OpenID:       getOpenID(claims),
				CredentialID: req.CredentialID,
				Code:         req.Code,
			})
			if err != nil {
				errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
				return
			}
		} else {
			err := h.credentialSvc.VerifyTOTP(ctx, &hermes.VerifyTOTPRequest{
				OpenID: getOpenID(claims),
				Code:   req.Code,
			})
			if err != nil {
				errorResponse(c, autherrors.NewAccessDenied(err.Error()))
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"type": "totp", "success": true})

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		h.verifyWebAuthn(c, getOpenID(claims), req.Type, req.Action, req.ChallengeID)

	default:
		errorResponse(c, autherrors.NewInvalidRequest("unsupported credential type"))
	}
}

// verifyWebAuthn 处理 WebAuthn 验证流程
func (h *Handler) verifyWebAuthn(c *gin.Context, openID, credType, action, challengeID string) {
	if h.webauthnSvc == nil {
		errorResponse(c, autherrors.NewServerError("webauthn not enabled"))
		return
	}

	ctx := c.Request.Context()

	switch action {
	case "", "begin":
		// 开始验证
		user, err := h.userSvc.GetUserWithDecrypted(ctx, openID)
		if err != nil {
			errorResponse(c, autherrors.NewNotFound("user not found"))
			return
		}

		existingCredentials, err := h.webauthnSvc.ListCredentials(ctx, user.OpenID)
		if err != nil || len(existingCredentials) == 0 {
			errorResponse(c, autherrors.NewInvalidRequest("no webauthn credentials found"))
			return
		}

		resp, err := h.webauthnSvc.BeginLogin(ctx, user, existingCredentials)
		if err != nil {
			errorResponse(c, autherrors.NewServerError(err.Error()))
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"type":         credType,
			"action":       "begin",
			"options":      resp.Options,
			"challenge_id": resp.ChallengeID,
		})

	case "finish":
		if challengeID == "" {
			errorResponse(c, autherrors.NewInvalidRequest("challenge_id is required for finish"))
			return
		}

		userID, credential, err := h.webauthnSvc.FinishLogin(ctx, challengeID, c.Request)
		if err != nil {
			errorResponse(c, autherrors.NewAccessDenied(err.Error()))
			return
		}

		// 更新签名计数
		if err := h.webauthnSvc.UpdateCredentialSignCount(ctx, encodeCredentialID(credential.ID), credential.Authenticator.SignCount); err != nil {
			logger.Warnf("[WebAuthn] UpdateCredentialSignCount failed: %v", err)
		}

		c.JSON(http.StatusOK, gin.H{
			"type":    credType,
			"action":  "finish",
			"success": true,
			"user_id": userID,
		})

	default:
		errorResponse(c, autherrors.NewInvalidRequest("invalid action, must be 'begin' or 'finish'"))
	}
}

// UpdateMFARequest 更新 MFA 请求
type UpdateMFARequest struct {
	Type         string `json:"type" binding:"required,oneof=totp webauthn passkey"`
	CredentialID string `json:"credential_id,omitempty"`
	Enabled      *bool  `json:"enabled"`
}

// UpdateMFA PATCH /user/mfa
// 启用/禁用 MFA
func (h *Handler) UpdateMFA(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	var req UpdateMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	if req.Enabled == nil {
		errorResponse(c, autherrors.NewInvalidRequest("enabled is required"))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		err := h.credentialSvc.SetTOTPEnabled(ctx, getOpenID(claims), *req.Enabled)
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		if req.CredentialID == "" {
			errorResponse(c, autherrors.NewInvalidRequest("credential_id is required"))
			return
		}
		err := h.credentialSvc.SetWebAuthnEnabled(ctx, getOpenID(claims), req.CredentialID, *req.Enabled)
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}

	default:
		errorResponse(c, autherrors.NewInvalidRequest("unsupported credential type"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// DeleteMFARequest 删除 MFA 请求
type DeleteMFARequest struct {
	Type         string `json:"type" binding:"required,oneof=totp webauthn passkey"`
	CredentialID string `json:"credential_id,omitempty"`
}

// DeleteMFA DELETE /user/mfa
// 删除 MFA
func (h *Handler) DeleteMFA(c *gin.Context) {
	claims := getToken(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	var req DeleteMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		err := h.credentialSvc.DisableTOTP(ctx, getOpenID(claims))
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		if req.CredentialID == "" {
			errorResponse(c, autherrors.NewInvalidRequest("credential_id is required"))
			return
		}
		err := h.credentialSvc.DeleteWebAuthn(ctx, getOpenID(claims), req.CredentialID)
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}

	default:
		errorResponse(c, autherrors.NewInvalidRequest("unsupported credential type"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// encodeCredentialID 编码凭证 ID
func encodeCredentialID(id []byte) string {
	return encodeBase64URL(id)
}

// encodeBase64URL Base64URL 编码
func encodeBase64URL(data []byte) string {
	const base64URLCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, 0, (len(data)*4+2)/3)
	for i := 0; i < len(data); i += 3 {
		val := uint32(data[i]) << 16
		if i+1 < len(data) {
			val |= uint32(data[i+1]) << 8
		}
		if i+2 < len(data) {
			val |= uint32(data[i+2])
		}

		result = append(result, base64URLCharset[(val>>18)&0x3F])
		result = append(result, base64URLCharset[(val>>12)&0x3F])
		if i+1 < len(data) {
			result = append(result, base64URLCharset[(val>>6)&0x3F])
		}
		if i+2 < len(data) {
			result = append(result, base64URLCharset[val&0x3F])
		}
	}
	return string(result)
}

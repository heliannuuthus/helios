package iris

import (
	"net/http"

	"github.com/gin-gonic/gin"

	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/token"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// Handler 用户信息处理器
type Handler struct {
	userSvc       *hermes.UserService
	credentialSvc *hermes.CredentialService
}

// NewHandler 创建用户信息处理器
func NewHandler(userSvc *hermes.UserService, credentialSvc *hermes.CredentialService) *Handler {
	return &Handler{
		userSvc:       userSvc,
		credentialSvc: credentialSvc,
	}
}

// getClaims 从上下文获取用户 Claims
func getClaims(c *gin.Context) *token.Claims {
	if claims, exists := c.Get("user"); exists {
		if cl, ok := claims.(*token.Claims); ok {
			return cl
		}
	}
	return nil
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
	claims := getClaims(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	user, err := h.userSvc.GetUserWithDecrypted(c.Request.Context(), claims.Subject)
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
	claims := getClaims(c)
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

	if err := h.userSvc.Update(c.Request.Context(), claims.Subject, updates); err != nil {
		errorResponse(c, autherrors.NewServerError(err.Error()))
		return
	}

	// 返回更新后的信息
	h.GetProfile(c)
}

// UploadAvatar POST /user/profile/avatar
// 上传头像
func (h *Handler) UploadAvatar(c *gin.Context) {
	claims := getClaims(c)
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
	claims := getClaims(c)
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
	claims := getClaims(c)
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
	claims := getClaims(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	identities, err := h.userSvc.GetIdentities(c.Request.Context(), claims.Subject)
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
	claims := getClaims(c)
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
	claims := getClaims(c)
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
	claims := getClaims(c)
	if claims == nil {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	ctx := c.Request.Context()

	status, err := h.credentialSvc.GetUserMFAStatus(ctx, claims.Subject)
	if err != nil {
		errorResponse(c, autherrors.NewServerError(err.Error()))
		return
	}

	summaries, err := h.credentialSvc.GetUserCredentialSummaries(ctx, claims.Subject)
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
	Type    string `json:"type" binding:"required,oneof=totp webauthn passkey"`
	AppName string `json:"app_name,omitempty"`

	// WebAuthn 专用
	CredentialID    string   `json:"credential_id,omitempty"`
	PublicKey       string   `json:"public_key,omitempty"`
	AAGUID          string   `json:"aaguid,omitempty"`
	Transport       []string `json:"transport,omitempty"`
	AttestationType string   `json:"attestation_type,omitempty"`
}

// SetupMFA POST /user/mfa
// 设置 MFA
func (h *Handler) SetupMFA(c *gin.Context) {
	claims := getClaims(c)
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
			OpenID:  claims.Subject,
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
		if req.CredentialID == "" || req.PublicKey == "" {
			errorResponse(c, autherrors.NewInvalidRequest("credential_id and public_key are required"))
			return
		}
		credential, err := h.credentialSvc.RegisterWebAuthn(ctx, &hermes.RegisterWebAuthnRequest{
			OpenID:          claims.Subject,
			CredentialID:    req.CredentialID,
			PublicKey:       req.PublicKey,
			AAGUID:          req.AAGUID,
			Transport:       req.Transport,
			AttestationType: req.AttestationType,
		})
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"type":          req.Type,
			"credential_id": credential.ID,
		})

	default:
		errorResponse(c, autherrors.NewInvalidRequest("unsupported credential type"))
	}
}

// VerifyMFARequest 验证 MFA 请求
type VerifyMFARequest struct {
	Type         string `json:"type" binding:"required,oneof=totp webauthn passkey"`
	CredentialID uint   `json:"credential_id,omitempty"`
	Code         string `json:"code,omitempty"`
	Confirm      bool   `json:"confirm,omitempty"`
}

// VerifyMFA PUT /user/mfa
// 验证 MFA
func (h *Handler) VerifyMFA(c *gin.Context) {
	claims := getClaims(c)
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
				OpenID:       claims.Subject,
				CredentialID: req.CredentialID,
				Code:         req.Code,
			})
			if err != nil {
				errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
				return
			}
		} else {
			err := h.credentialSvc.VerifyTOTP(ctx, &hermes.VerifyTOTPRequest{
				OpenID: claims.Subject,
				Code:   req.Code,
			})
			if err != nil {
				errorResponse(c, autherrors.NewAccessDenied(err.Error()))
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"success": true})

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		errorResponse(c, autherrors.NewInvalidRequest("webauthn verification not implemented"))

	default:
		errorResponse(c, autherrors.NewInvalidRequest("unsupported credential type"))
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
	claims := getClaims(c)
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
		err := h.credentialSvc.SetTOTPEnabled(ctx, claims.Subject, *req.Enabled)
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		if req.CredentialID == "" {
			errorResponse(c, autherrors.NewInvalidRequest("credential_id is required"))
			return
		}
		err := h.credentialSvc.SetWebAuthnEnabled(ctx, claims.Subject, req.CredentialID, *req.Enabled)
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
	claims := getClaims(c)
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
		err := h.credentialSvc.DisableTOTP(ctx, claims.Subject)
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		if req.CredentialID == "" {
			errorResponse(c, autherrors.NewInvalidRequest("credential_id is required"))
			return
		}
		err := h.credentialSvc.DeleteWebAuthn(ctx, claims.Subject, req.CredentialID)
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

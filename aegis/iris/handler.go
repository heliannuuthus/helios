package iris

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-json-experiment/json/jsontext"

	"github.com/heliannuuthus/aegis"
	"github.com/heliannuuthus/aegis/contract"
	autherrors "github.com/heliannuuthus/aegis/errors"
	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/pkg/aegis/guard"
	"github.com/heliannuuthus/pkg/patch"
)

// Handler 用户信息处理器
type Handler struct {
	userSvc contract.UserProvider
	mfaSvc  *aegis.MFAService
}

// getOpenID 从 context 中获取用户标识
func getOpenID(c *gin.Context) string {
	return guard.GetTokenContext(c.Request.Context()).AccessToken.OpenID()
}

// errorResponse 统一错误响应
func errorResponse(c *gin.Context, err error) {
	authErr := autherrors.ToAuthError(err)
	c.JSON(authErr.HTTPStatus, authErr)
}

// encodeCredentialID 编码凭证 ID 为 Base64URL 字符串
func encodeCredentialID(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}

// NewHandler 创建用户信息处理器
func NewHandler(userSvc contract.UserProvider, mfaSvc *aegis.MFAService) *Handler {
	return &Handler{
		userSvc: userSvc,
		mfaSvc:  mfaSvc,
	}
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
	openid := getOpenID(c)
	if openid == "" {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	user, err := h.userSvc.GetUserByOpenID(c.Request.Context(), openid)
	if err != nil {
		errorResponse(c, autherrors.NewNotFound("user not found"))
		return
	}

	c.JSON(http.StatusOK, &ProfileResponse{
		OpenID:        openid,
		Nickname:      user.Nickname,
		Picture:       user.Picture,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Phone:         user.Phone,
	})
}

// UpdateProfileRequest 更新用户信息请求（JSON Merge Patch 语义）
type UpdateProfileRequest struct {
	Nickname    patch.Optional[string] `json:"nickname,omitempty"`
	Picture     patch.Optional[string] `json:"picture,omitempty"`
	OldPassword string                 `json:"old_password,omitempty"` // 修改密码时需提供旧密码
	Password    patch.Optional[string] `json:"password,omitempty"`     // 新密码
}

// UpdateProfile PATCH /user/profile
// 更新用户信息
func (h *Handler) UpdateProfile(c *gin.Context) {
	openid := getOpenID(c)
	if openid == "" {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()

	// 收集基础字段更新
	updates := patch.Collect(
		patch.Field("nickname", req.Nickname),
		patch.Field("picture", req.Picture),
	)

	hasProfileUpdates := len(updates) > 0
	hasPasswordUpdate := req.Password.HasValue()

	if !hasProfileUpdates && !hasPasswordUpdate {
		errorResponse(c, autherrors.NewInvalidRequest("no fields to update"))
		return
	}

	// 处理密码修改
	if hasPasswordUpdate {
		if err := aegis.ChangePassword(ctx, h.userSvc, openid, req.OldPassword, req.Password.Value()); err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}
	}

	// 处理其他字段更新
	if hasProfileUpdates {
		if err := h.userSvc.PatchUser(ctx, openid, updates); err != nil {
			errorResponse(c, autherrors.NewServerError(err.Error()))
			return
		}
	}

	// 返回更新后的信息
	h.GetProfile(c)
}

// UploadAvatar POST /user/profile/avatar
// 上传头像
func (h *Handler) UploadAvatar(c *gin.Context) {
	openid := getOpenID(c)
	if openid == "" {
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
	if getOpenID(c) == "" {
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
	if getOpenID(c) == "" {
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
	openid := getOpenID(c)
	if openid == "" {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	identities, err := h.userSvc.ListUserIdentities(c.Request.Context(), openid)
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
	if getOpenID(c) == "" {
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
	if getOpenID(c) == "" {
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
	openid := getOpenID(c)
	if openid == "" {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	ctx := c.Request.Context()
	status, err := h.mfaSvc.GetMFAStatus(ctx, openid)
	if err != nil {
		errorResponse(c, autherrors.NewServerError(err.Error()))
		return
	}

	summaries, err := h.mfaSvc.ListCredentialSummaries(ctx, openid)
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
	Type string `json:"type" binding:"required,oneof=totp webauthn passkey"`

	// TOTP 专用
	AppName string `json:"app_name,omitempty"`
}

// SetupMFA POST /user/mfa
// 初始化 MFA 凭证
// - TOTP: 直接返回 secret 和 otpauth_uri
// - WebAuthn/Passkey: 返回创建凭证所需的 options 和 uid
func (h *Handler) SetupMFA(c *gin.Context) {
	openid := getOpenID(c)
	if openid == "" {
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
		resp, err := h.mfaSvc.BeginTOTP(ctx, &models.TOTPSetupRequest{
			OpenID:  openid,
			AppName: req.AppName,
		})
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"type":        "totp",
			"uid":         resp.UID,
			"secret":      resp.Secret,
			"otpauth_uri": resp.OTPAuthURI,
		})

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		h.beginWebAuthnRegistration(c, openid, req.Type)

	default:
		errorResponse(c, autherrors.NewInvalidRequest("unsupported credential type"))
	}
}

// CompleteMFARequest 完成 MFA 凭证创建请求
type CompleteMFARequest struct {
	Type string `json:"type" binding:"required,oneof=totp webauthn passkey"`

	// TOTP 专用
	Code string `json:"code,omitempty"`

	// WebAuthn/Passkey 专用
	Credential jsontext.Value `json:"credential,omitempty"`
}

// CompleteMFA POST /user/mfa/:uid
// 完成 MFA 凭证创建
// - TOTP: 用验证码确认绑定
// - WebAuthn/Passkey: 用 attestation credential 完成注册
func (h *Handler) CompleteMFA(c *gin.Context) {
	openid := getOpenID(c)
	if openid == "" {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	var req CompleteMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()
	uid := c.Param("uid")
	if uid == "" {
		errorResponse(c, autherrors.NewInvalidRequest("uid is required"))
		return
	}

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		if req.Code == "" {
			errorResponse(c, autherrors.NewInvalidRequest("code is required"))
			return
		}
		err := h.mfaSvc.CompleteTOTP(ctx, &models.ConfirmTOTPRequest{
			OpenID: openid,
			UID:    uid,
			Code:   req.Code,
		})
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}
		c.JSON(http.StatusOK, gin.H{"type": "totp", "success": true})

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		h.finishWebAuthnRegistration(c, openid, req.Type, uid, req.Credential)

	default:
		errorResponse(c, autherrors.NewInvalidRequest("unsupported credential type"))
	}
}

// UpdateMFARequest 更新 MFA 请求
type UpdateMFARequest struct {
	Type         string `json:"type" binding:"required,oneof=totp webauthn passkey"`
	CredentialID string `json:"credential_id,omitempty"`
	Enabled      *bool  `json:"enabled"`
	Label        string `json:"label,omitempty"`
}

// UpdateMFA PATCH /user/mfa
// 启用/禁用 MFA
func (h *Handler) UpdateMFA(c *gin.Context) {
	openid := getOpenID(c)
	if openid == "" {
		errorResponse(c, autherrors.NewInvalidToken("not authenticated"))
		return
	}

	var req UpdateMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	if req.Enabled == nil && req.Label == "" {
		errorResponse(c, autherrors.NewInvalidRequest("enabled or label is required"))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		if req.Enabled == nil {
			errorResponse(c, autherrors.NewInvalidRequest("enabled is required for totp"))
			return
		}
		err := h.mfaSvc.PatchCredential(ctx, openid, req.Type, "", map[string]any{"enabled": *req.Enabled})
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		if req.CredentialID == "" {
			errorResponse(c, autherrors.NewInvalidRequest("credential_id is required"))
			return
		}
		updates := make(map[string]any)
		if req.Label != "" {
			updates["label"] = req.Label
		}
		if req.Enabled != nil {
			updates["enabled"] = *req.Enabled
		}
		if err := h.mfaSvc.PatchCredential(ctx, openid, req.Type, req.CredentialID, updates); err != nil {
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
	openid := getOpenID(c)
	if openid == "" {
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
		err := h.mfaSvc.DeleteCredential(ctx, openid, req.Type, "")
		if err != nil {
			errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
			return
		}

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		if req.CredentialID == "" {
			errorResponse(c, autherrors.NewInvalidRequest("credential_id is required"))
			return
		}
		err := h.mfaSvc.DeleteCredential(ctx, openid, req.Type, req.CredentialID)
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

// beginWebAuthnRegistration 发起 WebAuthn/Passkey MFA 凭证注册
func (h *Handler) beginWebAuthnRegistration(c *gin.Context, openID, credType string) {
	ctx := c.Request.Context()

	user, err := h.userSvc.GetUserByOpenID(ctx, openID)
	if err != nil {
		errorResponse(c, autherrors.NewNotFound("user not found"))
		return
	}
	resp, err := h.mfaSvc.BeginWebAuthnRegistration(ctx, user)
	if err != nil {
		errorResponse(c, autherrors.NewServerError(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"type":    credType,
		"uid":     resp.ChallengeID,
		"options": resp.Options,
	})
}

// finishWebAuthnRegistration 完成 WebAuthn/Passkey MFA 凭证注册
func (h *Handler) finishWebAuthnRegistration(c *gin.Context, openID, credType, uid string, credentialJSON jsontext.Value) {
	if uid == "" {
		errorResponse(c, autherrors.NewInvalidRequest("uid is required"))
		return
	}
	if len(credentialJSON) == 0 {
		errorResponse(c, autherrors.NewInvalidRequest("credential data is required"))
		return
	}

	c.Request.Body = io.NopCloser(bytes.NewReader(credentialJSON))
	credInfo, err := h.mfaSvc.FinishWebAuthnRegistration(c.Request.Context(), openID, uid, c.Request)
	if err != nil {
		errorResponse(c, autherrors.NewInvalidRequest(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"type":          credType,
		"success":       true,
		"credential_id": encodeCredentialID(credInfo.ID),
	})
}

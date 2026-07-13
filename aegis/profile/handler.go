package profile

import (
	"bytes"
	"context"
	"encoding/base64"
	stderrors "errors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-json-experiment/json/jsontext"
	"golang.org/x/crypto/bcrypt"

	"github.com/heliannuuthus/aegis/errors"
	"github.com/heliannuuthus/aegis/internal/mfa"
	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/aegis/rpc/hermes"
	"github.com/heliannuuthus/pkg/aegis/guard"
	"github.com/heliannuuthus/pkg/patch"
)

type Handler struct {
	hermes *hermes.Client
	mfaSvc *mfa.Service
}

func NewHandler(hermesClient *hermes.Client, mfaSvc *mfa.Service) *Handler {
	return &Handler{
		hermes: hermesClient,
		mfaSvc: mfaSvc,
	}
}

type ProfileResponse struct {
	OpenID        string  `json:"id"`
	Nickname      *string `json:"nickname,omitempty"`
	Picture       *string `json:"picture,omitempty"`
	Email         *string `json:"email,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Phone         string  `json:"phone,omitempty"`
}

func (h *Handler) GetProfile(c *gin.Context) {
	openid := guard.OpenID(c.Request.Context())
	if openid == "" {
		h.writeError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	user, err := h.hermes.GetUserByOpenID(c.Request.Context(), openid)
	if err != nil {
		h.writeError(c, errors.NewNotFound("user not found"))
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

type UpdateProfileRequest struct {
	Nickname    patch.Optional[string] `json:"nickname,omitempty"`
	Picture     patch.Optional[string] `json:"picture,omitempty"`
	Email       patch.Optional[string] `json:"email,omitempty"`
	Phone       patch.Optional[string] `json:"phone,omitempty"`
	OldPassword string                 `json:"old_password,omitempty"`
	Password    patch.Optional[string] `json:"password,omitempty"`
}

func (h *Handler) UpdateProfile(c *gin.Context) {
	openid := guard.OpenID(c.Request.Context())
	if openid == "" {
		h.writeError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.writeError(c, errors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()

	updates := patch.Collect(
		patch.Field("nickname", req.Nickname),
		patch.Field("picture", req.Picture),
		patch.Field("email", req.Email),
		patch.Field("phone", req.Phone),
	)

	hasProfileUpdates := len(updates) > 0
	hasPasswordUpdate := req.Password.HasValue()

	if !hasProfileUpdates && !hasPasswordUpdate {
		h.writeError(c, errors.NewInvalidRequest("no fields to update"))
		return
	}

	if hasPasswordUpdate {
		if err := h.changePassword(ctx, openid, req.OldPassword, req.Password.Value()); err != nil {
			h.writeError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
	}

	if hasProfileUpdates {
		if err := h.hermes.PatchUser(ctx, openid, updates); err != nil {
			h.writeError(c, errors.NewServerError(err.Error()))
			return
		}
	}

	h.GetProfile(c)
}

type IdentityResponse struct {
	IDP       string `json:"idp"`
	CreatedAt string `json:"created_at"`
}

func (h *Handler) ListIdentities(c *gin.Context) {
	openid := guard.OpenID(c.Request.Context())
	if openid == "" {
		h.writeError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	identities, err := h.hermes.ListUserIdentities(c.Request.Context(), openid)
	if err != nil {
		h.writeError(c, errors.NewServerError(err.Error()))
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

func (h *Handler) BindIdentity(c *gin.Context) {
	if guard.OpenID(c.Request.Context()) == "" {
		h.writeError(c, errors.NewInvalidToken("not authenticated"))
		return
	}
	h.writeError(c, errors.NewServerError("not implemented"))
}

func (h *Handler) UnbindIdentity(c *gin.Context) {
	if guard.OpenID(c.Request.Context()) == "" {
		h.writeError(c, errors.NewInvalidToken("not authenticated"))
		return
	}
	h.writeError(c, errors.NewServerError("not implemented"))
}

func (h *Handler) GetMFAStatus(c *gin.Context) {
	openid := guard.OpenID(c.Request.Context())
	if openid == "" {
		h.writeError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	ctx := c.Request.Context()
	status, err := h.mfaSvc.Status(ctx, openid)
	if err != nil {
		h.writeError(c, errors.NewServerError(err.Error()))
		return
	}

	summaries, err := h.mfaSvc.ListCredentials(ctx, openid)
	if err != nil {
		h.writeError(c, errors.NewServerError(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      status,
		"credentials": summaries,
	})
}

type SetupMFARequest struct {
	Type    string `json:"type" binding:"required,oneof=totp webauthn passkey"`
	AppName string `json:"app_name,omitempty"`
}

func (h *Handler) SetupMFA(c *gin.Context) {
	openid := guard.OpenID(c.Request.Context())
	if openid == "" {
		h.writeError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	var req SetupMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.writeError(c, errors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		resp, err := h.mfaSvc.CreateTOTPEnrollment(ctx, openid, req.AppName)
		if err != nil {
			h.writeError(c, errors.NewInvalidRequest(err.Error()))
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
		h.writeError(c, errors.NewInvalidRequest("unsupported credential type"))
	}
}

type CompleteMFARequest struct {
	Type       string         `json:"type" binding:"required,oneof=totp webauthn passkey"`
	Code       string         `json:"code,omitempty"`
	Credential jsontext.Value `json:"credential,omitempty"`
}

func (h *Handler) CompleteMFA(c *gin.Context) {
	openid := guard.OpenID(c.Request.Context())
	if openid == "" {
		h.writeError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	var req CompleteMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.writeError(c, errors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()
	uid := c.Param("uid")
	if uid == "" {
		h.writeError(c, errors.NewInvalidRequest("uid is required"))
		return
	}

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		if req.Code == "" {
			h.writeError(c, errors.NewInvalidRequest("code is required"))
			return
		}
		err := h.mfaSvc.ConfirmTOTPEnrollment(ctx, openid, uid, req.Code)
		if err != nil {
			h.writeError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
		c.JSON(http.StatusOK, gin.H{"type": "totp", "success": true})

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		h.finishWebAuthnRegistration(c, openid, req.Type, uid, req.Credential)

	default:
		h.writeError(c, errors.NewInvalidRequest("unsupported credential type"))
	}
}

type UpdateMFARequest struct {
	Type         string                 `json:"type" binding:"required,oneof=totp webauthn passkey"`
	CredentialID string                 `json:"credential_id,omitempty"`
	Enabled      patch.Optional[bool]   `json:"enabled,omitempty"`
	Label        patch.Optional[string] `json:"label,omitempty"`
}

func (h *Handler) UpdateMFA(c *gin.Context) {
	openid := guard.OpenID(c.Request.Context())
	if openid == "" {
		h.writeError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	var req UpdateMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.writeError(c, errors.NewInvalidRequest(err.Error()))
		return
	}

	if !req.Enabled.IsPresent() && !req.Label.IsPresent() {
		h.writeError(c, errors.NewInvalidRequest("enabled or label is required"))
		return
	}
	if req.Enabled.IsPresent() && !req.Enabled.HasValue() {
		h.writeError(c, errors.NewInvalidRequest("enabled is required"))
		return
	}
	if req.Label.IsPresent() && !req.Label.HasValue() {
		h.writeError(c, errors.NewInvalidRequest("label is required"))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		if !req.Enabled.HasValue() {
			h.writeError(c, errors.NewInvalidRequest("enabled is required for totp"))
			return
		}
		updates := patch.Collect(patch.Field("enabled", req.Enabled))
		if err := h.mfaSvc.UpdateCredential(ctx, openid, req.Type, "", updates); err != nil {
			h.writeError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		if req.CredentialID == "" {
			h.writeError(c, errors.NewInvalidRequest("credential_id is required"))
			return
		}
		updates := patch.Collect(
			patch.Field("label", req.Label),
			patch.Field("enabled", req.Enabled),
		)
		if err := h.mfaSvc.UpdateCredential(ctx, openid, req.Type, req.CredentialID, updates); err != nil {
			h.writeError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
	default:
		h.writeError(c, errors.NewInvalidRequest("unsupported credential type"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

type DeleteMFARequest struct {
	Type         string `json:"type" binding:"required,oneof=totp webauthn passkey"`
	CredentialID string `json:"credential_id,omitempty"`
}

func (h *Handler) DeleteMFA(c *gin.Context) {
	openid := guard.OpenID(c.Request.Context())
	if openid == "" {
		h.writeError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	var req DeleteMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.writeError(c, errors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		if err := h.mfaSvc.DeleteCredential(ctx, openid, req.Type, ""); err != nil {
			h.writeError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		if req.CredentialID == "" {
			h.writeError(c, errors.NewInvalidRequest("credential_id is required"))
			return
		}
		if err := h.mfaSvc.DeleteCredential(ctx, openid, req.Type, req.CredentialID); err != nil {
			h.writeError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
	default:
		h.writeError(c, errors.NewInvalidRequest("unsupported credential type"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *Handler) writeError(c *gin.Context, err error) {
	authErr := errors.ToAuthError(err)
	c.JSON(authErr.HTTPStatus, authErr)
}

func (h *Handler) changePassword(ctx context.Context, openid, oldPassword, newPassword string) error {
	user, err := h.hermes.GetUserByOpenID(ctx, openid)
	if err != nil {
		return stderrors.New("user not found")
	}
	if user.PasswordHash != nil && *user.PasswordHash != "" {
		if oldPassword == "" {
			return stderrors.New("old password is required")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(oldPassword)); err != nil {
			return stderrors.New("old password is incorrect")
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return h.hermes.PatchUser(ctx, openid, map[string]any{"password_hash": string(hash)})
}

func (h *Handler) beginWebAuthnRegistration(c *gin.Context, openID, credType string) {
	ctx := c.Request.Context()

	user, err := h.hermes.GetUserByOpenID(ctx, openID)
	if err != nil {
		h.writeError(c, errors.NewNotFound("user not found"))
		return
	}
	resp, err := h.mfaSvc.CreateWebAuthnEnrollment(ctx, user)
	if err != nil {
		h.writeError(c, errors.NewServerError(err.Error()))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"type":    credType,
		"uid":     resp.ChallengeID,
		"options": resp.Options,
	})
}

func (h *Handler) finishWebAuthnRegistration(c *gin.Context, openID, credType, uid string, credentialJSON jsontext.Value) {
	if uid == "" {
		h.writeError(c, errors.NewInvalidRequest("uid is required"))
		return
	}
	if len(credentialJSON) == 0 {
		h.writeError(c, errors.NewInvalidRequest("credential data is required"))
		return
	}

	c.Request.Body = io.NopCloser(bytes.NewReader(credentialJSON))
	credInfo, err := h.mfaSvc.ConfirmWebAuthnEnrollment(c.Request.Context(), openID, uid, c.Request)
	if err != nil {
		h.writeError(c, errors.NewInvalidRequest(err.Error()))
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"type":          credType,
		"success":       true,
		"credential_id": base64.RawURLEncoding.EncodeToString(credInfo.ID),
	})
}

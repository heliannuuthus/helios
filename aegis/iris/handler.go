package iris

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/heliannuuthus/aegis-go/guard"

	"github.com/heliannuuthus/helios/aegis/internal/contract"
	"github.com/heliannuuthus/helios/aegis/internal/errors"
	"github.com/heliannuuthus/helios/aegis/internal/models"
	"github.com/heliannuuthus/helios/pkg/patch"
)

type ProfileHandler struct {
	userSvc       contract.UserProvider
	credentialSvc contract.CredentialProvider
	mfaSvc        *MFAService
}

func NewProfileHandler(userSvc contract.UserProvider, credentialSvc contract.CredentialProvider, mfaSvc *MFAService) *ProfileHandler {
	return &ProfileHandler{
		userSvc:       userSvc,
		credentialSvc: credentialSvc,
		mfaSvc:        mfaSvc,
	}
}

func profileOpenID(c *gin.Context) string {
	return guard.GetTokenContext(c.Request.Context()).AccessToken.OpenID()
}

func profileError(c *gin.Context, err error) {
	authErr := errors.ToAuthError(err)
	c.JSON(authErr.HTTPStatus, authErr)
}

type ProfileResponse struct {
	OpenID        string  `json:"id"`
	Nickname      *string `json:"nickname,omitempty"`
	Picture       *string `json:"picture,omitempty"`
	Email         *string `json:"email,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Phone         string  `json:"phone,omitempty"`
}

func (h *ProfileHandler) GetProfile(c *gin.Context) {
	openid := profileOpenID(c)
	if openid == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	user, err := h.userSvc.GetDecryptedUserByOpenID(c.Request.Context(), openid)
	if err != nil {
		profileError(c, errors.NewNotFound("user not found"))
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
	OldPassword string                 `json:"old_password,omitempty"`
	Password    patch.Optional[string] `json:"password,omitempty"`
}

func (h *ProfileHandler) UpdateProfile(c *gin.Context) {
	openid := profileOpenID(c)
	if openid == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		profileError(c, errors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()

	updates := patch.Collect(
		patch.Field("nickname", req.Nickname),
		patch.Field("picture", req.Picture),
	)

	hasProfileUpdates := len(updates) > 0
	hasPasswordUpdate := req.Password.HasValue()

	if !hasProfileUpdates && !hasPasswordUpdate {
		profileError(c, errors.NewInvalidRequest("no fields to update"))
		return
	}

	if hasPasswordUpdate {
		if err := h.userSvc.UpdatePassword(ctx, openid, req.OldPassword, req.Password.Value()); err != nil {
			profileError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
	}

	if hasProfileUpdates {
		if err := h.userSvc.UpdateUser(ctx, openid, updates); err != nil {
			profileError(c, errors.NewServerError(err.Error()))
			return
		}
	}

	h.GetProfile(c)
}

func (h *ProfileHandler) UploadAvatar(c *gin.Context) {
	if profileOpenID(c) == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}
	profileError(c, errors.NewServerError("not implemented"))
}

func (h *ProfileHandler) UpdateEmail(c *gin.Context) {
	if profileOpenID(c) == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}
	profileError(c, errors.NewServerError("not implemented"))
}

func (h *ProfileHandler) UpdatePhone(c *gin.Context) {
	if profileOpenID(c) == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}
	profileError(c, errors.NewServerError("not implemented"))
}

type IdentityResponse struct {
	IDP       string `json:"idp"`
	CreatedAt string `json:"created_at"`
}

func (h *ProfileHandler) ListIdentities(c *gin.Context) {
	openid := profileOpenID(c)
	if openid == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	identities, err := h.userSvc.GetUserIdentitiesByOpenID(c.Request.Context(), openid)
	if err != nil {
		profileError(c, errors.NewServerError(err.Error()))
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

func (h *ProfileHandler) BindIdentity(c *gin.Context) {
	if profileOpenID(c) == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}
	profileError(c, errors.NewServerError("not implemented"))
}

func (h *ProfileHandler) UnbindIdentity(c *gin.Context) {
	if profileOpenID(c) == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}
	profileError(c, errors.NewServerError("not implemented"))
}

func (h *ProfileHandler) GetMFAStatus(c *gin.Context) {
	openid := profileOpenID(c)
	if openid == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	ctx := c.Request.Context()
	status, err := h.credentialSvc.GetUserMFAStatus(ctx, openid)
	if err != nil {
		profileError(c, errors.NewServerError(err.Error()))
		return
	}

	summaries, err := h.credentialSvc.GetUserCredentialSummaries(ctx, openid)
	if err != nil {
		profileError(c, errors.NewServerError(err.Error()))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":      status,
		"credentials": summaries,
	})
}

type SetupMFARequest struct {
	Type        string         `json:"type" binding:"required,oneof=totp webauthn passkey"`
	Action      string         `json:"action,omitempty"`
	AppName     string         `json:"app_name,omitempty"`
	ChallengeID string         `json:"challenge_id,omitempty"`
	Credential  jsontext.Value `json:"credential,omitempty"`
}

func (h *ProfileHandler) SetupMFA(c *gin.Context) {
	openid := profileOpenID(c)
	if openid == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	var req SetupMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		profileError(c, errors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		resp, err := h.credentialSvc.SetupTOTP(ctx, &models.TOTPSetupRequest{
			OpenID:  openid,
			AppName: req.AppName,
		})
		if err != nil {
			profileError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"type":          "totp",
			"credential_id": resp.CredentialID,
			"secret":        resp.Secret,
			"otpauth_uri":   resp.OTPAuthURI,
		})

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		h.setupWebAuthn(c, openid, req.Type, req.Action, req.ChallengeID, req.Credential)

	default:
		profileError(c, errors.NewInvalidRequest("unsupported credential type"))
	}
}

type VerifyMFARequest struct {
	Type         string         `json:"type" binding:"required,oneof=totp webauthn passkey"`
	Action       string         `json:"action,omitempty"`
	CredentialID uint           `json:"credential_id,omitempty"`
	Code         string         `json:"code,omitempty"`
	Confirm      bool           `json:"confirm,omitempty"`
	ChallengeID  string         `json:"challenge_id,omitempty"`
	Credential   jsontext.Value `json:"credential,omitempty"`
}

func (h *ProfileHandler) VerifyMFA(c *gin.Context) {
	openid := profileOpenID(c)
	if openid == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	var req VerifyMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		profileError(c, errors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		if req.Code == "" {
			profileError(c, errors.NewInvalidRequest("code is required"))
			return
		}
		if req.Confirm {
			if req.CredentialID == 0 {
				profileError(c, errors.NewInvalidRequest("credential_id is required for confirm"))
				return
			}
			err := h.credentialSvc.ConfirmTOTP(ctx, &models.ConfirmTOTPRequest{
				OpenID:       openid,
				CredentialID: req.CredentialID,
				Code:         req.Code,
			})
			if err != nil {
				profileError(c, errors.NewInvalidRequest(err.Error()))
				return
			}
		} else {
			err := h.credentialSvc.VerifyTOTP(ctx, &models.VerifyTOTPRequest{
				OpenID: openid,
				Code:   req.Code,
			})
			if err != nil {
				profileError(c, errors.NewAccessDenied(err.Error()))
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"type": "totp", "success": true})

	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		h.verifyWebAuthn(c, openid, req.Type, req.Action, req.ChallengeID, req.Credential)

	default:
		profileError(c, errors.NewInvalidRequest("unsupported credential type"))
	}
}

type UpdateMFARequest struct {
	Type         string `json:"type" binding:"required,oneof=totp webauthn passkey"`
	CredentialID string `json:"credential_id,omitempty"`
	Enabled      *bool  `json:"enabled"`
}

func (h *ProfileHandler) UpdateMFA(c *gin.Context) {
	openid := profileOpenID(c)
	if openid == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	var req UpdateMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		profileError(c, errors.NewInvalidRequest(err.Error()))
		return
	}

	if req.Enabled == nil {
		profileError(c, errors.NewInvalidRequest("enabled is required"))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		if err := h.credentialSvc.SetTOTPEnabled(ctx, openid, *req.Enabled); err != nil {
			profileError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		if req.CredentialID == "" {
			profileError(c, errors.NewInvalidRequest("credential_id is required"))
			return
		}
		if err := h.credentialSvc.SetWebAuthnEnabled(ctx, openid, req.CredentialID, *req.Enabled); err != nil {
			profileError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
	default:
		profileError(c, errors.NewInvalidRequest("unsupported credential type"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

type DeleteMFARequest struct {
	Type         string `json:"type" binding:"required,oneof=totp webauthn passkey"`
	CredentialID string `json:"credential_id,omitempty"`
}

func (h *ProfileHandler) DeleteMFA(c *gin.Context) {
	openid := profileOpenID(c)
	if openid == "" {
		profileError(c, errors.NewInvalidToken("not authenticated"))
		return
	}

	var req DeleteMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		profileError(c, errors.NewInvalidRequest(err.Error()))
		return
	}

	ctx := c.Request.Context()

	switch models.CredentialType(req.Type) {
	case models.CredentialTypeTOTP:
		if err := h.credentialSvc.DisableTOTP(ctx, openid); err != nil {
			profileError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
	case models.CredentialTypeWebAuthn, models.CredentialTypePasskey:
		if req.CredentialID == "" {
			profileError(c, errors.NewInvalidRequest("credential_id is required"))
			return
		}
		if err := h.credentialSvc.DeleteWebAuthn(ctx, openid, req.CredentialID); err != nil {
			profileError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
	default:
		profileError(c, errors.NewInvalidRequest("unsupported credential type"))
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *ProfileHandler) setupWebAuthn(c *gin.Context, openID, credType, action, challengeID string, credentialJSON jsontext.Value) {
	if !h.mfaSvc.WebAuthnEnabled() {
		profileError(c, errors.NewServerError("webauthn not enabled"))
		return
	}

	ctx := c.Request.Context()

	switch action {
	case "", "begin":
		user, err := h.userSvc.GetDecryptedUserByOpenID(ctx, openID)
		if err != nil {
			profileError(c, errors.NewNotFound("user not found"))
			return
		}
		resp, err := h.mfaSvc.BeginWebAuthnRegistration(ctx, user)
		if err != nil {
			profileError(c, errors.NewServerError(err.Error()))
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
			profileError(c, errors.NewInvalidRequest("challenge_id is required for finish"))
			return
		}
		if len(credentialJSON) == 0 {
			profileError(c, errors.NewInvalidRequest("credential data is required for finish"))
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(credentialJSON))

		credInfo, err := h.mfaSvc.FinishWebAuthnRegistration(ctx, openID, challengeID, c.Request)
		if err != nil {
			profileError(c, errors.NewInvalidRequest(err.Error()))
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"type":          credType,
			"action":        "finish",
			"success":       true,
			"credential_id": base64.RawURLEncoding.EncodeToString(credInfo.ID),
		})

	default:
		profileError(c, errors.NewInvalidRequest("invalid action, must be 'begin' or 'finish'"))
	}
}

func (h *ProfileHandler) verifyWebAuthn(c *gin.Context, openID, credType, action, challengeID string, credentialJSON jsontext.Value) {
	if !h.mfaSvc.WebAuthnEnabled() {
		profileError(c, errors.NewServerError("webauthn not enabled"))
		return
	}

	ctx := c.Request.Context()

	switch action {
	case "", "begin":
		user, err := h.userSvc.GetDecryptedUserByOpenID(ctx, openID)
		if err != nil {
			profileError(c, errors.NewNotFound("user not found"))
			return
		}
		resp, err := h.mfaSvc.BeginWebAuthnVerification(ctx, user)
		if err != nil {
			profileError(c, errors.NewServerError(err.Error()))
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
			profileError(c, errors.NewInvalidRequest("challenge_id is required for finish"))
			return
		}
		if len(credentialJSON) == 0 {
			profileError(c, errors.NewInvalidRequest("credential data is required for finish"))
			return
		}
		openid, _, err := h.mfaSvc.FinishWebAuthnVerification(ctx, challengeID, credentialJSON)
		if err != nil {
			profileError(c, errors.NewAccessDenied(err.Error()))
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"type":    credType,
			"action":  "finish",
			"success": true,
			"openid":  openid,
		})

	default:
		profileError(c, errors.NewInvalidRequest("invalid action, must be 'begin' or 'finish'"))
	}
}

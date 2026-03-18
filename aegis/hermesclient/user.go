package hermesclient

import (
	"context"
	"fmt"

	hermesv1 "github.com/heliannuuthus/helios/gen/proto/hermes/v1"
	"github.com/heliannuuthus/helios/pkg/dto"
	"github.com/heliannuuthus/helios/pkg/models"
)

// ==================== User Query ====================

func (c *Client) GetByOpenID(ctx context.Context, openid string) (*models.User, error) {
	resp, err := c.user.GetByOpenID(ctx, &hermesv1.OpenIDRequest{Openid: openid})
	if err != nil {
		return nil, err
	}
	return userFromProto(resp), nil
}

func (c *Client) GetByIdentity(ctx context.Context, identity *models.UserIdentity) (*models.User, error) {
	resp, err := c.user.GetByIdentity(ctx, &hermesv1.GetByIdentityRequest{
		Domain:  identity.Domain,
		Idp:     identity.IDP,
		TOpenid: identity.TOpenID,
	})
	if err != nil {
		return nil, err
	}
	return userFromProto(resp), nil
}

func (c *Client) GetByEmail(ctx context.Context, email string) (*models.UserWithDecrypted, error) {
	resp, err := c.user.GetByEmail(ctx, &hermesv1.GetByEmailRequest{Email: email})
	if err != nil {
		return nil, err
	}
	return decryptedUserFromProto(resp), nil
}

func (c *Client) GetByPhonePlain(ctx context.Context, phone string) (*models.UserWithDecrypted, error) {
	resp, err := c.user.GetByPhonePlain(ctx, &hermesv1.GetByPhonePlainRequest{Phone: phone})
	if err != nil {
		return nil, err
	}
	return decryptedUserFromProto(resp), nil
}

func (c *Client) GetUserWithDecrypted(ctx context.Context, openid string) (*models.UserWithDecrypted, error) {
	resp, err := c.user.GetDecryptedUser(ctx, &hermesv1.OpenIDRequest{Openid: openid})
	if err != nil {
		return nil, err
	}
	return decryptedUserFromProto(resp), nil
}

func (c *Client) GetUserWithDecryptedByIdentity(ctx context.Context, identity *models.UserIdentity) (*models.UserWithDecrypted, error) {
	resp, err := c.user.GetDecryptedUserByIdentity(ctx, &hermesv1.GetByIdentityRequest{
		Domain:  identity.Domain,
		Idp:     identity.IDP,
		TOpenid: identity.TOpenID,
	})
	if err != nil {
		return nil, err
	}
	return decryptedUserFromProto(resp), nil
}

// ==================== User Write ====================

func (c *Client) CreateUser(ctx context.Context, identity *models.UserIdentity, userInfo *models.TUserInfo) (*models.UserWithDecrypted, error) {
	pbReq := &hermesv1.CreateUserRequest{
		Identity: &hermesv1.UserIdentity{
			Domain:  identity.Domain,
			Idp:     identity.IDP,
			TOpenid: identity.TOpenID,
			RawData: &identity.RawData,
		},
	}
	if userInfo != nil {
		pbReq.UserInfo = &hermesv1.TUserInfo{
			TOpenid: userInfo.TOpenID,
		}
		if userInfo.Nickname != "" {
			pbReq.UserInfo.Nickname = &userInfo.Nickname
		}
		if userInfo.Email != "" {
			pbReq.UserInfo.Email = &userInfo.Email
		}
		if userInfo.Phone != "" {
			pbReq.UserInfo.Phone = &userInfo.Phone
		}
		if userInfo.Picture != "" {
			pbReq.UserInfo.Picture = &userInfo.Picture
		}
		if userInfo.RawData != "" {
			pbReq.UserInfo.RawData = &userInfo.RawData
		}
	}
	resp, err := c.user.CreateUser(ctx, pbReq)
	if err != nil {
		return nil, fmt.Errorf("创建用户失败: %w", err)
	}
	return decryptedUserFromProto(resp), nil
}

func (c *Client) Update(ctx context.Context, openid string, updates map[string]any) error {
	pbReq := &hermesv1.UpdateUserRequest{Openid: openid}
	if v, ok := updates["nickname"]; ok {
		if s, ok := v.(string); ok {
			pbReq.Nickname = &s
		}
	}
	if v, ok := updates["picture"]; ok {
		if s, ok := v.(string); ok {
			pbReq.Picture = &s
		}
	}
	if v, ok := updates["email"]; ok {
		if s, ok := v.(string); ok {
			pbReq.Email = &s
		}
	}
	if v, ok := updates["status"]; ok {
		if s, ok := v.(int8); ok {
			i := int32(s)
			pbReq.Status = &i
		}
	}
	_, err := c.user.UpdateUser(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("更新用户失败: %w", err)
	}
	return nil
}

func (c *Client) UpdateLastLogin(ctx context.Context, openid string) error {
	_, err := c.user.UpdateLastLogin(ctx, &hermesv1.OpenIDRequest{Openid: openid})
	return err
}

func (c *Client) UpdatePassword(ctx context.Context, openid, oldPassword, newPassword string) error {
	_, err := c.user.UpdatePassword(ctx, &hermesv1.UpdatePasswordRequest{
		Openid:      openid,
		OldPassword: oldPassword,
		NewPassword: newPassword,
	})
	return err
}

// ==================== Identity ====================

func (c *Client) GetIdentities(ctx context.Context, openid string) (models.Identities, error) {
	resp, err := c.user.GetIdentities(ctx, &hermesv1.OpenIDRequest{Openid: openid})
	if err != nil {
		return nil, err
	}
	identities := make(models.Identities, 0, len(resp.Identities))
	for _, id := range resp.Identities {
		identities = append(identities, identityFromProto(id))
	}
	return identities, nil
}

func (c *Client) GetIdentitiesByIdentity(ctx context.Context, identity *models.UserIdentity) (models.Identities, error) {
	resp, err := c.user.GetIdentitiesByIdentity(ctx, &hermesv1.GetByIdentityRequest{
		Domain:  identity.Domain,
		Idp:     identity.IDP,
		TOpenid: identity.TOpenID,
	})
	if err != nil {
		return nil, err
	}
	identities := make(models.Identities, 0, len(resp.Identities))
	for _, id := range resp.Identities {
		identities = append(identities, identityFromProto(id))
	}
	return identities, nil
}

func (c *Client) GetIdentityByType(ctx context.Context, domain, openid, idpType string) (*models.UserIdentity, error) {
	resp, err := c.user.GetIdentityByType(ctx, &hermesv1.GetIdentityByTypeRequest{
		Domain:  domain,
		Openid:  openid,
		IdpType: idpType,
	})
	if err != nil {
		return nil, err
	}
	return identityFromProto(resp), nil
}

func (c *Client) AddIdentity(ctx context.Context, identity *models.UserIdentity) error {
	pbReq := &hermesv1.AddIdentityRequest{
		Domain:  identity.Domain,
		Openid:  identity.UID,
		Idp:     identity.IDP,
		TOpenid: identity.TOpenID,
	}
	if identity.RawData != "" {
		pbReq.RawData = &identity.RawData
	}
	_, err := c.user.AddIdentity(ctx, pbReq)
	return err
}

// ==================== Password Store ====================

func (c *Client) GetUserByIdentifier(ctx context.Context, identifier string) (*dto.PasswordStoreCredential, error) {
	resp, err := c.user.GetUserByIdentifier(ctx, &hermesv1.GetByIdentifierRequest{Identifier: identifier})
	if err != nil {
		return nil, err
	}
	return passwordStoreCredentialFromProto(resp), nil
}

func (c *Client) GetStaffByIdentifier(ctx context.Context, identifier string) (*dto.PasswordStoreCredential, error) {
	resp, err := c.user.GetStaffByIdentifier(ctx, &hermesv1.GetByIdentifierRequest{Identifier: identifier})
	if err != nil {
		return nil, err
	}
	return passwordStoreCredentialFromProto(resp), nil
}

// ==================== Credential CRUD ====================

func (c *Client) CreateCredential(ctx context.Context, cred *models.UserCredential) error {
	pbReq := &hermesv1.CreateCredentialRequest{
		Openid:  cred.OpenID,
		Type:    cred.Type,
		Enabled: cred.Enabled,
		Secret:  cred.Secret,
	}
	if cred.CredentialID != nil {
		pbReq.CredentialId = cred.CredentialID
	}
	_, err := c.user.CreateCredential(ctx, pbReq)
	return err
}

func (c *Client) GetCredentialByID(ctx context.Context, credentialID string) (*models.UserCredential, error) {
	resp, err := c.user.GetCredentialByID(ctx, &hermesv1.CredentialIDRequest{CredentialId: credentialID})
	if err != nil {
		return nil, err
	}
	return credentialFromProto(resp), nil
}

func (c *Client) GetUserCredentials(ctx context.Context, openid string) ([]models.UserCredential, error) {
	resp, err := c.user.GetUserCredentials(ctx, &hermesv1.OpenIDRequest{Openid: openid})
	if err != nil {
		return nil, err
	}
	creds := make([]models.UserCredential, 0, len(resp.Credentials))
	for _, cr := range resp.Credentials {
		creds = append(creds, *credentialFromProto(cr))
	}
	return creds, nil
}

func (c *Client) GetUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error) {
	resp, err := c.user.GetUserCredentialsByType(ctx, &hermesv1.GetCredentialsByTypeRequest{
		Openid: openid,
		Type:   credType,
	})
	if err != nil {
		return nil, err
	}
	creds := make([]models.UserCredential, 0, len(resp.Credentials))
	for _, cr := range resp.Credentials {
		creds = append(creds, *credentialFromProto(cr))
	}
	return creds, nil
}

func (c *Client) GetEnabledUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error) {
	resp, err := c.user.GetEnabledUserCredentialsByType(ctx, &hermesv1.GetCredentialsByTypeRequest{
		Openid: openid,
		Type:   credType,
	})
	if err != nil {
		return nil, err
	}
	creds := make([]models.UserCredential, 0, len(resp.Credentials))
	for _, cr := range resp.Credentials {
		creds = append(creds, *credentialFromProto(cr))
	}
	return creds, nil
}

func (c *Client) UpdateCredential(ctx context.Context, credentialID string, updates map[string]any) error {
	pbReq := &hermesv1.UpdateCredentialRequest{CredentialId: credentialID}
	if v, ok := updates["enabled"]; ok {
		if b, ok := v.(bool); ok {
			pbReq.Enabled = &b
		}
	}
	if v, ok := updates["secret"]; ok {
		if s, ok := v.(string); ok {
			pbReq.Secret = &s
		}
	}
	_, err := c.user.UpdateCredential(ctx, pbReq)
	return err
}

func (c *Client) UpdateCredentialSignCount(ctx context.Context, credentialID string, signCount uint32) error {
	_, err := c.user.UpdateCredentialSignCount(ctx, &hermesv1.UpdateCredentialSignCountRequest{
		CredentialId: credentialID,
		SignCount:    signCount,
	})
	return err
}

func (c *Client) EnableCredential(ctx context.Context, credentialID string) error {
	_, err := c.user.EnableCredential(ctx, &hermesv1.CredentialIDRequest{CredentialId: credentialID})
	return err
}

func (c *Client) DisableCredential(ctx context.Context, credentialID string) error {
	_, err := c.user.DisableCredential(ctx, &hermesv1.CredentialIDRequest{CredentialId: credentialID})
	return err
}

func (c *Client) DeleteCredential(ctx context.Context, openid, credentialID string) error {
	_, err := c.user.DeleteCredential(ctx, &hermesv1.DeleteCredentialRequest{
		Openid:       openid,
		CredentialId: credentialID,
	})
	return err
}

func (c *Client) GetOpenIDByCredentialID(ctx context.Context, credentialID string) (string, error) {
	resp, err := c.user.GetOpenIDByCredentialID(ctx, &hermesv1.CredentialIDRequest{CredentialId: credentialID})
	if err != nil {
		return "", err
	}
	return resp.Openid, nil
}

// ==================== Credential Summary & MFA ====================
// NOTE: Business logic (TOTP setup/verify, WebAuthn register/verify, MFA status)
// has been moved to iris layer. hermesclient only provides CRUD operations.

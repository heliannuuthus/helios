package hermes

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/heliannuuthus/aegis/models"
	hermesv1 "github.com/heliannuuthus/proto/gen/proto/hermes/v1"
)

// ==================== User Query ====================

func (c *Client) GetUserByOpenID(ctx context.Context, openid string) (*models.UserWithDecrypted, error) {
	resp, err := c.user.GetDecryptedUser(ctx, &hermesv1.OpenIDRequest{Openid: openid})
	if err != nil {
		return nil, err
	}
	return decryptedUserFromProto(resp), nil
}

func (c *Client) GetUserByEmail(ctx context.Context, email string) (*models.UserWithDecrypted, error) {
	resp, err := c.user.GetByEmail(ctx, &hermesv1.GetByEmailRequest{Email: email})
	if err != nil {
		return nil, err
	}
	return decryptedUserFromProto(resp), nil
}

func (c *Client) GetUserByPhone(ctx context.Context, phone string) (*models.UserWithDecrypted, error) {
	resp, err := c.user.GetByPhonePlain(ctx, &hermesv1.GetByPhonePlainRequest{Phone: phone})
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

func (c *Client) PatchUser(ctx context.Context, openid string, updates map[string]any) error {
	pbReq := &hermesv1.PatchUserRequest{Openid: openid}
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
	if v, ok := updates["password_hash"]; ok {
		if s, ok := v.(string); ok {
			pbReq.PasswordHash = &s
		}
	}
	if v, ok := updates["last_login_at"]; ok {
		if t, ok := v.(time.Time); ok {
			pbReq.LastLoginAt = timestamppb.New(t)
		}
	}
	_, err := c.user.PatchUser(ctx, pbReq)
	if err != nil {
		return fmt.Errorf("更新用户失败: %w", err)
	}
	return nil
}

// ==================== Identity ====================

func (c *Client) ListUserIdentities(ctx context.Context, openid string) (models.Identities, error) {
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

func (c *Client) ListIdentitiesByIdentity(ctx context.Context, domain, idp, tOpenID string) (models.Identities, error) {
	resp, err := c.user.GetIdentitiesByIdentity(ctx, &hermesv1.GetByIdentityRequest{
		Domain:  domain,
		Idp:     idp,
		TOpenid: tOpenID,
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

func (c *Client) CreateIdentity(ctx context.Context, identity *models.UserIdentity) error {
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

// ==================== Credential ====================

func (c *Client) CreateCredential(ctx context.Context, cred *models.UserCredential) error {
	pbReq := &hermesv1.CreateCredentialRequest{
		Openid: cred.OpenID,
		Type:   cred.Type,
		Secret: cred.Secret,
		Label:  cred.Label,
	}
	if cred.CredentialID != nil {
		pbReq.CredentialId = cred.CredentialID
	}
	_, err := c.user.CreateCredential(ctx, pbReq)
	return err
}

func (c *Client) DeleteCredential(ctx context.Context, openid, credentialID string) error {
	_, err := c.user.DeleteCredential(ctx, &hermesv1.DeleteCredentialRequest{
		Openid:       openid,
		CredentialId: credentialID,
	})
	return err
}

func (c *Client) DeleteCredentialByOpenIDAndType(ctx context.Context, openid, credType string) error {
	_, err := c.user.DeleteCredentialByOpenIDAndType(ctx, &hermesv1.DeleteCredentialByTypeRequest{
		Openid: openid,
		Type:   credType,
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

func (c *Client) ListUserCredentials(ctx context.Context, openid string) ([]models.UserCredential, error) {
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

func (c *Client) ListUserCredentialsByType(ctx context.Context, openid, credType string) ([]models.UserCredential, error) {
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

func (c *Client) GetCredentialByID(ctx context.Context, credentialID string) (*models.UserCredential, error) {
	resp, err := c.user.GetCredentialByID(ctx, &hermesv1.CredentialIDRequest{CredentialId: credentialID})
	if err != nil {
		return nil, err
	}
	return credentialFromProto(resp), nil
}

func (c *Client) PatchCredential(ctx context.Context, credentialID string, updates map[string]any) error {
	pbReq := &hermesv1.PatchCredentialRequest{CredentialId: credentialID}
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
	if v, ok := updates["label"]; ok {
		if s, ok := v.(string); ok {
			pbReq.Label = &s
		}
	}
	if v, ok := updates["last_used_at"]; ok {
		if t, ok := v.(time.Time); ok {
			pbReq.LastUsedAt = timestamppb.New(t)
		}
	}
	if v, ok := updates["sign_count"]; ok {
		switch n := v.(type) {
		case uint32:
			pbReq.SignCount = &n
		case uint:
			signCount := uint32(n)
			pbReq.SignCount = &signCount
		case int:
			signCount := uint32(n)
			pbReq.SignCount = &signCount
		}
	}
	_, err := c.user.PatchCredential(ctx, pbReq)
	return err
}

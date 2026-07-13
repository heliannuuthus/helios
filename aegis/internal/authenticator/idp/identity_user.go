package idp

import (
	"context"
	"errors"

	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/aegis/rpc/hermes"
)

var errIdentityUserNotFound = errors.New("user not found")

func ResolveUserIdentity(ctx context.Context, client *hermes.Client, idpType, principal string) (*models.UserWithDecrypted, *models.UserIdentity, error) {
	if principal == "" {
		return nil, nil, errIdentityUserNotFound
	}

	if user, identity, err := resolveByIdentityTag(ctx, client, idpType, principal); err == nil {
		return user, identity, nil
	}
	if user, identity, err := resolveByOpenID(ctx, client, idpType, principal); err == nil {
		return user, identity, nil
	}
	if isEmailPrincipal(principal) {
		if user, identity, err := resolveByEmail(ctx, client, idpType, principal); err == nil {
			return user, identity, nil
		}
	}
	if isPhonePrincipal(principal) {
		if user, identity, err := resolveByPhone(ctx, client, idpType, principal); err == nil {
			return user, identity, nil
		}
	}

	return nil, nil, errIdentityUserNotFound
}

func resolveByIdentityTag(ctx context.Context, client *hermes.Client, idpType, principal string) (*models.UserWithDecrypted, *models.UserIdentity, error) {
	identities, err := client.ListIdentitiesByIdentity(ctx, "", idpType, principal)
	if err != nil {
		return nil, nil, err
	}
	identity := identities.FindByIDP(idpType)
	if identity == nil {
		return nil, nil, errIdentityUserNotFound
	}
	user, err := client.GetUserByOpenID(ctx, identity.UID)
	if err != nil {
		return nil, nil, err
	}
	return user, identity, nil
}

func resolveByOpenID(ctx context.Context, client *hermes.Client, idpType, openid string) (*models.UserWithDecrypted, *models.UserIdentity, error) {
	user, err := client.GetUserByOpenID(ctx, openid)
	if err != nil {
		return nil, nil, err
	}
	identity, err := getUserIdentity(ctx, client, user.OpenID, idpType)
	if err != nil {
		return nil, nil, err
	}
	return user, identity, nil
}

func resolveByEmail(ctx context.Context, client *hermes.Client, idpType, email string) (*models.UserWithDecrypted, *models.UserIdentity, error) {
	user, err := client.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, nil, err
	}
	identity, err := getUserIdentity(ctx, client, user.OpenID, idpType)
	if err != nil {
		return nil, nil, err
	}
	return user, identity, nil
}

func resolveByPhone(ctx context.Context, client *hermes.Client, idpType, phone string) (*models.UserWithDecrypted, *models.UserIdentity, error) {
	user, err := client.GetUserByPhone(ctx, phone)
	if err != nil {
		return nil, nil, err
	}
	identity, err := getUserIdentity(ctx, client, user.OpenID, idpType)
	if err != nil {
		return nil, nil, err
	}
	return user, identity, nil
}

func getUserIdentity(ctx context.Context, client *hermes.Client, openid, idpType string) (*models.UserIdentity, error) {
	identities, err := client.ListUserIdentities(ctx, openid)
	if err != nil {
		return nil, err
	}
	identity := identities.FindByIDP(idpType)
	if identity == nil {
		return nil, errIdentityUserNotFound
	}
	return identity, nil
}

func isEmailPrincipal(s string) bool {
	for _, c := range s {
		if c == '@' {
			return true
		}
	}
	return false
}

func isPhonePrincipal(s string) bool {
	if len(s) < 10 || len(s) > 15 {
		return false
	}
	for i, c := range s {
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '+' && i == 0 {
			continue
		}
		return false
	}
	return true
}

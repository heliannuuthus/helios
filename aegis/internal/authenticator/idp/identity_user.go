package idp

import (
	"context"
	"errors"

	"github.com/heliannuuthus/aegis/contract"
	"github.com/heliannuuthus/aegis/models"
)

var errIdentityUserNotFound = errors.New("user not found")

func ResolveUserIdentity(ctx context.Context, users contract.UserProfileProvider, identities contract.IdentityProvider, idpType, principal string) (*models.UserWithDecrypted, *models.UserIdentity, error) {
	if principal == "" {
		return nil, nil, errIdentityUserNotFound
	}

	if user, identity, err := resolveByIdentityTag(ctx, users, identities, idpType, principal); err == nil {
		return user, identity, nil
	}
	if user, identity, err := resolveByOpenID(ctx, users, identities, idpType, principal); err == nil {
		return user, identity, nil
	}
	if isEmailPrincipal(principal) {
		if user, identity, err := resolveByEmail(ctx, users, identities, idpType, principal); err == nil {
			return user, identity, nil
		}
	}
	if isPhonePrincipal(principal) {
		if user, identity, err := resolveByPhone(ctx, users, identities, idpType, principal); err == nil {
			return user, identity, nil
		}
	}

	return nil, nil, errIdentityUserNotFound
}

func resolveByIdentityTag(ctx context.Context, users contract.UserProfileProvider, identityProvider contract.IdentityProvider, idpType, principal string) (*models.UserWithDecrypted, *models.UserIdentity, error) {
	identities, err := identityProvider.ListIdentitiesByIdentity(ctx, "", idpType, principal)
	if err != nil {
		return nil, nil, err
	}
	identity := identities.FindByIDP(idpType)
	if identity == nil {
		return nil, nil, errIdentityUserNotFound
	}
	user, err := users.GetUserByOpenID(ctx, identity.UID)
	if err != nil {
		return nil, nil, err
	}
	return user, identity, nil
}

func resolveByOpenID(ctx context.Context, users contract.UserProfileProvider, identities contract.IdentityProvider, idpType, openid string) (*models.UserWithDecrypted, *models.UserIdentity, error) {
	user, err := users.GetUserByOpenID(ctx, openid)
	if err != nil {
		return nil, nil, err
	}
	identity, err := getUserIdentity(ctx, identities, user.OpenID, idpType)
	if err != nil {
		return nil, nil, err
	}
	return user, identity, nil
}

func resolveByEmail(ctx context.Context, users contract.UserProfileProvider, identities contract.IdentityProvider, idpType, email string) (*models.UserWithDecrypted, *models.UserIdentity, error) {
	user, err := users.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, nil, err
	}
	identity, err := getUserIdentity(ctx, identities, user.OpenID, idpType)
	if err != nil {
		return nil, nil, err
	}
	return user, identity, nil
}

func resolveByPhone(ctx context.Context, users contract.UserProfileProvider, identities contract.IdentityProvider, idpType, phone string) (*models.UserWithDecrypted, *models.UserIdentity, error) {
	user, err := users.GetUserByPhone(ctx, phone)
	if err != nil {
		return nil, nil, err
	}
	identity, err := getUserIdentity(ctx, identities, user.OpenID, idpType)
	if err != nil {
		return nil, nil, err
	}
	return user, identity, nil
}

func getUserIdentity(ctx context.Context, identityProvider contract.IdentityProvider, openid, idpType string) (*models.UserIdentity, error) {
	identities, err := identityProvider.ListUserIdentities(ctx, openid)
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

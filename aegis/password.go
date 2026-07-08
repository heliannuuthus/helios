package aegis

import (
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"

	"github.com/heliannuuthus/aegis/contract"
	"github.com/heliannuuthus/aegis/internal/authenticator/idp"
)

func ChangePassword(ctx context.Context, userSvc contract.UserProvider, openid, oldPassword, newPassword string) error {
	cred, err := userSvc.GetPasswordAuth(ctx, idp.TypeGlobal, openid)
	if err != nil {
		return errors.New("user not found")
	}
	if cred.PasswordHash != "" {
		if oldPassword == "" {
			return errors.New("old password is required")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(oldPassword)); err != nil {
			return errors.New("old password is incorrect")
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return userSvc.PatchUser(ctx, openid, map[string]any{"password_hash": string(hash)})
}

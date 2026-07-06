package requirement

import (
	"context"

	"github.com/heliannuuthus/pkg/aegis/guard"
	"github.com/heliannuuthus/pkg/aegis/utilities/errors"
)

type userRequirement struct{}

// User 要求 token 为 UserAccessToken 且已解密用户身份。
func User() guard.Requirement {
	return &userRequirement{}
}

func (r *userRequirement) Enforce(ctx context.Context) error {
	tc := guard.GetTokenContext(ctx)
	if tc == nil || tc.AccessToken == nil || !tc.AccessToken.Identified() {
		return errors.ErrUnauthorized
	}
	return nil
}

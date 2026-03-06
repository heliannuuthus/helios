package requirement

import (
	"context"

	"github.com/heliannuuthus/helios/pkg/aegis/utils/errors"
	"github.com/heliannuuthus/helios/pkg/aegis/web"
)

type userRequirement struct{}

// User 要求 token 为 UserAccessToken 且已解密用户身份。
func User() web.Requirement {
	return &userRequirement{}
}

func (r *userRequirement) Enforce(ctx context.Context) error {
	tc := web.GetTokenContext(ctx)
	if tc == nil || tc.AccessToken == nil || !tc.AccessToken.Identified() {
		return errors.ErrUnauthorized
	}
	return nil
}

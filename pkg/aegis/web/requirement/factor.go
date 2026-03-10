package requirement

import (
	"context"
	"fmt"
	"slices"

	"github.com/heliannuuthus/helios/pkg/aegis/utils/errors"
	"github.com/heliannuuthus/helios/pkg/aegis/web"
)

type factorRequirement struct {
	types []string
}

// Factor 要求请求携带 ChallengeToken，且其 type 字段匹配给定值之一。
func Factor(types ...string) web.Requirement {
	return &factorRequirement{types: types}
}

func (r *factorRequirement) Enforce(ctx context.Context) error {
	tc := web.GetTokenContext(ctx)
	if tc == nil {
		return errors.ErrUnauthorized
	}
	ct := tc.ChallengeToken
	if ct == nil {
		return fmt.Errorf("missing challenge token for factor %v", r.types)
	}
	if !slices.Contains(r.types, ct.GetType()) {
		return fmt.Errorf("challenge token type %q not in %v", ct.GetType(), r.types)
	}
	return nil
}

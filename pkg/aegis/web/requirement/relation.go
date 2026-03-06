package requirement

import (
	"context"

	"github.com/heliannuuthus/helios/pkg/aegis/utils/errors"
	"github.com/heliannuuthus/helios/pkg/aegis/utils/relation"
	"github.com/heliannuuthus/helios/pkg/aegis/web"
	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	subjectTypeUser = "user"
	subjectTypeApp  = "app"
)

type relationRequirement struct {
	inner relation.Resolvable
}

// Relation 将 relation 包的构造产物包装为 Requirement。
//
//	reqr.Relation(relation.Expr("service:{path.id}#admin"))
//	reqr.Relation(relation.Build("admin").On("service", "{path.id}"))
//	reqr.Relation(relation.Qualify("admin", "service:{path.id}"))
func Relation(r relation.Resolvable) web.Requirement {
	return &relationRequirement{inner: r}
}

func (r *relationRequirement) Enforce(ctx context.Context) error {
	tc := web.GetTokenContext(ctx)
	if tc == nil || tc.AccessToken == nil {
		return errors.ErrForbidden
	}

	manager := web.GetTokenManager()
	if manager == nil {
		return errors.ErrForbidden
	}

	tuple, err := web.GetRelationResolver(ctx).Resolve(r.inner)
	if err != nil {
		logger.Errorf("[Relation] resolve failed: %v", err)
		return errors.ErrForbidden
	}

	subjectType := tuple.SubjectType
	subjectID := tuple.SubjectID
	if subjectType == "" || subjectID == "" {
		if tc.AccessToken.Identified() {
			subjectType = subjectTypeUser
			subjectID = tc.AccessToken.OpenID()
		} else {
			subjectType = subjectTypeApp
			subjectID = tc.AccessToken.ClientID()
		}
	}

	allowed, checkErr := manager.Check(ctx, tc.AccessToken.Audience(),
		subjectType, subjectID, tuple.Relation, tuple.ObjectType, tuple.ObjectID)
	if checkErr != nil || !allowed {
		return errors.ErrForbidden
	}
	return nil
}

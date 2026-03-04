package web

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/pkg/aegis/utils/expr"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
)

// FactorType 业务场景类型常量，对应 ChallengeToken.typ 字段。
type FactorType string

const (
	FactorStaffVerify   FactorType = "staff:verify"
	FactorUserVerify    FactorType = "user:verify"
	FactorPasskeyVerify FactorType = "passkey:verify"
)

// Requirement 声明式鉴权条件。
// Guard 在 Check 阶段依次调用 Enforce，全部通过才放行。
type Requirement interface {
	Enforce(ctx context.Context, tc *TokenContext, checker *RelationChecker) error
}

// ---------- Factor ----------

type factorRequirement struct {
	typ FactorType
}

// Factor 要求请求携带指定业务类型的 ChallengeToken。
func Factor(typ FactorType) Requirement {
	return &factorRequirement{typ: typ}
}

// ---------- Relation（表达式） ----------

type relationExprRequirement struct {
	ast        expr.Node
	objectType string
	objectID   string
}

// RelationExpr 通过布尔表达式声明关系鉴权条件（通配资源）。
//
// 支持 &&（与）、||（或）、!（非）和括号分组，标识符为 relation 名称。
//
//	RelationExpr("admin || editor")
//	RelationExpr("admin && !guest")
//	RelationExpr("(owner || admin) && !banned")
//
// 表达式在服务启动时解析，语法错误会 panic 以快速暴露配置问题。
func RelationExpr(expression string) Requirement {
	return RelationExprOn(expression, "*", "*")
}

// RelationExprOn 通过布尔表达式声明关系鉴权条件（指定资源）。
func RelationExprOn(expression, objectType, objectID string) Requirement {
	ast, err := expr.Parse(expression)
	if err != nil {
		panic(fmt.Sprintf("invalid relation expression %q: %v", expression, err))
	}
	return &relationExprRequirement{ast: ast, objectType: objectType, objectID: objectID}
}

// ---------- 便捷别名 ----------

// Relation 单个关系检查（通配资源），等价于 RelationExpr("admin")。
func Relation(relation string) Requirement {
	return RelationExpr(relation)
}

// RelationOn 单个关系检查（指定资源）。
func RelationOn(relation, objectType, objectID string) Requirement {
	return RelationExprOn(relation, objectType, objectID)
}

// accessTokenFrom 从 TokenContext 中提取 access token 用于鉴权。
func accessTokenFrom(tc *TokenContext) tokendef.Token {
	if uat := tc.UserAccessToken(); uat != nil {
		return uat
	}
	if sat := tc.ServiceAccessToken(); sat != nil { //nolint:revive // 直接 return sat 会导致 nil 具体类型包装成非 nil interface
		return sat
	}
	return nil
}

func (r *factorRequirement) Enforce(_ context.Context, tc *TokenContext, _ *RelationChecker) error {
	ct := tc.ChallengeToken()
	if ct == nil {
		return fmt.Errorf("missing challenge token for factor %q", r.typ)
	}
	if ct.GetType() != string(r.typ) {
		return fmt.Errorf("challenge token type mismatch: want %q, got %q", r.typ, ct.GetType())
	}
	return nil
}

func (r *relationExprRequirement) Enforce(ctx context.Context, tc *TokenContext, checker *RelationChecker) error {
	if checker == nil {
		return errForbidden
	}
	t := accessTokenFrom(tc)
	if t == nil {
		return errForbidden
	}

	cache := make(map[string]bool)
	var rpcErr error

	permitted := expr.Eval(r.ast, func(ident string) bool {
		if rpcErr != nil {
			return false
		}
		if v, ok := cache[ident]; ok {
			return v
		}
		v, err := checker.Check(ctx, t, ident, r.objectType, r.objectID)
		if err != nil {
			rpcErr = fmt.Errorf("relation check %q: %w", ident, err)
			return false
		}
		cache[ident] = v
		return v
	})

	if rpcErr != nil {
		return rpcErr
	}
	if !permitted {
		return errForbidden
	}
	return nil
}

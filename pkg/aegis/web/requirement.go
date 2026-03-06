package web

import (
	"context"
	"fmt"
	"slices"

	"github.com/heliannuuthus/helios/pkg/aegis/utils/relation"
)

// Requirement 声明式鉴权条件。
// Guard 在 Check 阶段依次调用 Enforce，全部通过才放行。
type Requirement interface {
	Enforce(ctx context.Context) error
}

// ---------- Factor ----------

type factorRequirement struct {
	types []string
}

// Factor 要求请求携带 ChallengeToken，且其 type 字段匹配给定值之一。
func Factor(types ...string) Requirement {
	return &factorRequirement{types: types}
}

func (r *factorRequirement) Enforce(ctx context.Context) error {
	tc := GetTokenContext(ctx)
	if tc == nil {
		return ErrUnauthorized
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

// ---------- User ----------

type userRequirement struct{}

// User 要求 token 为 UserAccessToken 且已解密用户身份。
func User() Requirement {
	return &userRequirement{}
}

func (r *userRequirement) Enforce(ctx context.Context) error {
	tc := GetTokenContext(ctx)
	if tc == nil || tc.AccessToken == nil || !tc.AccessToken.Identified() {
		return ErrUnauthorized
	}
	return nil
}

// ---------- Relation（ReBAC 元组） ----------

// RelationBuilder 通过链式调用构建 ReBAC 关系元组 Requirement。
// 实现 Requirement 接口，可直接传给 Guard.Require。
type RelationBuilder struct {
	tuple *relation.Tuple
}

// Relation 创建关系鉴权条件。
//
// 支持两种输入格式：
//
// Zanzibar 元组格式：
//
//	Relation("service:zwei#admin")
//	Relation("service:zwei#admin@user:alice")
//	Relation("service:{path.id}#editor@device:{path.did}")
//
// 纯 relation 标识符（等同于 *:*#relation）：
//
//	Relation("admin")
//
// 返回 RelationBuilder，可通过 .On() / .As() 链式补充 object 和 subject。
// 语法错误会 panic 以快速暴露配置问题。
func Relation(s string) *RelationBuilder {
	t, err := relation.ParseTuple(s)
	if err != nil {
		panic(fmt.Sprintf("invalid relation tuple %q: %v", s, err))
	}
	return &RelationBuilder{tuple: t}
}

// On 指定资源（objectType:objectID），覆盖元组中的 object 部分。
func (b *RelationBuilder) On(objectType, objectID string) *RelationBuilder {
	b.tuple.ObjectType = objectType
	b.tuple.ObjectID = objectID
	return b
}

// As 指定主体（subjectType:subjectID），覆盖 token 推断。
func (b *RelationBuilder) As(subjectType, subjectID string) *RelationBuilder {
	b.tuple.SubjectType = subjectType
	b.tuple.SubjectID = subjectID
	return b
}

func (b *RelationBuilder) Enforce(ctx context.Context) error {
	return enforceRelation(ctx, b.tuple)
}

// Qualify 创建关系鉴权条件（subject 从 token 推断）。
//
//	Qualify("admin", "service:zwei")
//	Qualify("editor", "document:{path.doc_id}")
func Qualify(rel, object string) Requirement {
	if err := relation.ValidRelation(rel); err != nil {
		panic(fmt.Sprintf("Qualify: %v", err))
	}
	objType, objID, err := relation.ParseEntity(object)
	if err != nil {
		panic(fmt.Sprintf("invalid object %q: %v", object, err))
	}
	return &RelationBuilder{tuple: &relation.Tuple{
		Relation:   rel,
		ObjectType: objType,
		ObjectID:   objID,
	}}
}

// QualifySubject 创建关系鉴权条件（完整三元组）。
//
//	QualifySubject("device:{path.did}", "control", "zone:{path.zid}")
//	QualifySubject("user:{body.open_id}", "admin", "service:zwei")
func QualifySubject(subject, rel, object string) Requirement {
	if err := relation.ValidRelation(rel); err != nil {
		panic(fmt.Sprintf("QualifySubject: %v", err))
	}
	subType, subID, err := relation.ParseEntity(subject)
	if err != nil {
		panic(fmt.Sprintf("invalid subject %q: %v", subject, err))
	}
	objType, objID, err := relation.ParseEntity(object)
	if err != nil {
		panic(fmt.Sprintf("invalid object %q: %v", object, err))
	}
	return &RelationBuilder{tuple: &relation.Tuple{
		SubjectType: subType,
		SubjectID:   subID,
		Relation:    rel,
		ObjectType:  objType,
		ObjectID:    objID,
	}}
}

func enforceRelation(ctx context.Context, t *relation.Tuple) error {
	tc := GetTokenContext(ctx)
	if tc == nil || tc.AccessToken == nil {
		return ErrForbidden
	}

	manager := GetTokenManager()
	if manager == nil {
		return ErrForbidden
	}

	rel := t.Relation
	objectType := t.ObjectType
	objectID := t.ObjectID
	subjectType := t.SubjectType
	subjectID := t.SubjectID

	if t.HasBinding() {
		params := GetParams(ctx)
		if params == nil {
			return fmt.Errorf("relation tuple contains bindings but no Params in context")
		}
		rel = ResolveBindings(rel, params)
		objectType = ResolveBindings(objectType, params)
		objectID = ResolveBindings(objectID, params)
		subjectType = ResolveBindings(subjectType, params)
		subjectID = ResolveBindings(subjectID, params)
	}

	results, err := manager.Check(ctx, tc.AccessToken, []string{rel}, objectType, objectID, subjectType, subjectID)
	if err != nil {
		return fmt.Errorf("relation check: %w", err)
	}

	if !results[rel] {
		return ErrForbidden
	}
	return nil
}

// ---------- 布尔组合 ----------

type anyOfRequirement struct {
	reqs []Requirement
}

// AnyOf 任一 Requirement 满足即通过。
func AnyOf(reqs ...Requirement) Requirement {
	if len(reqs) == 0 {
		panic("AnyOf requires at least one requirement")
	}
	return &anyOfRequirement{reqs: reqs}
}

func (r *anyOfRequirement) Enforce(ctx context.Context) error {
	var lastErr error
	for _, req := range r.reqs {
		if err := req.Enforce(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

type allOfRequirement struct {
	reqs []Requirement
}

// AllOf 所有 Requirement 均满足才通过。
func AllOf(reqs ...Requirement) Requirement {
	if len(reqs) == 0 {
		panic("AllOf requires at least one requirement")
	}
	return &allOfRequirement{reqs: reqs}
}

func (r *allOfRequirement) Enforce(ctx context.Context) error {
	for _, req := range r.reqs {
		if err := req.Enforce(ctx); err != nil {
			return err
		}
	}
	return nil
}

type notRequirement struct {
	req Requirement
}

// Not 取反：内部 Requirement 失败则通过，通过则返回 Forbidden。
func Not(req Requirement) Requirement {
	return &notRequirement{req: req}
}

func (r *notRequirement) Enforce(ctx context.Context) error {
	if err := r.req.Enforce(ctx); err != nil {
		return nil
	}
	return ErrForbidden
}

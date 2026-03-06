package relation

import (
	"fmt"
)

// Resolvable 持有未解析的模板 Tuple，由 Resolver 消费。
type Resolvable interface {
	Tuple() (*Tuple, error)
}

// Expression 由 Expr() 创建，持有从 Zanzibar 元组字符串解析出的预解析元组。
type Expression struct {
	tuple *Tuple
	err   error
}

// Expr 解析完整的 Zanzibar 元组表达式，要求包含 #（object + relation 必须存在）。
// 解析错误不会 panic，而是延迟到 Tuple() 时返回 error。
//
//	relation.Expr("service:{path.id}#admin")
//	relation.Expr("service:zwei#admin@user:alice")
func Expr(s string) *Expression {
	t, err := ParseTuple(s)
	if err != nil {
		return &Expression{err: fmt.Errorf("relation.Expr: invalid tuple %q: %w", s, err)}
	}
	return &Expression{tuple: t}
}

func (e *Expression) Tuple() (*Tuple, error) {
	if e.err != nil {
		return nil, e.err
	}
	return e.tuple, nil
}

// Builder 由 Build() 创建，通过链式调用 .On() / .As() 构建元组。
type Builder struct {
	tuple *Tuple
	err   error
}

// Build 从纯 relation 标识符开始构建元组。
// 必须通过 .On() 补全 object 后才能使用。
//
//	relation.Build("admin").On("service", "{path.id}")
func New(rel string) *Builder {
	if err := ValidRelation(rel); err != nil {
		return &Builder{err: fmt.Errorf("relation.Build: %w", err)}
	}
	return &Builder{tuple: &Tuple{Relation: rel}}
}

// On 指定资源（objectType, objectID）。
func (b *Builder) On(objectType, objectID string) *Builder {
	if b.err == nil {
		b.tuple.ObjectType = objectType
		b.tuple.ObjectID = objectID
	}
	return b
}

// As 指定主体（subjectType, subjectID），跳过 token 推断。
func (b *Builder) As(subjectType, subjectID string) *Builder {
	if b.err == nil {
		b.tuple.SubjectType = subjectType
		b.tuple.SubjectID = subjectID
	}
	return b
}

func (b *Builder) Tuple() (*Tuple, error) {
	if b.err != nil {
		return nil, b.err
	}
	if b.tuple.ObjectType == "" || b.tuple.ObjectID == "" {
		return nil, fmt.Errorf("relation.Builder: object not set, call .On() first")
	}
	return b.tuple, nil
}

// Qualify 创建已绑定 object 的 Builder（subject 留空由 Enforce 层推断）。
// object 参数格式为 "type:id"。
//
//	relation.Qualify("admin", "service:{path.id}")
func Qualify(rel, object string) *Builder {
	if err := ValidRelation(rel); err != nil {
		return &Builder{err: fmt.Errorf("relation.Qualify: %w", err)}
	}
	objType, objID, err := ParseEntity(object)
	if err != nil {
		return &Builder{err: fmt.Errorf("relation.Qualify: invalid object %q: %w", object, err)}
	}
	return &Builder{tuple: &Tuple{
		Relation:   rel,
		ObjectType: objType,
		ObjectID:   objID,
	}}
}

// QualifySubject 创建完整三元组的 Builder。
// subject 和 object 参数格式均为 "type:id"。
//
//	relation.QualifySubject("device:{path.did}", "control", "zone:{path.zid}")
func QualifySubject(subject, rel, object string) *Builder {
	if err := ValidRelation(rel); err != nil {
		return &Builder{err: fmt.Errorf("relation.QualifySubject: %w", err)}
	}
	subType, subID, err := ParseEntity(subject)
	if err != nil {
		return &Builder{err: fmt.Errorf("relation.QualifySubject: invalid subject %q: %w", subject, err)}
	}
	objType, objID, err := ParseEntity(object)
	if err != nil {
		return &Builder{err: fmt.Errorf("relation.QualifySubject: invalid object %q: %w", object, err)}
	}
	return &Builder{tuple: &Tuple{
		SubjectType: subType,
		SubjectID:   subID,
		Relation:    rel,
		ObjectType:  objType,
		ObjectID:    objID,
	}}
}

// Package relation 提供 ReBAC 关系元组的数据模型和解析。
//
// 元组格式遵循 Zanzibar 风格：
//
//	[object_type:object_id#]relation[@subject_type:subject_id]
//
// 简写规则：
//
//	"admin"                              → relation=admin, object=*:*
//	"service:zwei#admin"                 → relation=admin, object=service:zwei
//	"service:zwei#admin@user:alice"      → relation=admin, object=service:zwei, subject=user:alice
//	"service:{path.id}#admin@device:{path.d}"  → 带参数绑定的完整元组
package relation

import (
	"fmt"
	"regexp"
	"strings"
)

const Wildcard = "*"

// identPattern 合法的标识符：字母、数字、下划线、连字符、冒号、点、以及 {dotpath} 绑定占位符。
var identPattern = regexp.MustCompile(`^[a-zA-Z0-9_:\-.\{\}]+$`)

// ValidRelation 校验 relation 标识符是否合法。
func ValidRelation(s string) error {
	if s == "" {
		return fmt.Errorf("empty relation")
	}
	if !identPattern.MatchString(s) {
		return fmt.Errorf("invalid relation identifier %q", s)
	}
	return nil
}

// Tuple 表示一个 ReBAC 关系元组。
type Tuple struct {
	SubjectType string // 空 = 从 token 推断
	SubjectID   string // 空 = 从 token 推断
	Relation    string // 单一标识符
	ObjectType  string // 默认 "*"
	ObjectID    string // 默认 "*"
}

// ParseTuple 解析 Zanzibar 风格的关系元组字符串。
//
// 格式：[object_type:object_id#]relation[@subject_type:subject_id]
func ParseTuple(s string) (*Tuple, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty tuple string")
	}

	t := &Tuple{
		ObjectType: Wildcard,
		ObjectID:   Wildcard,
	}

	remaining := s

	// 解析 object 部分（# 前面）
	if idx := strings.Index(remaining, "#"); idx >= 0 {
		objectPart := remaining[:idx]
		remaining = remaining[idx+1:]

		typ, id, err := ParseEntity(objectPart)
		if err != nil {
			return nil, fmt.Errorf("invalid object %q: %w", objectPart, err)
		}
		t.ObjectType = typ
		t.ObjectID = id
	}

	// 解析 subject 部分（@ 后面）
	if idx := strings.Index(remaining, "@"); idx >= 0 {
		relationPart := remaining[:idx]
		subjectPart := remaining[idx+1:]

		typ, id, err := ParseEntity(subjectPart)
		if err != nil {
			return nil, fmt.Errorf("invalid subject %q: %w", subjectPart, err)
		}
		t.SubjectType = typ
		t.SubjectID = id
		remaining = relationPart
	}

	// 剩余部分是 relation
	remaining = strings.TrimSpace(remaining)
	if remaining == "" {
		return nil, fmt.Errorf("missing relation in %q", s)
	}
	if !identPattern.MatchString(remaining) {
		return nil, fmt.Errorf("invalid relation identifier %q: must be alphanumeric with _:-. or binding placeholder", remaining)
	}
	t.Relation = remaining

	return t, nil
}

// ParseEntity 解析 "type:id" 格式的实体引用。
// 按第一个 ":" 分割。
func ParseEntity(s string) (typ, id string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("empty entity")
	}

	idx := strings.Index(s, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("missing ':' in entity %q, expected type:id format", s)
	}

	typ = s[:idx]
	id = s[idx+1:]

	if typ == "" {
		return "", "", fmt.Errorf("empty type in entity %q", s)
	}
	if id == "" {
		return "", "", fmt.Errorf("empty id in entity %q", s)
	}

	return typ, id, nil
}

// HasBinding 检查 tuple 中是否包含 {dotpath} 参数绑定占位符。
func (t *Tuple) HasBinding() bool {
	return containsBinding(t.Relation) ||
		containsBinding(t.ObjectType) || containsBinding(t.ObjectID) ||
		containsBinding(t.SubjectType) || containsBinding(t.SubjectID)
}

var bindingPattern = regexp.MustCompile(`\{[^}]+\}`)

func containsBinding(s string) bool {
	return bindingPattern.MatchString(s)
}

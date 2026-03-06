// Package relation 提供 ReBAC 关系元组的数据模型、解析和构造。
//
// 元组格式遵循 Zanzibar 风格：
//
//	object_type:object_id#relation[@subject_type:subject_id]
//
// object 和 relation 必须存在（# 必须存在），subject 可选（@ 可选）。
//
// 示例：
//
//	"service:zwei#admin"                       → relation=admin, object=service:zwei
//	"service:zwei#admin@user:alice"            → 带显式 subject
//	"service:{path.id}#admin@device:{path.d}" → 带占位符绑定
package relation

import (
	"fmt"
	"regexp"
	"strings"
)

// identPattern 合法的标识符：字母、数字、下划线、连字符、点、以及 {dotpath} 绑定占位符。
var identPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-.\{\}]+$`)

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

// Tuple 表示一个完整的 ReBAC 关系元组（五元组）。
// Relation、ObjectType、ObjectID 必须非空。
// SubjectType、SubjectID 为空时由 Enforce 层从 token 推断。
type Tuple struct {
	SubjectType string
	SubjectID   string
	Relation    string
	ObjectType  string
	ObjectID    string
}

// ParseTuple 解析 Zanzibar 风格的关系元组字符串。
// 要求 # 必须存在（object + relation 必填），@ 后的 subject 可选。
//
// 格式：object_type:object_id#relation[@subject_type:subject_id]
func ParseTuple(s string) (*Tuple, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty tuple string")
	}

	idx := strings.Index(s, "#")
	if idx < 0 {
		return nil, fmt.Errorf("missing '#' in tuple %q: object_type:object_id#relation required", s)
	}

	t := &Tuple{}

	objectPart := s[:idx]
	remaining := s[idx+1:]

	typ, id, err := ParseEntity(objectPart)
	if err != nil {
		return nil, fmt.Errorf("invalid object %q: %w", objectPart, err)
	}
	t.ObjectType = typ
	t.ObjectID = id

	if atIdx := strings.Index(remaining, "@"); atIdx >= 0 {
		relationPart := remaining[:atIdx]
		subjectPart := remaining[atIdx+1:]

		sTyp, sID, err := ParseEntity(subjectPart)
		if err != nil {
			return nil, fmt.Errorf("invalid subject %q: %w", subjectPart, err)
		}
		t.SubjectType = sTyp
		t.SubjectID = sID
		remaining = relationPart
	}

	remaining = strings.TrimSpace(remaining)
	if remaining == "" {
		return nil, fmt.Errorf("missing relation in %q", s)
	}
	if !identPattern.MatchString(remaining) {
		return nil, fmt.Errorf("invalid relation identifier %q: must be alphanumeric with _-. or binding placeholder", remaining)
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


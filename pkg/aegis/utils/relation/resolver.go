package relation

import (
	"fmt"
	"maps"
	"regexp"
	"strings"
)

var placeholderPattern = regexp.MustCompile(`\{[^}]+\}`)

// Resolver 嵌套 map 的 dot-path 查询容器，负责占位符替换。
type Resolver struct {
	data map[string]any
}

// NewResolver 从嵌套 map 构建 Resolver。
func NewResolver(data map[string]any) *Resolver {
	return &Resolver{data: data}
}

// Merge 返回合并了额外 kv 的新 Resolver，不修改原始对象。
func (r *Resolver) Merge(extra map[string]any) *Resolver {
	cp := make(map[string]any, len(r.data)+len(extra))
	maps.Copy(cp, r.data)
	maps.Copy(cp, extra)
	return &Resolver{data: cp}
}

// Resolve 从 Resolvable 取出模板 Tuple，替换占位符，校验完整性。
func (r *Resolver) Resolve(resolvable Resolvable) (*Tuple, error) {
	t, err := resolvable.Tuple()
	if err != nil {
		return nil, err
	}

	return &Tuple{
		SubjectType: r.resolve(t.SubjectType),
		SubjectID:   r.resolve(t.SubjectID),
		Relation:    r.resolve(t.Relation),
		ObjectType:  r.resolve(t.ObjectType),
		ObjectID:    r.resolve(t.ObjectID),
	}, nil
}

func (r *Resolver) get(dotpath string) string {
	if r == nil || len(r.data) == 0 {
		return ""
	}

	parts := strings.Split(dotpath, ".")
	var current any = r.data

	for _, key := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = m[key]
		if !ok {
			return ""
		}
	}

	switch v := current.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func (r *Resolver) resolve(s string) string {
	if r == nil || !placeholderPattern.MatchString(s) {
		return s
	}
	return placeholderPattern.ReplaceAllStringFunc(s, func(match string) string {
		key := match[1 : len(match)-1]
		if val := r.get(key); val != "" {
			return val
		}
		return match
	})
}

package web

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Params 存储请求参数，按来源分 namespace：path / query / body。
// body 支持嵌套结构，通过 dotpath 访问（如 body.user.id）。
type Params struct {
	data map[string]any
}

// NewParams 从 path、query、body 三个来源构建 Params。
// body 允许嵌套 map[string]any（JSON 反序列化结果），path 和 query 为扁平 map。
func NewParams(path, query, body map[string]any) *Params {
	data := make(map[string]any, 3)
	if path != nil {
		data["path"] = path
	}
	if query != nil {
		data["query"] = query
	}
	if body != nil {
		data["body"] = body
	}
	return &Params{data: data}
}

// Get 通过 dotpath 获取参数值，返回字符串形式。
// 支持嵌套访问：path.id / query.page / body.user.name。
// 非 string 类型会用 fmt.Sprint 转换。未找到返回空字符串。
func (p *Params) Get(dotpath string) string {
	if p == nil || len(p.data) == 0 {
		return ""
	}

	parts := strings.Split(dotpath, ".")
	var current any = p.data

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

type paramsKey struct{}

// SetParams 将 Params 注入 context。
func SetParams(ctx context.Context, params *Params) context.Context {
	return context.WithValue(ctx, paramsKey{}, params)
}

// GetParams 从 context 获取 Params。
func GetParams(ctx context.Context) *Params {
	p, _ := ctx.Value(paramsKey{}).(*Params)
	return p
}

var bindingPattern = regexp.MustCompile(`\{([^}]+)\}`)

// ResolveBindings 替换字符串中的 {dotpath} 占位符为实际值。
// 占位符格式：{path.id}、{query.page}、{body.user.id}。
// 如果 params 为 nil 或参数未找到，占位符保持原样。
func ResolveBindings(template string, params *Params) string {
	if params == nil || !bindingPattern.MatchString(template) {
		return template
	}
	return bindingPattern.ReplaceAllStringFunc(template, func(match string) string {
		dotpath := match[1 : len(match)-1]
		if val := params.Get(dotpath); val != "" {
			return val
		}
		return match
	})
}

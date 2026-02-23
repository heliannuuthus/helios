// Package patch 提供符合 JSON Merge Patch (RFC 7396) 语义的部分更新工具。
//
// 核心类型 Optional[T] 支持三态语义：
//   - 零值（字段未出现在 JSON 中）→ 不更新
//   - 显式赋值（字段有具体值）→ 更新为该值
//   - 显式 null（字段值为 null）→ 清空该字段（设为数据库 NULL）
package patch

import (
	"github.com/go-json-experiment/json"
)

// Optional 表示一个可选的 JSON 字段，支持三态语义。
//
// 零值表示"字段未出现"，不会参与更新。
// 通过 JSON 反序列化自动识别 null 和具体值。
type Optional[T any] struct {
	value   T
	present bool // JSON 中是否出现了这个字段
	null    bool // JSON 中是否为 null
}

// Set 创建一个包含具体值的 Optional。
func Set[T any](v T) Optional[T] {
	return Optional[T]{value: v, present: true, null: false}
}

// Null 创建一个表示 null 的 Optional。
func Null[T any]() Optional[T] {
	return Optional[T]{present: true, null: true}
}

// IsPresent 返回字段是否出现在 JSON 中（无论是 null 还是有值）。
func (o Optional[T]) IsPresent() bool {
	return o.present
}

// IsNull 返回字段是否被显式设为 null。
func (o Optional[T]) IsNull() bool {
	return o.present && o.null
}

// HasValue 返回字段是否有具体值（出现且不为 null）。
func (o Optional[T]) HasValue() bool {
	return o.present && !o.null
}

// Value 返回字段的值。仅在 HasValue() 为 true 时有意义。
func (o Optional[T]) Value() T {
	return o.value
}

// UnmarshalJSON 实现 json.Unmarshaler 接口。
// 当 JSON 中出现该字段时（无论是 null 还是有值），present 标记为 true。
// 当字段值为 null 时，null 标记为 true。
func (o *Optional[T]) UnmarshalJSON(data []byte) error {
	o.present = true

	if string(data) == "null" {
		o.null = true
		return nil
	}

	o.null = false
	return json.Unmarshal(data, &o.value)
}

// MarshalJSON 实现 json.Marshaler 接口。
// 当字段未出现时序列化为 null（在外层使用 omitempty 可避免输出）。
// 当字段为 null 时序列化为 null。
// 否则序列化为具体值。
func (o Optional[T]) MarshalJSON() ([]byte, error) {
	if !o.present || o.null {
		return []byte("null"), nil
	}
	return json.Marshal(o.value)
}

// Update 表示一个待应用到数据库的字段更新。
type Update struct {
	Column string
	Value  any
}

// Field 从 Optional 字段构造一个 Update。
// 如果字段未出现在 JSON 中，返回 nil（不参与更新）。
// 如果字段为 null，value 为 nil（GORM 会更新为数据库 NULL）。
// 如果字段有具体值，value 为该值。
func Field[T any](column string, opt Optional[T]) *Update {
	if !opt.IsPresent() {
		return nil
	}
	if opt.IsNull() {
		return &Update{Column: column, Value: nil}
	}
	return &Update{Column: column, Value: opt.Value()}
}

// Collect 从多个 Field 调用的结果中收集非 nil 的更新，构建 GORM Updates 所需的 map。
// 返回的 map 可直接传给 db.Model(...).Updates(map)。
func Collect(fields ...*Update) map[string]any {
	updates := make(map[string]any, len(fields))
	for _, f := range fields {
		if f != nil {
			updates[f.Column] = f.Value
		}
	}
	return updates
}

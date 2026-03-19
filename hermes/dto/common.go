package dto

import (
	"encoding/json"
	"time"

	"github.com/heliannuuthus/helios/pkg/pagination"
)

// ListRequest 通用列表查询请求（游标分页），筛选条件通过 filter=col<op>val 传递
type ListRequest struct {
	pagination.Pagination
	Filter string `form:"filter"`
}

// FormatTime 时间格式化为 ISO8601
func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// ParseJSONStringSlice 将 DB 存的 JSON 字符串解析为 []string，供 handler 构建 Application 响应时使用
func ParseJSONStringSlice(s *string) []string {
	if s == nil || *s == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(*s), &out)
	return out
}

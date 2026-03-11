package dto

import (
	"encoding/json"
	"time"
)

// 响应 DTO：仅包含需要暴露给前端的字段，不包含内部 _id；由 handler 直接构建。

// DomainResponse 域基础信息（名称、描述等）；allowed_idps 不在此暴露，需时调 GET /domains/:id/idps）
type DomainResponse struct {
	DomainID    string  `json:"domain_id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
}

// ServiceResponse 服务（无 _id，仅 access_token 有效期由服务控制）
type ServiceResponse struct {
	ServiceID             string  `json:"service_id"`
	DomainID              string  `json:"domain_id"`
	Name                  string  `json:"name"`
	Description           *string `json:"description,omitempty"`
	LogoURL               *string `json:"logo_url,omitempty"`
	AccessTokenExpiresIn  uint    `json:"access_token_expires_in"`
	CreatedAt             string  `json:"created_at"`
	UpdatedAt             string  `json:"updated_at"`
}

// ApplicationIDPConfigResponse 应用 IDP 配置（无 _id）
type ApplicationIDPConfigResponse struct {
	AppID    string   `json:"app_id"`
	Type     string   `json:"type"`
	Priority int      `json:"priority"`
	Strategy *string  `json:"strategy,omitempty"`
	Delegate *string  `json:"delegate,omitempty"`
	Require  *string  `json:"require,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// ApplicationResponse 应用（无 _id，redirect_uris/allowed_origins 为数组）
type ApplicationResponse struct {
	DomainID                      string   `json:"domain_id"`
	AppID                         string   `json:"app_id"`
	Name                          string   `json:"name"`
	Description                   *string  `json:"description,omitempty"`
	LogoURL                       *string  `json:"logo_url,omitempty"`
	RedirectURIs                  []string `json:"redirect_uris,omitempty"`
	AllowedOrigins                []string `json:"allowed_origins,omitempty"`
	IdTokenExpiresIn              uint     `json:"id_token_expires_in"`
	RefreshTokenExpiresIn         uint     `json:"refresh_token_expires_in"`
	RefreshTokenAbsoluteExpiresIn uint     `json:"refresh_token_absolute_expires_in"`
	CreatedAt                     string   `json:"created_at"`
	UpdatedAt                     string   `json:"updated_at"`
}

// RelationshipResponse 关系（无 _id，expires_at 为 ISO 字符串）
type RelationshipResponse struct {
	ServiceID   string  `json:"service_id"`
	SubjectType string  `json:"subject_type"`
	SubjectID   string  `json:"subject_id"`
	Relation    string  `json:"relation"`
	ObjectType  string  `json:"object_type"`
	ObjectID    string  `json:"object_id"`
	CreatedAt   string  `json:"created_at"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
}

// GroupResponse 组（无 _id）
type GroupResponse struct {
	GroupID     string  `json:"group_id"`
	ServiceID   string  `json:"service_id"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// ApplicationServiceRelationResponse 应用可访问服务关系（无 _id）
type ApplicationServiceRelationResponse struct {
	ServiceID string   `json:"service_id"`
	Relations []string `json:"relations"`
}

// ServiceApplicationRelationResponse 服务侧：已授权应用及授予的权限（无 _id）
type ServiceApplicationRelationResponse struct {
	AppID     string   `json:"app_id"`
	Relations []string `json:"relations"`
}

// GroupMembersResponse 组成员列表
type GroupMembersResponse struct {
	Members []string `json:"members"`
}

// FormatTime 时间格式化为 ISO8601，供 handler 构建响应时使用
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

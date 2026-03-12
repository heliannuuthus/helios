package hermes

import (
	"github.com/heliannuuthus/helios/pkg/patch"
)

// DomainUpdateRequest 更新域请求（JSON Merge Patch 语义，仅 name、description 可编辑）
type DomainUpdateRequest struct {
	Name        patch.Optional[string] `json:"name"`
	Description patch.Optional[string] `json:"description"`
}

// ServiceCreateRequest 创建服务请求（服务仅控制 access_token 有效期）
type ServiceCreateRequest struct {
	ServiceID            string  `json:"service_id" binding:"required"`
	DomainID             string  `json:"domain_id" binding:"required"`
	Name                 string  `json:"name" binding:"required"`
	Description          string  `json:"description" binding:"required"`
	LogoURL              *string `json:"logo_url"`
	AccessTokenExpiresIn *uint   `json:"access_token_expires_in"`
}

// ServiceUpdateRequest 更新服务请求（JSON Merge Patch 语义）
type ServiceUpdateRequest struct {
	Name                 patch.Optional[string] `json:"name"`
	Description          patch.Optional[string] `json:"description"`
	LogoURL              patch.Optional[string] `json:"logo_url"`
	AccessTokenExpiresIn patch.Optional[uint]   `json:"access_token_expires_in"`
}

// ApplicationCreateRequest 创建应用请求（应用控制 id_token、refresh_token 有效期）
// AppID 可选；不填时后端用随机 bigint 经 base62 编码自动生成
type ApplicationCreateRequest struct {
	DomainID                      string   `json:"domain_id" binding:"required"`
	AppID                         string   `json:"app_id"` // 可选，空则自动生成
	Name                          string   `json:"name" binding:"required"`
	Description                   string   `json:"description" binding:"required"`
	AllowedRedirectURIs           []string `json:"allowed_redirect_uris"`
	AllowedOrigins                []string `json:"allowed_origins"`
	AllowedLogoutURIs             []string `json:"allowed_logout_uris"`
	NeedKey                       bool     `json:"need_key"` // 是否需要密钥
	IDTokenExpiresIn              *uint    `json:"id_token_expires_in"`
	RefreshTokenExpiresIn         *uint    `json:"refresh_token_expires_in"`
	RefreshTokenAbsoluteExpiresIn *uint    `json:"refresh_token_absolute_expires_in"`
}

// ApplicationUpdateRequest 更新应用请求（JSON Merge Patch 语义）
type ApplicationUpdateRequest struct {
	Name                          patch.Optional[string]   `json:"name"`
	Description                   patch.Optional[string]   `json:"description"`
	LogoURL                       patch.Optional[string]   `json:"logo_url"`
	AllowedRedirectURIs           patch.Optional[[]string] `json:"allowed_redirect_uris"`
	AllowedOrigins                patch.Optional[[]string] `json:"allowed_origins"`
	AllowedLogoutURIs             patch.Optional[[]string] `json:"allowed_logout_uris"`
	IDTokenExpiresIn              patch.Optional[uint]     `json:"id_token_expires_in"`
	RefreshTokenExpiresIn         patch.Optional[uint]     `json:"refresh_token_expires_in"`
	RefreshTokenAbsoluteExpiresIn patch.Optional[uint]     `json:"refresh_token_absolute_expires_in"`
}

// ApplicationIDPConfigCreateRequest 创建应用 IDP 配置请求（idp 类型必须在应用所属域的 allowed_idps 内）
type ApplicationIDPConfigCreateRequest struct {
	Type     string  `json:"type" binding:"required"` // idp 类型：github/google/user/staff 等
	Priority int     `json:"priority"`
	Strategy *string `json:"strategy,omitempty"` // password,webauthn
	Delegate *string `json:"delegate,omitempty"` // email_otp,totp,webauthn
	Require  *string `json:"require,omitempty"`  // captcha
}

// ApplicationIDPConfigUpdateRequest 更新应用 IDP 配置请求（若修改 type 则必须在域 allowed_idps 内）
type ApplicationIDPConfigUpdateRequest struct {
	Priority patch.Optional[int]    `json:"priority"`
	Strategy patch.Optional[string] `json:"strategy"`
	Delegate patch.Optional[string] `json:"delegate"`
	Require  patch.Optional[string] `json:"require"`
}

// ApplicationServiceRelationRequest 应用服务关系请求（内部用，path 提供 app_id/service_id）
type ApplicationServiceRelationRequest struct {
	AppID     string   `json:"app_id" binding:"required"`
	ServiceID string   `json:"service_id" binding:"required"`
	Relations []string `json:"relations" binding:"required"` // 关系列表，["*"] 表示全部
}

// ServiceAppRelationsRequest 服务-应用关系请求 PUT /services/:service_id/applications/:app_id/relations
type ServiceAppRelationsRequest struct {
	Relations []string `json:"relations" binding:"required"`
}

// RelationshipCreateRequest 创建关系请求
type RelationshipCreateRequest struct {
	ServiceID   string  `json:"service_id" binding:"required"`
	SubjectType string  `json:"subject_type" binding:"required"` // user/group/application
	SubjectID   string  `json:"subject_id" binding:"required"`
	Relation    string  `json:"relation" binding:"required"`
	ObjectType  string  `json:"object_type" binding:"required"`
	ObjectID    string  `json:"object_id" binding:"required"`
	ExpiresAt   *string `json:"expires_at"` // ISO 8601 格式
}

// RelationshipDeleteRequest 删除关系请求
type RelationshipDeleteRequest struct {
	ServiceID   string `json:"service_id" binding:"required"`
	SubjectType string `json:"subject_type" binding:"required"`
	SubjectID   string `json:"subject_id" binding:"required"`
	Relation    string `json:"relation" binding:"required"`
	ObjectType  string `json:"object_type" binding:"required"`
	ObjectID    string `json:"object_id" binding:"required"`
}

// RelationshipUpdateRequest 更新关系请求（JSON Merge Patch 语义）
type RelationshipUpdateRequest struct {
	ServiceID   string                 `json:"service_id" binding:"required"`
	SubjectType string                 `json:"subject_type" binding:"required"`
	SubjectID   string                 `json:"subject_id" binding:"required"`
	Relation    string                 `json:"relation" binding:"required"` // 旧的关系类型（用于定位）
	ObjectType  string                 `json:"object_type" binding:"required"`
	ObjectID    string                 `json:"object_id" binding:"required"`
	NewRelation patch.Optional[string] `json:"new_relation,omitempty"` // 新的关系类型（可选）
	ExpiresAt   patch.Optional[string] `json:"expires_at,omitempty"`   // 新的过期时间（可选，ISO 8601 格式，传 null 表示清除过期时间）
}

// AppServiceRelationshipCreateRequest 在应用服务下创建关系请求（RESTful 风格）
type AppServiceRelationshipCreateRequest struct {
	SubjectType string  `json:"subject_type" binding:"required"` // user/group/application
	SubjectID   string  `json:"subject_id" binding:"required"`
	Relation    string  `json:"relation" binding:"required"`
	ObjectType  string  `json:"object_type" binding:"required"`
	ObjectID    string  `json:"object_id" binding:"required"`
	ExpiresAt   *string `json:"expires_at,omitempty"` // ISO 8601 格式
}

// AppServiceRelationshipUpdateRequest 在应用服务下更新关系请求（JSON Merge Patch 语义）
type AppServiceRelationshipUpdateRequest struct {
	NewRelation patch.Optional[string] `json:"new_relation,omitempty"` // 新的关系类型（可选）
	ExpiresAt   patch.Optional[string] `json:"expires_at,omitempty"`   // 新的过期时间（可选，ISO 8601 格式，传 null 表示清除过期时间）
}

// GroupCreateRequest 创建组请求
type GroupCreateRequest struct {
	GroupID     string  `json:"group_id" binding:"required"`
	ServiceID   string  `json:"service_id" binding:"required"`
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description"`
}

// GroupUpdateRequest 更新组请求（JSON Merge Patch 语义）
type GroupUpdateRequest struct {
	Name        patch.Optional[string] `json:"name"`
	Description patch.Optional[string] `json:"description"`
}

// GroupMemberRequest 组成员请求
type GroupMemberRequest struct {
	GroupID string   `json:"group_id" binding:"required"`
	UserIDs []string `json:"user_ids" binding:"required"`
}

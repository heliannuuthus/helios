package dto

import (
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// ==================== PasswordStoreCredential ====================

// PasswordStoreCredential 密码存储凭证（IDP 身份解析结果）
type PasswordStoreCredential struct {
	OpenID       string
	PasswordHash string
	Nickname     string
	Email        string
	Picture      string
	Status       int8
}

// ==================== Group ====================

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

// GroupListRequest 组列表查询请求（游标分页）
type GroupListRequest struct {
	Cursor string `form:"cursor"`
	Limit  int    `form:"limit" binding:"omitempty,min=1,max=100"`
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

func NewGroupResponse(g *models.Group) GroupResponse {
	return GroupResponse{
		GroupID:     g.GroupID,
		ServiceID:   g.ServiceID,
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   FormatTime(g.CreatedAt),
		UpdatedAt:   FormatTime(g.UpdatedAt),
	}
}

// GroupMembersResponse 组成员列表
type GroupMembersResponse struct {
	Members []string `json:"members"`
}

// ==================== List Requests ====================

// ServiceListRequest 服务列表查询请求（游标分页）
type ServiceListRequest struct {
	DomainID string `form:"domain_id"`
	Cursor   string `form:"cursor"`
	Limit    int    `form:"limit" binding:"omitempty,min=1,max=100"`
}

// ApplicationListRequest 应用列表查询请求（游标分页）
type ApplicationListRequest struct {
	DomainID string `form:"domain_id"`
	Cursor   string `form:"cursor"`
	Limit    int    `form:"limit" binding:"omitempty,min=1,max=100"`
}

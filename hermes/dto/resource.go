package dto

import (
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// ==================== Application-Service Relation ====================

// ApplicationServiceRelationRequest 应用服务关系请求（内部用，path 提供 app_id/service_id）
type ApplicationServiceRelationRequest struct {
	AppID     string   `json:"app_id" binding:"required"`
	ServiceID string   `json:"service_id" binding:"required"`
	Relations []string `json:"relations" binding:"required"`
}

// ServiceAppRelationsRequest 服务-应用关系请求 PUT /services/:service_id/applications/:app_id/relations
type ServiceAppRelationsRequest struct {
	Relations []string `json:"relations" binding:"required"`
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

// ==================== Relationship ====================

// RelationshipCreateRequest 创建关系请求
type RelationshipCreateRequest struct {
	ServiceID   string  `json:"service_id" binding:"required"`
	SubjectType string  `json:"subject_type" binding:"required"`
	SubjectID   string  `json:"subject_id" binding:"required"`
	Relation    string  `json:"relation" binding:"required"`
	ObjectType  string  `json:"object_type" binding:"required"`
	ObjectID    string  `json:"object_id" binding:"required"`
	ExpiresAt   *string `json:"expires_at"`
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
	Relation    string                 `json:"relation" binding:"required"`
	ObjectType  string                 `json:"object_type" binding:"required"`
	ObjectID    string                 `json:"object_id" binding:"required"`
	NewRelation patch.Optional[string] `json:"new_relation,omitempty"`
	ExpiresAt   patch.Optional[string] `json:"expires_at,omitempty"`
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

func NewRelationshipResponse(r *models.Relationship) RelationshipResponse {
	resp := RelationshipResponse{
		ServiceID:   r.ServiceID,
		SubjectType: r.SubjectType,
		SubjectID:   r.SubjectID,
		Relation:    r.Relation,
		ObjectType:  r.ObjectType,
		ObjectID:    r.ObjectID,
		CreatedAt:   FormatTime(r.CreatedAt),
	}
	if r.ExpiresAt != nil {
		s := FormatTime(*r.ExpiresAt)
		resp.ExpiresAt = &s
	}
	return resp
}

// ==================== App-Service Relationship (RESTful) ====================

// AppServiceRelationshipCreateRequest 在应用服务下创建关系请求（RESTful 风格）
type AppServiceRelationshipCreateRequest struct {
	SubjectType string  `json:"subject_type" binding:"required"`
	SubjectID   string  `json:"subject_id" binding:"required"`
	Relation    string  `json:"relation" binding:"required"`
	ObjectType  string  `json:"object_type" binding:"required"`
	ObjectID    string  `json:"object_id" binding:"required"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
}

// AppServiceRelationshipUpdateRequest 在应用服务下更新关系请求（JSON Merge Patch 语义）
type AppServiceRelationshipUpdateRequest struct {
	NewRelation patch.Optional[string] `json:"new_relation,omitempty"`
	ExpiresAt   patch.Optional[string] `json:"expires_at,omitempty"`
}

// AppServiceRelationshipListRequest 应用服务关系列表查询请求（游标分页）
type AppServiceRelationshipListRequest struct {
	SubjectType string `form:"subject_type"`
	SubjectID   string `form:"subject_id"`
	Cursor      string `form:"cursor"`
	Limit       int    `form:"limit" binding:"omitempty,min=1,max=100"`
}

// RelationshipListRequest 通用关系查询请求（游标分页）
type RelationshipListRequest struct {
	ServiceID   string `form:"service_id"`
	SubjectType string `form:"subject_type"`
	SubjectID   string `form:"subject_id"`
	Relation    string `form:"relation"`
	ObjectType  string `form:"object_type"`
	ObjectID    string `form:"object_id"`
	EntityType  string `form:"entity_type"`
	EntityID    string `form:"entity_id"`
	Cursor      string `form:"cursor"`
	Limit       int    `form:"limit" binding:"omitempty,min=1,max=100"`
}

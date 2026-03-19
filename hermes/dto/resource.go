package dto

import (
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// ==================== Relationship ====================

// RelationshipCreateRequest 创建关系请求（service_id 从 URL 路径获取）
type RelationshipCreateRequest struct {
	ServiceID   string  `json:"-"`
	SubjectType string  `json:"subject_type" binding:"required"`
	SubjectID   string  `json:"subject_id" binding:"required"`
	Relation    string  `json:"relation" binding:"required"`
	ObjectType  string  `json:"object_type" binding:"required"`
	ObjectID    string  `json:"object_id" binding:"required"`
	ExpiresAt   *string `json:"expires_at"`
}

// RelationshipDeleteRequest 删除关系请求（service_id 从 URL 路径获取）
type RelationshipDeleteRequest struct {
	ServiceID   string `json:"-"`
	SubjectType string `json:"subject_type" binding:"required"`
	SubjectID   string `json:"subject_id" binding:"required"`
	Relation    string `json:"relation" binding:"required"`
	ObjectType  string `json:"object_type" binding:"required"`
	ObjectID    string `json:"object_id" binding:"required"`
}

// RelationshipUpdateRequest 更新关系请求（JSON Merge Patch 语义，service_id 从 URL 路径获取）
type RelationshipUpdateRequest struct {
	ServiceID   string                 `json:"-"`
	SubjectType string                 `json:"subject_type" binding:"required"`
	SubjectID   string                 `json:"subject_id" binding:"required"`
	Relation    string                 `json:"relation" binding:"required"`
	ObjectType  string                 `json:"object_type" binding:"required"`
	ObjectID    string                 `json:"object_id" binding:"required"`
	NewRelation patch.Optional[string] `json:"new_relation,omitempty"`
	ExpiresAt   patch.Optional[string] `json:"expires_at,omitempty"`
}

// RelationshipResponse 关系响应
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

// ==================== ApplicationServiceRelation ====================

// ApplicationRelationResponse 应用服务关系响应
type ApplicationRelationResponse struct {
	AppID     string `json:"app_id"`
	ServiceID string `json:"service_id"`
	Relation  string `json:"relation"`
	CreatedAt string `json:"created_at"`
}

func NewApplicationRelationResponse(r *models.ApplicationServiceRelation) ApplicationRelationResponse {
	return ApplicationRelationResponse{
		AppID:     r.AppID,
		ServiceID: r.ServiceID,
		Relation:  r.Relation,
		CreatedAt: FormatTime(r.CreatedAt),
	}
}

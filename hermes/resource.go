package hermes

import (
	"context"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/filter"
	"github.com/heliannuuthus/helios/pkg/pagination"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// ==================== Relationship 相关 ====================

// CreateRelationship 创建关系（service_id 由调用方从 URL 路径注入）
func (s *ResourceService) CreateRelationship(ctx context.Context, req *dto.RelationshipCreateRequest) (*models.Relationship, error) {
	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		exp, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("解析过期时间失败: %w", err)
		}
		expiresAt = &exp
	}

	rel := &models.Relationship{
		ServiceID:   req.ServiceID,
		SubjectType: req.SubjectType,
		SubjectID:   req.SubjectID,
		Relation:    req.Relation,
		ObjectType:  req.ObjectType,
		ObjectID:    req.ObjectID,
		ExpiresAt:   expiresAt,
	}
	if err := s.db.WithContext(ctx).Create(rel).Error; err != nil {
		return nil, fmt.Errorf("创建关系失败: %w", err)
	}
	return rel, nil
}

// DeleteRelationship 删除关系
func (s *ResourceService) DeleteRelationship(ctx context.Context, req *dto.RelationshipDeleteRequest) error {
	if err := s.db.WithContext(ctx).Where(
		"service_id = ? AND subject_type = ? AND subject_id = ? AND relation = ? AND object_type = ? AND object_id = ?",
		req.ServiceID, req.SubjectType, req.SubjectID, req.Relation, req.ObjectType, req.ObjectID,
	).Delete(&models.Relationship{}).Error; err != nil {
		return fmt.Errorf("删除关系失败: %w", err)
	}
	return nil
}

var relationshipFilters = filter.Whitelist{
	"subject_type": {filter.Eq},
	"subject_id":   {filter.Eq},
	"relation":     {filter.Eq},
	"object_type":  {filter.Eq},
	"object_id":    {filter.Eq},
}

// ListRelationships 列出服务维度的关系（游标分页）
func (s *ResourceService) ListRelationships(ctx context.Context, serviceID string, req *dto.ListRequest) (*pagination.Items[models.Relationship], error) {
	query := s.db.WithContext(ctx).Model(&models.Relationship{}).Where("service_id = ?", serviceID)
	query = filter.Apply(query, req.Filter, relationshipFilters)
	return pagination.CursorPaginate[models.Relationship](query, req.Pagination)
}

// FindRelationships 按精确条件查询关系（不分页），供内部服务调用
func (s *ResourceService) FindRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]models.Relationship, error) {
	var rels []models.Relationship
	query := s.db.WithContext(ctx).Where("service_id = ? AND subject_type = ? AND subject_id = ?", serviceID, subjectType, subjectID)
	if err := query.Find(&rels).Error; err != nil {
		return nil, fmt.Errorf("查询关系失败: %w", err)
	}
	return rels, nil
}

// UpdateRelationship 更新关系（JSON Merge Patch 语义）
func (s *ResourceService) UpdateRelationship(ctx context.Context, req *dto.RelationshipUpdateRequest) (*models.Relationship, error) {
	var rel models.Relationship
	if err := s.db.WithContext(ctx).Where(
		"service_id = ? AND subject_type = ? AND subject_id = ? AND relation = ? AND object_type = ? AND object_id = ?",
		req.ServiceID, req.SubjectType, req.SubjectID, req.Relation, req.ObjectType, req.ObjectID,
	).First(&rel).Error; err != nil {
		return nil, fmt.Errorf("关系不存在: %w", err)
	}

	updates := patch.Collect(
		patch.Field("relation", req.NewRelation),
	)

	if req.ExpiresAt.IsPresent() {
		if req.ExpiresAt.IsNull() {
			updates["expires_at"] = nil
		} else {
			exp, err := time.Parse(time.RFC3339, req.ExpiresAt.Value())
			if err != nil {
				return nil, fmt.Errorf("解析过期时间失败: %w", err)
			}
			updates["expires_at"] = exp
		}
	}

	if len(updates) == 0 {
		return &rel, nil
	}

	if err := s.db.WithContext(ctx).Model(&rel).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新关系失败: %w", err)
	}

	if err := s.db.WithContext(ctx).First(&rel, rel.ID).Error; err != nil {
		return nil, fmt.Errorf("获取更新后的关系失败: %w", err)
	}
	return &rel, nil
}

// ==================== ApplicationServiceRelation 相关 ====================

var appRelationFilters = filter.Whitelist{
	"service_id": {filter.Eq},
	"relation":   {filter.Eq},
}

// ListApplicationRelations 列出应用的服务关系（游标分页）
func (s *ResourceService) ListApplicationRelations(ctx context.Context, appID string, req *dto.ListRequest) (*pagination.Items[models.ApplicationServiceRelation], error) {
	query := s.db.WithContext(ctx).Model(&models.ApplicationServiceRelation{}).Where("app_id = ?", appID)
	query = filter.Apply(query, req.Filter, appRelationFilters)
	return pagination.CursorPaginate[models.ApplicationServiceRelation](query, req.Pagination)
}

// FindApplicationRelations 查询应用的服务关系（不分页），供 gRPC 内部调用
func (s *ResourceService) FindApplicationRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error) {
	var rels []models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).Find(&rels).Error; err != nil {
		return nil, fmt.Errorf("获取应用服务关系失败: %w", err)
	}
	return rels, nil
}

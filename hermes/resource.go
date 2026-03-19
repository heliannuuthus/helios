package hermes

import (
	"context"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/filter"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/pagination"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// ==================== ApplicationServiceRelation 相关 ====================

// SetApplicationServiceRelations 设置应用可访问的服务和关系
func (s *Service) SetApplicationServiceRelations(ctx context.Context, req *dto.ApplicationServiceRelationRequest) error {
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", req.AppID, req.ServiceID).
		Delete(&models.ApplicationServiceRelation{}).Error; err != nil {
		return fmt.Errorf("删除旧关系失败: %w", err)
	}

	for _, relation := range req.Relations {
		rel := &models.ApplicationServiceRelation{
			AppID:     req.AppID,
			ServiceID: req.ServiceID,
			Relation:  relation,
		}
		if err := s.db.WithContext(ctx).Create(rel).Error; err != nil {
			logger.Errorf("创建应用服务关系失败: %v", err)
		}
	}
	return nil
}

// GetApplicationServiceRelations 获取应用可访问的服务和关系
func (s *Service) GetApplicationServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error) {
	var relations []models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).Find(&relations).Error; err != nil {
		return nil, fmt.Errorf("获取应用服务关系失败: %w", err)
	}
	return relations, nil
}

// GetServiceApplicationRelations 获取服务已授权给哪些应用及授予的权限
func (s *Service) GetServiceApplicationRelations(ctx context.Context, serviceID string) ([]models.ApplicationServiceRelation, error) {
	var relations []models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).Find(&relations).Error; err != nil {
		return nil, fmt.Errorf("获取服务已授权应用失败: %w", err)
	}
	return relations, nil
}

// GetServiceAppRelations 获取某服务授予某应用的关系列表
func (s *Service) GetServiceAppRelations(ctx context.Context, serviceID, appID string) ([]string, error) {
	var relations []models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("service_id = ? AND app_id = ?", serviceID, appID).Find(&relations).Error; err != nil {
		return nil, fmt.Errorf("获取服务应用关系失败: %w", err)
	}
	rels := make([]string, 0, len(relations))
	for i := range relations {
		rels = append(rels, relations[i].Relation)
	}
	return rels, nil
}

// ==================== Relationship 相关 ====================

// CreateRelationship 创建关系
func (s *Service) CreateRelationship(ctx context.Context, req *dto.RelationshipCreateRequest) (*models.Relationship, error) {
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
func (s *Service) DeleteRelationship(ctx context.Context, req *dto.RelationshipDeleteRequest) error {
	if err := s.db.WithContext(ctx).Where(
		"service_id = ? AND subject_type = ? AND subject_id = ? AND relation = ? AND object_type = ? AND object_id = ?",
		req.ServiceID, req.SubjectType, req.SubjectID, req.Relation, req.ObjectType, req.ObjectID,
	).Delete(&models.Relationship{}).Error; err != nil {
		return fmt.Errorf("删除关系失败: %w", err)
	}
	return nil
}

var relationshipFilters = filter.Whitelist{
	"service_id":   {filter.Eq},
	"subject_type": {filter.Eq},
	"subject_id":   {filter.Eq},
}

// ListRelationships 列出关系（游标分页）
func (s *Service) ListRelationships(ctx context.Context, req *dto.ListRequest) (*pagination.Items[models.Relationship], error) {
	query := s.db.WithContext(ctx).Model(&models.Relationship{})
	query = filter.Apply(query, req.Filter, relationshipFilters)
	return pagination.CursorPaginate[models.Relationship](query, req.Pagination)
}

// FindRelationships 按精确条件查询关系（不分页），供内部服务调用
func (s *Service) FindRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]models.Relationship, error) {
	var rels []models.Relationship
	query := s.db.WithContext(ctx).Where("service_id = ? AND subject_type = ? AND subject_id = ?", serviceID, subjectType, subjectID)
	if err := query.Find(&rels).Error; err != nil {
		return nil, fmt.Errorf("查询关系失败: %w", err)
	}
	return rels, nil
}

// UpdateRelationship 更新关系（JSON Merge Patch 语义）
func (s *Service) UpdateRelationship(ctx context.Context, req *dto.RelationshipUpdateRequest) (*models.Relationship, error) {
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

// ==================== App Service Relationship 相关（RESTful 风格）====================

var appServiceRelationshipFilters = filter.Whitelist{
	"subject_type": {filter.Eq},
	"subject_id":   {filter.Eq},
}

// verifyAppServiceAccess 验证应用是否有权访问该服务
func (s *Service) verifyAppServiceAccess(ctx context.Context, appID, serviceID string) error {
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return fmt.Errorf("应用不存在: %w", err)
	}
	var svc models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&svc).Error; err != nil {
		return fmt.Errorf("服务不存在: %w", err)
	}
	var relation models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", appID, serviceID).First(&relation).Error; err != nil {
		return fmt.Errorf("应用无权访问该服务")
	}
	return nil
}

// ListAppServiceRelationships 列出应用服务下的关系（游标分页）
func (s *Service) ListAppServiceRelationships(ctx context.Context, appID, serviceID string, req *dto.ListRequest) (*pagination.Items[models.Relationship], error) {
	if err := s.verifyAppServiceAccess(ctx, appID, serviceID); err != nil {
		return nil, err
	}
	query := s.db.WithContext(ctx).Model(&models.Relationship{}).Where("service_id = ?", serviceID)
	query = filter.Apply(query, req.Filter, appServiceRelationshipFilters)
	return pagination.CursorPaginate[models.Relationship](query, req.Pagination)
}

// CreateAppServiceRelationship 在应用服务下创建关系
func (s *Service) CreateAppServiceRelationship(ctx context.Context, appID, serviceID string, req *dto.AppServiceRelationshipCreateRequest) (*models.Relationship, error) {
	if err := s.verifyAppServiceAccess(ctx, appID, serviceID); err != nil {
		return nil, err
	}

	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		exp, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("解析过期时间失败: %w", err)
		}
		expiresAt = &exp
	}

	rel := &models.Relationship{
		ServiceID:   serviceID,
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

// UpdateAppServiceRelationship 在应用服务下更新关系（JSON Merge Patch 语义）
func (s *Service) UpdateAppServiceRelationship(ctx context.Context, appID, serviceID string, relationshipID uint, req *dto.AppServiceRelationshipUpdateRequest) (*models.Relationship, error) {
	if err := s.verifyAppServiceAccess(ctx, appID, serviceID); err != nil {
		return nil, err
	}

	var rel models.Relationship
	if err := s.db.WithContext(ctx).Where("_id = ? AND service_id = ?", relationshipID, serviceID).First(&rel).Error; err != nil {
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

// DeleteAppServiceRelationship 在应用服务下删除关系
func (s *Service) DeleteAppServiceRelationship(ctx context.Context, appID, serviceID string, relationshipID uint) error {
	if err := s.verifyAppServiceAccess(ctx, appID, serviceID); err != nil {
		return err
	}
	if err := s.db.WithContext(ctx).Where("_id = ? AND service_id = ?", relationshipID, serviceID).Delete(&models.Relationship{}).Error; err != nil {
		return fmt.Errorf("删除关系失败: %w", err)
	}
	return nil
}

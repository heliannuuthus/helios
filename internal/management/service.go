package management

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/internal/management/models"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/database"
	"github.com/heliannuuthus/helios/pkg/kms"
	"github.com/heliannuuthus/helios/pkg/logger"
	"gorm.io/gorm"
)

// Service 管理服务
type Service struct {
	db *gorm.DB
}

// NewService 创建管理服务
func NewService() *Service {
	return &Service{
		db: database.GetAuth(),
	}
}

// ==================== Domain 相关 ====================

// CreateDomain 创建域
func (s *Service) CreateDomain(ctx context.Context, req *DomainCreateRequest) (*models.Domain, error) {
	domain := &models.Domain{
		DomainID:    req.DomainID,
		Name:        req.Name,
		Description: req.Description,
		Status:      0,
	}

	if err := s.db.WithContext(ctx).Create(domain).Error; err != nil {
		return nil, fmt.Errorf("创建域失败: %w", err)
	}

	return domain, nil
}

// GetDomain 获取域
func (s *Service) GetDomain(ctx context.Context, domainID string) (*models.Domain, error) {
	var domain models.Domain
	if err := s.db.WithContext(ctx).Where("domain_id = ?", domainID).First(&domain).Error; err != nil {
		return nil, fmt.Errorf("获取域失败: %w", err)
	}
	return &domain, nil
}

// ListDomains 列出所有域
func (s *Service) ListDomains(ctx context.Context) ([]models.Domain, error) {
	var domains []models.Domain
	if err := s.db.WithContext(ctx).Find(&domains).Error; err != nil {
		return nil, fmt.Errorf("列出域失败: %w", err)
	}
	return domains, nil
}

// UpdateDomain 更新域
func (s *Service) UpdateDomain(ctx context.Context, domainID string, req *DomainUpdateRequest) error {
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Status != nil {
		updates["status"] = *req.Status
	}

	if len(updates) == 0 {
		return nil
	}

	if err := s.db.WithContext(ctx).Model(&models.Domain{}).
		Where("domain_id = ?", domainID).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新域失败: %w", err)
	}

	return nil
}

// ==================== Service 相关 ====================

// generateServiceKey 生成服务密钥并加密
func (s *Service) generateServiceKey(domainID string) (string, error) {
	// 生成 AES-256 密钥
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("生成密钥失败: %w", err)
	}

	// 获取域加密密钥
	domainEncryptKey, err := config.GetDomainEncryptKey(domainID)
	if err != nil {
		return "", fmt.Errorf("获取域加密密钥失败: %w", err)
	}

	// 用域密钥加密服务密钥（AES-GCM，AAD=serviceID）
	encryptedKey, err := kms.EncryptAESGCM(key, domainEncryptKey, domainID)
	if err != nil {
		return "", fmt.Errorf("加密服务密钥失败: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// CreateService 创建服务
func (s *Service) CreateService(ctx context.Context, req *ServiceCreateRequest) (*models.Service, error) {
	// 生成并加密服务密钥
	encryptedKey, err := s.generateServiceKey(req.DomainID)
	if err != nil {
		return nil, err
	}

	service := &models.Service{
		ServiceID:             req.ServiceID,
		DomainID:              req.DomainID,
		Name:                  req.Name,
		Description:           req.Description,
		EncryptedKey:          encryptedKey,
		AccessTokenExpiresIn:  7200,
		RefreshTokenExpiresIn: 604800,
		Status:                0,
	}

	if req.AccessTokenExpiresIn != nil {
		service.AccessTokenExpiresIn = *req.AccessTokenExpiresIn
	}
	if req.RefreshTokenExpiresIn != nil {
		service.RefreshTokenExpiresIn = *req.RefreshTokenExpiresIn
	}

	if err := s.db.WithContext(ctx).Create(service).Error; err != nil {
		return nil, fmt.Errorf("创建服务失败: %w", err)
	}

	return service, nil
}

// GetService 获取服务
func (s *Service) GetService(ctx context.Context, serviceID string) (*models.Service, error) {
	var service models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&service).Error; err != nil {
		return nil, fmt.Errorf("获取服务失败: %w", err)
	}
	return &service, nil
}

// ListServices 列出所有服务
func (s *Service) ListServices(ctx context.Context, domainID string) ([]models.Service, error) {
	var services []models.Service
	query := s.db.WithContext(ctx)
	if domainID != "" {
		query = query.Where("domain_id = ?", domainID)
	}
	if err := query.Find(&services).Error; err != nil {
		return nil, fmt.Errorf("列出服务失败: %w", err)
	}
	return services, nil
}

// UpdateService 更新服务
func (s *Service) UpdateService(ctx context.Context, serviceID string, req *ServiceUpdateRequest) error {
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.AccessTokenExpiresIn != nil {
		updates["access_token_expires_in"] = *req.AccessTokenExpiresIn
	}
	if req.RefreshTokenExpiresIn != nil {
		updates["refresh_token_expires_in"] = *req.RefreshTokenExpiresIn
	}
	if req.Status != nil {
		updates["status"] = *req.Status
	}

	if len(updates) == 0 {
		return nil
	}

	if err := s.db.WithContext(ctx).Model(&models.Service{}).
		Where("service_id = ?", serviceID).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新服务失败: %w", err)
	}

	return nil
}

// ==================== Application 相关 ====================

// generateApplicationKey 生成应用密钥并加密
func (s *Service) generateApplicationKey(domainID, appID string) (string, error) {
	// 生成 AES-256 密钥
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("生成密钥失败: %w", err)
	}

	// 获取域加密密钥
	domainEncryptKey, err := config.GetDomainEncryptKey(domainID)
	if err != nil {
		return "", fmt.Errorf("获取域加密密钥失败: %w", err)
	}

	// 用域密钥加密应用密钥（AES-GCM，AAD=appID）
	encryptedKey, err := kms.EncryptAESGCM(key, domainEncryptKey, appID)
	if err != nil {
		return "", fmt.Errorf("加密应用密钥失败: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// CreateApplication 创建应用
func (s *Service) CreateApplication(ctx context.Context, req *ApplicationCreateRequest) (*models.Application, error) {
	var redirectURIs *string
	if len(req.RedirectURIs) > 0 {
		urisJSON, _ := json.Marshal(req.RedirectURIs)
		urisStr := string(urisJSON)
		redirectURIs = &urisStr
	}

	var encryptedKey *string
	if req.NeedKey {
		key, err := s.generateApplicationKey(req.DomainID, req.AppID)
		if err != nil {
			return nil, err
		}
		encryptedKey = &key
	}

	app := &models.Application{
		DomainID:     req.DomainID,
		AppID:        req.AppID,
		Name:         req.Name,
		RedirectURIs: redirectURIs,
		EncryptedKey: encryptedKey,
	}

	if err := s.db.WithContext(ctx).Create(app).Error; err != nil {
		return nil, fmt.Errorf("创建应用失败: %w", err)
	}

	return app, nil
}

// GetApplication 获取应用
func (s *Service) GetApplication(ctx context.Context, appID string) (*models.Application, error) {
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("获取应用失败: %w", err)
	}
	return &app, nil
}

// ListApplications 列出所有应用
func (s *Service) ListApplications(ctx context.Context, domainID string) ([]models.Application, error) {
	var apps []models.Application
	query := s.db.WithContext(ctx)
	if domainID != "" {
		query = query.Where("domain_id = ?", domainID)
	}
	if err := query.Find(&apps).Error; err != nil {
		return nil, fmt.Errorf("列出应用失败: %w", err)
	}
	return apps, nil
}

// UpdateApplication 更新应用
func (s *Service) UpdateApplication(ctx context.Context, appID string, req *ApplicationUpdateRequest) error {
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if len(req.RedirectURIs) > 0 {
		urisJSON, _ := json.Marshal(req.RedirectURIs)
		updates["redirect_uris"] = string(urisJSON)
	}

	if len(updates) == 0 {
		return nil
	}

	if err := s.db.WithContext(ctx).Model(&models.Application{}).
		Where("app_id = ?", appID).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新应用失败: %w", err)
	}

	return nil
}

// SetApplicationServiceRelations 设置应用可访问的服务和关系
func (s *Service) SetApplicationServiceRelations(ctx context.Context, req *ApplicationServiceRelationRequest) error {
	// 先删除旧的关系
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", req.AppID, req.ServiceID).
		Delete(&models.ApplicationServiceRelation{}).Error; err != nil {
		return fmt.Errorf("删除旧关系失败: %w", err)
	}

	// 插入新关系
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

// ==================== Relationship 相关 ====================

// CreateRelationship 创建关系
func (s *Service) CreateRelationship(ctx context.Context, req *RelationshipCreateRequest) (*models.Relationship, error) {
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
func (s *Service) DeleteRelationship(ctx context.Context, req *RelationshipDeleteRequest) error {
	if err := s.db.WithContext(ctx).Where(
		"service_id = ? AND subject_type = ? AND subject_id = ? AND relation = ? AND object_type = ? AND object_id = ?",
		req.ServiceID, req.SubjectType, req.SubjectID, req.Relation, req.ObjectType, req.ObjectID,
	).Delete(&models.Relationship{}).Error; err != nil {
		return fmt.Errorf("删除关系失败: %w", err)
	}

	return nil
}

// ListRelationships 列出关系
func (s *Service) ListRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]models.Relationship, error) {
	var rels []models.Relationship
	query := s.db.WithContext(ctx).Where("service_id = ?", serviceID)
	if subjectType != "" {
		query = query.Where("subject_type = ?", subjectType)
	}
	if subjectID != "" {
		query = query.Where("subject_id = ?", subjectID)
	}
	if err := query.Find(&rels).Error; err != nil {
		return nil, fmt.Errorf("列出关系失败: %w", err)
	}
	return rels, nil
}

// ==================== Group 相关 ====================

// CreateGroup 创建组
func (s *Service) CreateGroup(ctx context.Context, req *GroupCreateRequest) (*models.Group, error) {
	group := &models.Group{
		GroupID:     req.GroupID,
		Name:        req.Name,
		Description: req.Description,
	}

	if err := s.db.WithContext(ctx).Create(group).Error; err != nil {
		return nil, fmt.Errorf("创建组失败: %w", err)
	}

	return group, nil
}

// GetGroup 获取组
func (s *Service) GetGroup(ctx context.Context, groupID string) (*models.Group, error) {
	var group models.Group
	if err := s.db.WithContext(ctx).Where("group_id = ?", groupID).First(&group).Error; err != nil {
		return nil, fmt.Errorf("获取组失败: %w", err)
	}
	return &group, nil
}

// ListGroups 列出所有组
func (s *Service) ListGroups(ctx context.Context) ([]models.Group, error) {
	var groups []models.Group
	if err := s.db.WithContext(ctx).Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("列出组失败: %w", err)
	}
	return groups, nil
}

// UpdateGroup 更新组
func (s *Service) UpdateGroup(ctx context.Context, groupID string, req *GroupUpdateRequest) error {
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}

	if len(updates) == 0 {
		return nil
	}

	if err := s.db.WithContext(ctx).Model(&models.Group{}).
		Where("group_id = ?", groupID).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新组失败: %w", err)
	}

	return nil
}

// SetGroupMembers 设置组成员（通过关系表）
// 注意：组成员关系使用 service_id = "system" 表示系统级别关系
func (s *Service) SetGroupMembers(ctx context.Context, req *GroupMemberRequest) error {
	// 先删除旧的成员关系
	if err := s.db.WithContext(ctx).Where("service_id = ? AND object_type = ? AND object_id = ? AND relation = ?", "system", "group", req.GroupID, "member").
		Delete(&models.Relationship{}).Error; err != nil {
		return fmt.Errorf("删除旧成员关系失败: %w", err)
	}

	// 插入新成员关系
	for _, userID := range req.UserIDs {
		rel := &models.Relationship{
			ServiceID:   "system", // 系统级别关系
			SubjectType: "user",
			SubjectID:   userID,
			Relation:    "member",
			ObjectType:  "group",
			ObjectID:    req.GroupID,
		}
		if err := s.db.WithContext(ctx).Create(rel).Error; err != nil {
			logger.Errorf("创建组成员关系失败: %v", err)
		}
	}

	return nil
}

// GetGroupMembers 获取组成员
func (s *Service) GetGroupMembers(ctx context.Context, groupID string) ([]string, error) {
	var rels []models.Relationship
	if err := s.db.WithContext(ctx).Where("service_id = ? AND object_type = ? AND object_id = ? AND relation = ?", "system", "group", groupID, "member").
		Find(&rels).Error; err != nil {
		return nil, fmt.Errorf("获取组成员失败: %w", err)
	}

	userIDs := make([]string, 0, len(rels))
	for _, rel := range rels {
		if rel.SubjectType == "user" {
			userIDs = append(userIDs, rel.SubjectID)
		}
	}

	return userIDs, nil
}

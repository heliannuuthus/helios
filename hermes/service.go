package hermes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-json-experiment/json"
	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/hermes/config"
	"github.com/heliannuuthus/helios/hermes/models"
	cryptoutil "github.com/heliannuuthus/helios/pkg/crypto"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// Service 管理服务
type Service struct {
	db *gorm.DB
}

// generateEncryptedKey 生成 48 字节 seed（16-byte salt + 32-byte key）并用数据库加密密钥加密
// aad 用于 AES-GCM 加密的附加认证数据
func generateEncryptedKey(aad string) (string, error) {
	key := make([]byte, 48)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("生成密钥失败: %w", err)
	}

	// 获取数据库加密密钥（原始字节）
	domainEncryptKey, err := config.GetDBEncKeyRaw()
	if err != nil {
		return "", fmt.Errorf("获取数据库加密密钥失败: %w", err)
	}

	// 用域密钥加密密钥（AES-GCM，AAD=aad）
	encryptedKey, err := cryptoutil.EncryptAESGCM(key, domainEncryptKey, aad)
	if err != nil {
		return "", fmt.Errorf("加密密钥失败: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// NewService 创建管理服务
func NewService(db *gorm.DB) *Service {
	return &Service{
		db: db,
	}
}

// ==================== Domain 相关 ====================

// GetDomain 获取域（从配置读取，不含密钥）
func (*Service) GetDomain(ctx context.Context, domainID string) (*models.Domain, error) {
	// 检查域配置是否存在
	signKeys := config.GetDomainSignKeys(domainID)
	if len(signKeys) == 0 {
		return nil, fmt.Errorf("域 %s 配置不存在", domainID)
	}

	name := config.Cfg().GetString("aegis.domains" + "." + domainID + ".name")
	if name == "" {
		name = domainID
	}

	var description *string
	if desc := config.Cfg().GetString("aegis.domains" + "." + domainID + ".description"); desc != "" {
		description = &desc
	}

	domain := &models.Domain{
		DomainID:    domainID,
		Name:        name,
		Description: description,
	}

	return domain, nil
}

// GetDomainWithKey 获取域（含签名密钥）
func (s *Service) GetDomainWithKey(ctx context.Context, domainID string) (*models.DomainWithKey, error) {
	domain, err := s.GetDomain(ctx, domainID)
	if err != nil {
		return nil, err
	}

	// 获取所有签名密钥（第一把是主密钥，其余是旧密钥）
	signKeys, err := config.GetDomainSignKeysBytes(domainID)
	if err != nil {
		return nil, fmt.Errorf("获取域签名密钥失败: %w", err)
	}

	return &models.DomainWithKey{
		Domain: *domain,
		Main:   signKeys[0], // 第一把是主密钥
		Keys:   signKeys,    // 所有密钥（用于验证）
	}, nil
}

// ListDomains 列出所有域（从配置读取）
func (*Service) ListDomains(ctx context.Context) ([]models.Domain, error) {
	// 从配置读取 auth.domains 下的所有域
	domainsMap := config.Cfg().GetStringMap("aegis.domains")
	if len(domainsMap) == 0 {
		return nil, fmt.Errorf("aegis.domains 配置为空")
	}

	domains := make([]models.Domain, 0, len(domainsMap))
	for domainID := range domainsMap {
		name := config.Cfg().GetString("aegis.domains" + "." + domainID + ".name")
		if name == "" {
			name = domainID
		}

		var description *string
		if desc := config.Cfg().GetString("aegis.domains" + "." + domainID + ".description"); desc != "" {
			description = &desc
		}

		domain := models.Domain{
			DomainID:    domainID,
			Name:        name,
			Description: description,
		}
		domains = append(domains, domain)
	}

	return domains, nil
}

// ==================== Service 相关 ====================

// CreateService 创建服务
func (s *Service) CreateService(ctx context.Context, req *ServiceCreateRequest) (*models.Service, error) {
	service := &models.Service{
		ServiceID:             req.ServiceID,
		DomainID:              req.DomainID,
		Name:                  req.Name,
		Description:           req.Description,
		AccessTokenExpiresIn:  7200,
		RefreshTokenExpiresIn: 604800,
	}

	if req.AccessTokenExpiresIn != nil {
		service.AccessTokenExpiresIn = *req.AccessTokenExpiresIn
	}
	if req.RefreshTokenExpiresIn != nil {
		service.RefreshTokenExpiresIn = *req.RefreshTokenExpiresIn
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(service).Error; err != nil {
			return fmt.Errorf("创建服务失败: %w", err)
		}
		return s.createKey(tx, models.KeyOwnerService, req.ServiceID)
	})
	if err != nil {
		return nil, err
	}

	return service, nil
}

// GetService 获取服务（不含密钥）
func (s *Service) GetService(ctx context.Context, serviceID string) (*models.Service, error) {
	var service models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&service).Error; err != nil {
		return nil, fmt.Errorf("获取服务失败: %w", err)
	}
	return &service, nil
}

// GetServiceWithKey 获取服务（含解密密钥）
func (s *Service) GetServiceWithKey(ctx context.Context, serviceID string) (*models.ServiceWithKey, error) {
	service, err := s.GetService(ctx, serviceID)
	if err != nil {
		return nil, err
	}

	keys, err := s.GetServiceKeys(ctx, serviceID)
	if err != nil {
		return nil, err
	}

	result := &models.ServiceWithKey{Service: *service, Keys: keys}
	if len(keys) > 0 {
		result.Main = keys[0]
	}
	return result, nil
}

// ListServices 列出所有服务
func (s *Service) ListServices(ctx context.Context, req *ServiceListRequest) (*CursorPage[models.Service], error) {
	query := s.db.WithContext(ctx).Model(&models.Service{})
	if req.DomainID != "" {
		query = query.Where("domain_id = ?", req.DomainID)
	}
	return CursorPaginate[models.Service](query, req.Cursor, req.Limit)
}

// UpdateService 更新服务（JSON Merge Patch 语义）
func (s *Service) UpdateService(ctx context.Context, serviceID string, req *ServiceUpdateRequest) error {
	updates := patch.Collect(
		patch.Field("name", req.Name),
		patch.Field("description", req.Description),
		patch.Field("access_token_expires_in", req.AccessTokenExpiresIn),
		patch.Field("refresh_token_expires_in", req.RefreshTokenExpiresIn),
	)

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

// CreateApplication 创建应用
func (s *Service) CreateApplication(ctx context.Context, req *ApplicationCreateRequest) (*models.Application, error) {
	var redirectURIs *string
	if len(req.RedirectURIs) > 0 {
		urisJSON, err := json.Marshal(req.RedirectURIs)
		if err != nil {
			return nil, fmt.Errorf("marshal redirect uris: %w", err)
		}
		urisStr := string(urisJSON)
		redirectURIs = &urisStr
	}

	app := &models.Application{
		DomainID:     req.DomainID,
		AppID:        req.AppID,
		Name:         req.Name,
		RedirectURIs: redirectURIs,
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(app).Error; err != nil {
			return fmt.Errorf("创建应用失败: %w", err)
		}
		if req.NeedKey {
			if err := s.createKey(tx, models.KeyOwnerApplication, req.AppID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return app, nil
}

// GetApplication 获取应用（不含密钥）
func (s *Service) GetApplication(ctx context.Context, appID string) (*models.Application, error) {
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("获取应用失败: %w", err)
	}
	return &app, nil
}

// GetApplicationWithKey 获取应用（含解密密钥）
func (s *Service) GetApplicationWithKey(ctx context.Context, appID string) (*models.ApplicationWithKey, error) {
	app, err := s.GetApplication(ctx, appID)
	if err != nil {
		return nil, err
	}

	keys, err := s.GetApplicationKeys(ctx, appID)
	if err != nil {
		return nil, err
	}

	result := &models.ApplicationWithKey{Application: *app, Keys: keys}
	if len(keys) > 0 {
		result.Main = keys[0]
	}
	return result, nil
}

// ListApplications 列出所有应用
func (s *Service) ListApplications(ctx context.Context, req *ApplicationListRequest) (*CursorPage[models.Application], error) {
	query := s.db.WithContext(ctx).Model(&models.Application{})
	if req.DomainID != "" {
		query = query.Where("domain_id = ?", req.DomainID)
	}
	return CursorPaginate[models.Application](query, req.Cursor, req.Limit)
}

// UpdateApplication 更新应用（JSON Merge Patch 语义）
func (s *Service) UpdateApplication(ctx context.Context, appID string, req *ApplicationUpdateRequest) error {
	updates := patch.Collect(
		patch.Field("name", req.Name),
	)

	// redirect_uris 需要序列化为 JSON 字符串
	if req.RedirectURIs.IsPresent() {
		if req.RedirectURIs.IsNull() {
			updates["redirect_uris"] = nil
		} else {
			urisJSON, err := json.Marshal(req.RedirectURIs.Value())
			if err != nil {
				return fmt.Errorf("序列化 redirect_uris 失败: %w", err)
			}
			updates["redirect_uris"] = string(urisJSON)
		}
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

// ListRelationships 通用关系查询（游标分页）
func (s *Service) ListRelationships(ctx context.Context, req *RelationshipListRequest) (*CursorPage[models.Relationship], error) {
	query := s.db.WithContext(ctx).Model(&models.Relationship{})

	if req.ServiceID != "" {
		query = query.Where("service_id = ?", req.ServiceID)
	}
	if req.SubjectType != "" {
		query = query.Where("subject_type = ?", req.SubjectType)
	}
	if req.SubjectID != "" {
		query = query.Where("subject_id = ?", req.SubjectID)
	}
	if req.Relation != "" {
		query = query.Where("relation = ?", req.Relation)
	}
	if req.ObjectType != "" {
		query = query.Where("object_type = ?", req.ObjectType)
	}
	if req.ObjectID != "" {
		query = query.Where("object_id = ?", req.ObjectID)
	}
	if req.EntityType != "" {
		query = query.Where("(subject_type = ? OR object_type = ?)", req.EntityType, req.EntityType)
	}
	if req.EntityID != "" {
		query = query.Where("(subject_id = ? OR object_id = ?)", req.EntityID, req.EntityID)
	}

	return CursorPaginate[models.Relationship](query, req.Cursor, req.Limit)
}

// UpdateRelationship 更新关系（JSON Merge Patch 语义）
func (s *Service) UpdateRelationship(ctx context.Context, req *RelationshipUpdateRequest) (*models.Relationship, error) {
	// 1. 查找关系
	var rel models.Relationship
	if err := s.db.WithContext(ctx).Where(
		"service_id = ? AND subject_type = ? AND subject_id = ? AND relation = ? AND object_type = ? AND object_id = ?",
		req.ServiceID, req.SubjectType, req.SubjectID, req.Relation, req.ObjectType, req.ObjectID,
	).First(&rel).Error; err != nil {
		return nil, fmt.Errorf("关系不存在: %w", err)
	}

	// 2. 构建更新字段
	updates := patch.Collect(
		patch.Field("relation", req.NewRelation),
	)

	// 过期时间需要特殊处理：null → 清除，有值 → 解析时间
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

	// 3. 如果没有要更新的字段，直接返回
	if len(updates) == 0 {
		return &rel, nil
	}

	// 4. 更新关系
	if err := s.db.WithContext(ctx).Model(&rel).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新关系失败: %w", err)
	}

	// 5. 重新查询返回更新后的关系
	if err := s.db.WithContext(ctx).First(&rel, rel.ID).Error; err != nil {
		return nil, fmt.Errorf("获取更新后的关系失败: %w", err)
	}

	return &rel, nil
}

// ==================== App Service Relationship 相关（RESTful 风格）====================

// ListAppServiceRelationships 列出应用服务下的关系
func (s *Service) ListAppServiceRelationships(ctx context.Context, appID, serviceID string, req *AppServiceRelationshipListRequest) (*CursorPage[models.Relationship], error) {
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("应用不存在: %w", err)
	}

	var service models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&service).Error; err != nil {
		return nil, fmt.Errorf("服务不存在: %w", err)
	}

	var relation models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", appID, serviceID).First(&relation).Error; err != nil {
		return nil, fmt.Errorf("应用无权访问该服务")
	}

	query := s.db.WithContext(ctx).Model(&models.Relationship{}).Where("service_id = ?", serviceID)
	if req.SubjectType != "" {
		query = query.Where("subject_type = ?", req.SubjectType)
	}
	if req.SubjectID != "" {
		query = query.Where("subject_id = ?", req.SubjectID)
	}
	return CursorPaginate[models.Relationship](query, req.Cursor, req.Limit)
}

// CreateAppServiceRelationship 在应用服务下创建关系
func (s *Service) CreateAppServiceRelationship(ctx context.Context, appID, serviceID string, req *AppServiceRelationshipCreateRequest) (*models.Relationship, error) {
	// 1. 验证应用和服务是否存在
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("应用不存在: %w", err)
	}

	var service models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&service).Error; err != nil {
		return nil, fmt.Errorf("服务不存在: %w", err)
	}

	// 2. 验证应用是否有权限访问该服务
	var relation models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", appID, serviceID).First(&relation).Error; err != nil {
		return nil, fmt.Errorf("应用无权访问该服务")
	}

	// 3. 解析过期时间
	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		exp, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("解析过期时间失败: %w", err)
		}
		expiresAt = &exp
	}

	// 4. 创建关系
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
func (s *Service) UpdateAppServiceRelationship(ctx context.Context, appID, serviceID string, relationshipID uint, req *AppServiceRelationshipUpdateRequest) (*models.Relationship, error) {
	// 1. 验证应用和服务是否存在
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return nil, fmt.Errorf("应用不存在: %w", err)
	}

	var service models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&service).Error; err != nil {
		return nil, fmt.Errorf("服务不存在: %w", err)
	}

	// 2. 验证应用是否有权限访问该服务
	var relation models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", appID, serviceID).First(&relation).Error; err != nil {
		return nil, fmt.Errorf("应用无权访问该服务")
	}

	// 3. 查找关系（通过 ID 和 service_id）
	var rel models.Relationship
	if err := s.db.WithContext(ctx).Where("_id = ? AND service_id = ?", relationshipID, serviceID).First(&rel).Error; err != nil {
		return nil, fmt.Errorf("关系不存在: %w", err)
	}

	// 4. 构建更新字段
	updates := patch.Collect(
		patch.Field("relation", req.NewRelation),
	)

	// 过期时间需要特殊处理：null → 清除，有值 → 解析时间
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

	// 5. 如果没有要更新的字段，直接返回
	if len(updates) == 0 {
		return &rel, nil
	}

	// 6. 更新关系
	if err := s.db.WithContext(ctx).Model(&rel).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新关系失败: %w", err)
	}

	// 7. 重新查询返回更新后的关系
	if err := s.db.WithContext(ctx).First(&rel, rel.ID).Error; err != nil {
		return nil, fmt.Errorf("获取更新后的关系失败: %w", err)
	}

	return &rel, nil
}

// DeleteAppServiceRelationship 在应用服务下删除关系
func (s *Service) DeleteAppServiceRelationship(ctx context.Context, appID, serviceID string, relationshipID uint) error {
	// 1. 验证应用和服务是否存在
	var app models.Application
	if err := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; err != nil {
		return fmt.Errorf("应用不存在: %w", err)
	}

	var service models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&service).Error; err != nil {
		return fmt.Errorf("服务不存在: %w", err)
	}

	// 2. 验证应用是否有权限访问该服务
	var relation models.ApplicationServiceRelation
	if err := s.db.WithContext(ctx).Where("app_id = ? AND service_id = ?", appID, serviceID).First(&relation).Error; err != nil {
		return fmt.Errorf("应用无权访问该服务")
	}

	// 3. 删除关系（通过 ID 和 service_id）
	if err := s.db.WithContext(ctx).Where("_id = ? AND service_id = ?", relationshipID, serviceID).Delete(&models.Relationship{}).Error; err != nil {
		return fmt.Errorf("删除关系失败: %w", err)
	}

	return nil
}

// ==================== Group 相关 ====================

// CreateGroup 创建组
func (s *Service) CreateGroup(ctx context.Context, req *GroupCreateRequest) (*models.Group, error) {
	group := &models.Group{
		GroupID:     req.GroupID,
		ServiceID:   req.ServiceID,
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
func (s *Service) ListGroups(ctx context.Context, req *GroupListRequest) (*CursorPage[models.Group], error) {
	query := s.db.WithContext(ctx).Model(&models.Group{})
	return CursorPaginate[models.Group](query, req.Cursor, req.Limit)
}

// UpdateGroup 更新组（JSON Merge Patch 语义）
func (s *Service) UpdateGroup(ctx context.Context, groupID string, req *GroupUpdateRequest) error {
	updates := patch.Collect(
		patch.Field("name", req.Name),
		patch.Field("description", req.Description),
	)

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

// ==================== Application IDP Config 相关 ====================

// GetApplicationIDPConfigs 获取应用 IDP 配置列表（按 priority 降序）
func (s *Service) GetApplicationIDPConfigs(ctx context.Context, appID string) ([]*models.ApplicationIDPConfig, error) {
	var configs []*models.ApplicationIDPConfig
	if err := s.db.WithContext(ctx).
		Where("app_id = ?", appID).
		Order("priority DESC").
		Find(&configs).Error; err != nil {
		return nil, fmt.Errorf("获取应用 IDP 配置失败: %w", err)
	}
	return configs, nil
}

// ==================== Service Challenge Config 相关 ====================

// GetServiceChallengeSetting 获取服务 Challenge 配置（service_id + type 唯一）
func (s *Service) GetServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) (*models.ServiceChallengeSetting, error) {
	var cfg models.ServiceChallengeSetting
	if err := s.db.WithContext(ctx).
		Where("service_id = ? AND `type` = ?", serviceID, challengeType).
		First(&cfg).Error; err != nil {
		return nil, fmt.Errorf("获取 Challenge 配置失败: %w", err)
	}
	return &cfg, nil
}

// ==================== 密钥管理 ====================

// GetApplicationKeys 获取应用的所有有效密钥（已解密）
func (s *Service) GetApplicationKeys(ctx context.Context, appID string) ([][]byte, error) {
	return s.getKeys(ctx, models.KeyOwnerApplication, appID)
}

// GetServiceKeys 获取服务的所有有效密钥（已解密）
func (s *Service) GetServiceKeys(ctx context.Context, serviceID string) ([][]byte, error) {
	return s.getKeys(ctx, models.KeyOwnerService, serviceID)
}

// RotateKey 轮换密钥：给旧主密钥设 expired_at，插入新密钥
func (s *Service) RotateKey(ctx context.Context, ownerType, ownerID string, window time.Duration) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		expiredAt := time.Now().Add(window)
		if err := tx.Model(&models.Key{}).
			Where("owner_type = ? AND owner_id = ? AND expired_at IS NULL", ownerType, ownerID).
			Update("expired_at", expiredAt).Error; err != nil {
			return fmt.Errorf("标记旧密钥过期失败: %w", err)
		}
		return s.createKey(tx, ownerType, ownerID)
	})
}

// getKeys 获取指定 owner 的所有有效密钥（已解密），按 created_at DESC 排序
func (s *Service) getKeys(ctx context.Context, ownerType, ownerID string) ([][]byte, error) {
	var keys []models.Key
	if err := s.db.WithContext(ctx).
		Where("owner_type = ? AND owner_id = ? AND (expired_at IS NULL OR expired_at > NOW())", ownerType, ownerID).
		Order("created_at DESC").
		Find(&keys).Error; err != nil {
		return nil, fmt.Errorf("获取密钥失败: %w", err)
	}

	if len(keys) == 0 {
		return nil, nil
	}

	dbEncKey, err := config.GetDBEncKeyRaw()
	if err != nil {
		return nil, fmt.Errorf("获取数据库加密密钥失败: %w", err)
	}

	result := make([][]byte, 0, len(keys))
	for _, k := range keys {
		encrypted, err := base64.StdEncoding.DecodeString(k.EncryptedKey)
		if err != nil {
			return nil, fmt.Errorf("解码密钥失败: %w", err)
		}
		decrypted, err := cryptoutil.DecryptAESGCM(dbEncKey, encrypted, ownerID)
		if err != nil {
			return nil, fmt.Errorf("解密密钥失败: %w", err)
		}
		result = append(result, decrypted)
	}

	return result, nil
}

// createKey 为 owner 创建新密钥（在事务中调用）
func (s *Service) createKey(tx *gorm.DB, ownerType, ownerID string) error {
	encryptedKey, err := generateEncryptedKey(ownerID)
	if err != nil {
		return err
	}

	key := &models.Key{
		OwnerType:    ownerType,
		OwnerID:      ownerID,
		EncryptedKey: encryptedKey,
	}

	if err := tx.Create(key).Error; err != nil {
		return fmt.Errorf("创建密钥失败: %w", err)
	}
	return nil
}

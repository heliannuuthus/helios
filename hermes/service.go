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

// getDomainRecordOnly 仅查 t_domain，不查 allowed_idps（用于 GetDomain 等只需基础信息时）
func (s *Service) getDomainRecordOnly(ctx context.Context, domainID string) (*models.DomainRecord, error) {
	var rec models.DomainRecord
	if err := s.db.WithContext(ctx).Where("domain_id = ?", domainID).First(&rec).Error; err != nil {
		return nil, fmt.Errorf("域 %s 不存在: %w", domainID, err)
	}
	return &rec, nil
}

// getDomainFromDB 从数据库读取域元数据及允许的 IDP 列表（供 GetDomainWithKey 等需要完整域信息时用）
func (s *Service) getDomainFromDB(ctx context.Context, domainID string) (*models.Domain, error) {
	rec, err := s.getDomainRecordOnly(ctx, domainID)
	if err != nil {
		return nil, err
	}
	allowedIDPs, err := s.getDomainAllowedIDPs(ctx, domainID)
	if err != nil {
		return nil, err
	}
	return &models.Domain{
		DomainID:    rec.DomainID,
		Name:        rec.Name,
		Description: rec.Description,
		AllowedIDPs: allowedIDPs,
	}, nil
}

// getDomainAllowedIDPs 查询域允许的 IDP 类型列表
func (s *Service) getDomainAllowedIDPs(ctx context.Context, domainID string) ([]string, error) {
	var rows []models.DomainIDPRecord
	if err := s.db.WithContext(ctx).Where("domain_id = ?", domainID).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("查询域 IDP 列表失败: %w", err)
	}
	out := make([]string, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].IDPType)
	}
	return out, nil
}

// GetDomain 获取域基础信息（仅 t_domain，不查 t_domain_idp；需时调 GetDomainAllowedIDPs）
func (s *Service) GetDomain(ctx context.Context, domainID string) (*models.Domain, error) {
	rec, err := s.getDomainRecordOnly(ctx, domainID)
	if err != nil {
		return nil, err
	}
	return &models.Domain{
		DomainID:    rec.DomainID,
		Name:        rec.Name,
		Description: rec.Description,
		AllowedIDPs: nil,
	}, nil
}

// GetDomainAllowedIDPs 获取域允许的 IDP 类型列表（供应用配置 IDP 时按需拉取）
func (s *Service) GetDomainAllowedIDPs(ctx context.Context, domainID string) ([]string, error) {
	if _, err := s.getDomainRecordOnly(ctx, domainID); err != nil {
		return nil, err
	}
	return s.getDomainAllowedIDPs(ctx, domainID)
}

// GetDomainWithKey 获取域（含签名密钥，供 aegis 签发/验签；AllowedIDPs 来自 DB；密钥优先从 t_key 读，否则回退到配置）
func (s *Service) GetDomainWithKey(ctx context.Context, domainID string) (*models.DomainWithKey, error) {
	domain, err := s.getDomainFromDB(ctx, domainID)
	if err != nil {
		return nil, err
	}

	signKeys, err := s.getKeys(ctx, models.KeyOwnerDomain, domainID)
	if err != nil {
		return nil, fmt.Errorf("获取域密钥失败: %w", err)
	}
	if len(signKeys) == 0 {
		// 回退到配置文件（兼容未把域密钥写入 t_key 的旧部署）
		signKeys, err = config.GetDomainSignKeysBytes(domainID)
		if err != nil {
			return nil, fmt.Errorf("获取域签名密钥失败: %w", err)
		}
	}

	return &models.DomainWithKey{
		Domain: *domain,
		Main:   signKeys[0],
		Keys:   signKeys,
	}, nil
}

// ListDomains 列出所有域（仅基础信息，不含 allowed_idps；需时用 GetDomainAllowedIDPs）
func (s *Service) ListDomains(ctx context.Context) ([]models.Domain, error) {
	var recs []models.DomainRecord
	if err := s.db.WithContext(ctx).Find(&recs).Error; err != nil {
		return nil, fmt.Errorf("列出域失败: %w", err)
	}
	domains := make([]models.Domain, 0, len(recs))
	for i := range recs {
		domains = append(domains, models.Domain{
			DomainID:    recs[i].DomainID,
			Name:        recs[i].Name,
			Description: recs[i].Description,
			AllowedIDPs: nil,
		})
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
		LogoURL:               req.LogoURL,
		AccessTokenExpiresIn:  7200,
	}
	if req.AccessTokenExpiresIn != nil {
		service.AccessTokenExpiresIn = *req.AccessTokenExpiresIn
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

// ListServices 列出服务，支持 service_id 精确、name 左模糊。包含该域下的服务及跨域服务（domain_id = DomainIDCrossDomain），跨域不在上层暴露由 handler 用请求 domain 表示。
func (s *Service) ListServices(ctx context.Context, domainID, serviceIDExact, namePrefix string) ([]models.Service, error) {
	var services []models.Service
	query := s.db.WithContext(ctx).Where("domain_id = ? OR domain_id = ?", domainID, models.CrossDomainID)
	if serviceIDExact != "" && namePrefix != "" {
		query = query.Where("(service_id = ? OR name LIKE ?)", serviceIDExact, namePrefix+"%")
	} else if serviceIDExact != "" {
		query = query.Where("service_id = ?", serviceIDExact)
	} else if namePrefix != "" {
		query = query.Where("name LIKE ?", namePrefix+"%")
	}
	if err := query.Find(&services).Error; err != nil {
		return nil, fmt.Errorf("列出服务失败: %w", err)
	}
	return services, nil
}

// UpdateService 更新服务（JSON Merge Patch 语义）
func (s *Service) UpdateService(ctx context.Context, serviceID string, req *ServiceUpdateRequest) error {
	updates := patch.Collect(
		patch.Field("name", req.Name),
		patch.Field("description", req.Description),
		patch.Field("logo_url", req.LogoURL),
		patch.Field("access_token_expires_in", req.AccessTokenExpiresIn),
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

// DeleteService 删除服务（级联删除关联数据）
func (s *Service) DeleteService(ctx context.Context, serviceID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var svc models.Service
		if err := tx.Where("service_id = ?", serviceID).First(&svc).Error; err != nil {
			return fmt.Errorf("服务不存在: %w", err)
		}
		if err := tx.Where("service_id = ?", serviceID).Delete(&models.ApplicationServiceRelation{}).Error; err != nil {
			return err
		}
		if err := tx.Where("service_id = ?", serviceID).Delete(&models.Relationship{}).Error; err != nil {
			return err
		}
		if err := tx.Where("service_id = ?", serviceID).Delete(&models.Group{}).Error; err != nil {
			return err
		}
		if err := tx.Where("service_id = ?", serviceID).Delete(&models.ServiceChallengeSetting{}).Error; err != nil {
			return err
		}
		if err := tx.Where("owner_type = ? AND owner_id = ?", models.KeyOwnerService, serviceID).Delete(&models.Key{}).Error; err != nil {
			return err
		}
		if err := tx.Where("service_id = ?", serviceID).Delete(&models.Service{}).Error; err != nil {
			return err
		}
		return nil
	})
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
		DomainID:                      req.DomainID,
		AppID:                         req.AppID,
		Name:                          req.Name,
		Description:                   req.Description,
		RedirectURIs:                  redirectURIs,
		IdTokenExpiresIn:              3600,
		RefreshTokenExpiresIn:         604800,
		RefreshTokenAbsoluteExpiresIn: 0,
	}
	if req.IdTokenExpiresIn != nil {
		app.IdTokenExpiresIn = *req.IdTokenExpiresIn
	}
	if req.RefreshTokenExpiresIn != nil {
		app.RefreshTokenExpiresIn = *req.RefreshTokenExpiresIn
	}
	if req.RefreshTokenAbsoluteExpiresIn != nil {
		app.RefreshTokenAbsoluteExpiresIn = *req.RefreshTokenAbsoluteExpiresIn
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

// UpdateApplication 更新应用（JSON Merge Patch 语义）
func (s *Service) UpdateApplication(ctx context.Context, appID string, req *ApplicationUpdateRequest) error {
	updates := patch.Collect(
		patch.Field("name", req.Name),
		patch.Field("description", req.Description),
		patch.Field("id_token_expires_in", req.IdTokenExpiresIn),
		patch.Field("refresh_token_expires_in", req.RefreshTokenExpiresIn),
		patch.Field("refresh_token_absolute_expires_in", req.RefreshTokenAbsoluteExpiresIn),
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

// GetServiceApplicationRelations 获取服务已授权给哪些应用及授予的权限（ReBAC 服务侧视角）
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
func (s *Service) ListAppServiceRelationships(ctx context.Context, appID, serviceID, subjectType, subjectID string) ([]models.Relationship, error) {
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

	// 3. 查询关系
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
func (s *Service) ListGroups(ctx context.Context) ([]models.Group, error) {
	var groups []models.Group
	if err := s.db.WithContext(ctx).Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("列出组失败: %w", err)
	}
	return groups, nil
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

// ensureIDPAllowedForApplication 校验 idpType 是否在应用所属域的 allowed_idps 中
func (s *Service) ensureIDPAllowedForApplication(ctx context.Context, appID, idpType string) error {
	app, err := s.GetApplication(ctx, appID)
	if err != nil {
		return err
	}
	allowed, err := s.getDomainAllowedIDPs(ctx, app.DomainID)
	if err != nil {
		return err
	}
	for _, t := range allowed {
		if t == idpType {
			return nil
		}
	}
	return fmt.Errorf("IDP %s 不在域 %s 的允许列表中", idpType, app.DomainID)
}

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

// CreateApplicationIDPConfig 创建应用 IDP 配置（仅允许添加该应用所属域下的 IDP）
func (s *Service) CreateApplicationIDPConfig(ctx context.Context, appID string, req *ApplicationIDPConfigCreateRequest) (*models.ApplicationIDPConfig, error) {
	if err := s.ensureIDPAllowedForApplication(ctx, appID, req.Type); err != nil {
		return nil, err
	}
	cfg := &models.ApplicationIDPConfig{
		AppID:    appID,
		Type:     req.Type,
		Priority: req.Priority,
		Strategy: req.Strategy,
		Delegate: req.Delegate,
		Require:  req.Require,
	}
	if err := s.db.WithContext(ctx).Create(cfg).Error; err != nil {
		return nil, fmt.Errorf("创建应用 IDP 配置失败: %w", err)
	}
	return cfg, nil
}

// UpdateApplicationIDPConfig 更新应用 IDP 配置（不修改 type 时不校验域；若请求中带新 type 则需在域允许列表中）
func (s *Service) UpdateApplicationIDPConfig(ctx context.Context, appID, idpType string, req *ApplicationIDPConfigUpdateRequest) error {
	updates := patch.Collect(
		patch.Field("priority", req.Priority),
		patch.Field("strategy", req.Strategy),
		patch.Field("delegate", req.Delegate),
		patch.Field("require", req.Require),
	)
	if len(updates) == 0 {
		return nil
	}
	result := s.db.WithContext(ctx).Model(&models.ApplicationIDPConfig{}).
		Where("app_id = ? AND `type` = ?", appID, idpType).Updates(updates)
	if result.Error != nil {
		return fmt.Errorf("更新应用 IDP 配置失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("应用 IDP 配置不存在: app_id=%s, type=%s", appID, idpType)
	}
	return nil
}

// DeleteApplicationIDPConfig 删除应用 IDP 配置
func (s *Service) DeleteApplicationIDPConfig(ctx context.Context, appID, idpType string) error {
	result := s.db.WithContext(ctx).Where("app_id = ? AND `type` = ?", appID, idpType).Delete(&models.ApplicationIDPConfig{})
	if result.Error != nil {
		return fmt.Errorf("删除应用 IDP 配置失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("应用 IDP 配置不存在: app_id=%s, type=%s", appID, idpType)
	}
	return nil
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

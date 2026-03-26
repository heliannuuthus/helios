package hermes

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-json-experiment/json"
	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/hermes/validation"
	"github.com/heliannuuthus/helios/pkg/filter"
	"github.com/heliannuuthus/helios/pkg/helpers"
	"github.com/heliannuuthus/helios/pkg/pagination"
	"github.com/heliannuuthus/helios/pkg/patch"
)

// ==================== Domain 相关 ====================

// GetDomain 获取域基础信息（仅 t_domain 元数据）
func (s *Service) GetDomain(ctx context.Context, domainID string) (*models.Domain, error) {
	rec, err := s.getDomain(ctx, domainID)
	if err != nil {
		return nil, err
	}
	return &models.Domain{
		DomainID:    rec.DomainID,
		Name:        rec.Name,
		Description: rec.Description,
	}, nil
}

// ListDomains 列出所有域（仅基础信息）
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
		})
	}
	return domains, nil
}

// UpdateDomain 更新域（仅 name、description）
func (s *Service) UpdateDomain(ctx context.Context, domainID string, req *dto.DomainUpdateRequest) (*models.Domain, error) {
	if _, err := s.getDomain(ctx, domainID); err != nil {
		return nil, err
	}
	updates := patch.Collect(
		patch.Field("name", req.Name),
		patch.Field("description", req.Description),
	)
	if len(updates) == 0 {
		return s.GetDomain(ctx, domainID)
	}
	if err := s.db.WithContext(ctx).Model(&models.DomainRecord{}).Where("domain_id = ?", domainID).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新域失败: %w", err)
	}
	return s.GetDomain(ctx, domainID)
}

// DeleteDomain 删除域（级联删除关联数据）
func (s *Service) DeleteDomain(ctx context.Context, domainID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var rec models.DomainRecord
		if err := tx.Where("domain_id = ?", domainID).First(&rec).Error; err != nil {
			return fmt.Errorf("域不存在: %w", err)
		}
		if err := tx.Where("domain_id = ?", domainID).Delete(&models.DomainIDPConfig{}).Error; err != nil {
			return err
		}
		if err := tx.Where("domain_id = ?", domainID).Delete(&models.Service{}).Error; err != nil {
			return err
		}
		if err := tx.Where("domain_id = ?", domainID).Delete(&models.Application{}).Error; err != nil {
			return err
		}
		if err := tx.Where("owner_type = ? AND owner_id = ?", models.KeyOwnerDomain, domainID).Delete(&models.Key{}).Error; err != nil {
			return err
		}
		return tx.Where("domain_id = ?", domainID).Delete(&models.DomainRecord{}).Error
	})
}

// ==================== Service 相关 ====================

// CreateService 创建服务
func (s *Service) CreateService(ctx context.Context, req *dto.ServiceCreateRequest) (*models.Service, error) {
	if err := validation.ValidateID("service_id", req.ServiceID); err != nil {
		return nil, err
	}
	if err := validation.ValidateID("domain_id", req.DomainID); err != nil {
		return nil, err
	}
	desc := req.Description
	svc := &models.Service{
		ServiceID:            req.ServiceID,
		DomainID:             req.DomainID,
		Name:                 req.Name,
		Description:          &desc,
		LogoURL:              req.LogoURL,
		AccessTokenExpiresIn: 7200,
	}
	if req.AccessTokenExpiresIn != nil {
		svc.AccessTokenExpiresIn = *req.AccessTokenExpiresIn
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(svc).Error; err != nil {
			return fmt.Errorf("创建服务失败: %w", err)
		}
		return s.CreateKey(tx, models.KeyOwnerService, req.ServiceID)
	})
	if err != nil {
		return nil, err
	}
	return svc, nil
}

// GetService 获取服务（不含密钥）
func (s *Service) GetService(ctx context.Context, serviceID string) (*models.Service, error) {
	var svc models.Service
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).First(&svc).Error; err != nil {
		return nil, fmt.Errorf("获取服务失败: %w", err)
	}
	return &svc, nil
}

var serviceFilters = filter.Whitelist{
	"service_id": {filter.Eq},
	"name":       {filter.Eq, filter.Pre},
}

// ListServices 列出服务（游标分页）
func (s *Service) ListServices(ctx context.Context, domainID string, req *dto.ListRequest) (*pagination.Items[models.Service], error) {
	query := s.db.WithContext(ctx).Model(&models.Service{})
	if domainID != "" {
		query = query.Where("domain_id = ? OR domain_id = ?", domainID, models.CrossDomainID)
	}
	query = filter.Apply(query, req.Filter, serviceFilters)
	return pagination.CursorPaginate[models.Service](query, req.Pagination)
}

// UpdateService 更新服务（JSON Merge Patch 语义）
func (s *Service) UpdateService(ctx context.Context, serviceID string, req *dto.ServiceUpdateRequest) error {
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
		return tx.Where("service_id = ?", serviceID).Delete(&models.Service{}).Error
	})
}

// ==================== Application 相关 ====================

func marshalOptionalStringSlice(s []string) *string {
	if len(s) == 0 {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil
	}
	str := string(b)
	return &str
}

// CreateApplication 创建应用
func (s *Service) CreateApplication(ctx context.Context, req *dto.ApplicationCreateRequest) (*models.Application, error) {
	if err := validation.ValidateID("domain_id", req.DomainID); err != nil {
		return nil, err
	}
	appID := strings.TrimSpace(req.AppID)
	if appID == "" {
		appID = helpers.GenerateID(12)
	} else if err := validation.ValidateID("app_id", appID); err != nil {
		return nil, err
	}

	if err := validation.ValidateRedirectURIs(req.AllowedRedirectURIs); err != nil {
		return nil, fmt.Errorf("allowed_redirect_uris: %w", err)
	}
	if err := validation.ValidateAllowedOrigins(req.AllowedOrigins); err != nil {
		return nil, fmt.Errorf("allowed_origins: %w", err)
	}
	if err := validation.ValidateLogoutURIs(req.AllowedLogoutURIs); err != nil {
		return nil, fmt.Errorf("allowed_logout_uris: %w", err)
	}

	allowedRedirectURIs := marshalOptionalStringSlice(req.AllowedRedirectURIs)
	allowedOrigins := marshalOptionalStringSlice(req.AllowedOrigins)
	allowedLogoutURIs := marshalOptionalStringSlice(req.AllowedLogoutURIs)

	desc := req.Description
	app := &models.Application{
		DomainID:                      req.DomainID,
		AppID:                         appID,
		Name:                          req.Name,
		Description:                   &desc,
		AllowedRedirectURIs:           allowedRedirectURIs,
		AllowedOrigins:                allowedOrigins,
		AllowedLogoutURIs:             allowedLogoutURIs,
		IDTokenExpiresIn:              3600,
		RefreshTokenExpiresIn:         604800,
		RefreshTokenAbsoluteExpiresIn: 0,
	}
	if req.IDTokenExpiresIn != nil {
		app.IDTokenExpiresIn = *req.IDTokenExpiresIn
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
			if err := s.CreateKey(tx, models.KeyOwnerApplication, appID); err != nil {
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

var applicationFilters = filter.Whitelist{
	"name": {filter.Eq, filter.Pre},
}

// ListApplications 列出应用（游标分页）
func (s *Service) ListApplications(ctx context.Context, domainID string, req *dto.ListRequest) (*pagination.Items[models.Application], error) {
	query := s.db.WithContext(ctx).Model(&models.Application{})
	if domainID != "" {
		query = query.Where("domain_id = ?", domainID)
	}
	query = filter.Apply(query, req.Filter, applicationFilters)
	return pagination.CursorPaginate[models.Application](query, req.Pagination)
}

func applyOptionalURIList(
	updates map[string]interface{},
	opt patch.Optional[[]string],
	dbKey string,
	validate func([]string) error,
	errPrefix string,
) error {
	if !opt.IsPresent() {
		return nil
	}
	if opt.IsNull() {
		updates[dbKey] = nil
		return nil
	}
	vals := opt.Value()
	if err := validate(vals); err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}
	b, err := json.Marshal(vals)
	if err != nil {
		return fmt.Errorf("序列化 %s 失败: %w", errPrefix, err)
	}
	updates[dbKey] = string(b)
	return nil
}

// UpdateApplication 更新应用（JSON Merge Patch 语义）
func (s *Service) UpdateApplication(ctx context.Context, appID string, req *dto.ApplicationUpdateRequest) error {
	updates := patch.Collect(
		patch.Field("name", req.Name),
		patch.Field("description", req.Description),
		patch.Field("logo_url", req.LogoURL),
		patch.Field("id_token_expires_in", req.IDTokenExpiresIn),
		patch.Field("refresh_token_expires_in", req.RefreshTokenExpiresIn),
		patch.Field("refresh_token_absolute_expires_in", req.RefreshTokenAbsoluteExpiresIn),
	)

	if err := applyOptionalURIList(updates, req.AllowedRedirectURIs, "redirect_uris", validation.ValidateRedirectURIs, "allowed_redirect_uris"); err != nil {
		return err
	}
	if err := applyOptionalURIList(updates, req.AllowedOrigins, "allowed_origins", validation.ValidateAllowedOrigins, "allowed_origins"); err != nil {
		return err
	}
	if err := applyOptionalURIList(updates, req.AllowedLogoutURIs, "allowed_logout_uris", validation.ValidateLogoutURIs, "allowed_logout_uris"); err != nil {
		return err
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

// DeleteApplication 删除应用（级联删除关联数据）
func (s *Service) DeleteApplication(ctx context.Context, appID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var app models.Application
		if err := tx.Where("app_id = ?", appID).First(&app).Error; err != nil {
			return fmt.Errorf("应用不存在: %w", err)
		}
		if err := tx.Where("app_id = ?", appID).Delete(&models.ApplicationIDPConfig{}).Error; err != nil {
			return err
		}
		if err := tx.Where("app_id = ?", appID).Delete(&models.ApplicationServiceRelation{}).Error; err != nil {
			return err
		}
		if err := tx.Where("owner_type = ? AND owner_id = ?", models.KeyOwnerApplication, appID).Delete(&models.Key{}).Error; err != nil {
			return err
		}
		return tx.Where("app_id = ?", appID).Delete(&models.Application{}).Error
	})
}

// ==================== Domain IDP Config 相关 ====================

// GetDomainIDPConfigs 获取域下所有 IDP 配置（按 priority 降序）
func (s *Service) GetDomainIDPConfigs(ctx context.Context, domainID string) ([]*models.DomainIDPConfig, error) {
	var configs []*models.DomainIDPConfig
	if err := s.db.WithContext(ctx).
		Where("domain_id = ?", domainID).
		Order("priority DESC").
		Find(&configs).Error; err != nil {
		return nil, fmt.Errorf("获取域 IDP 配置列表失败: %w", err)
	}
	return configs, nil
}

// GetDomainIDPConfig 获取域下指定 IDP 类型的配置
func (s *Service) GetDomainIDPConfig(ctx context.Context, domainID, idpType string) (*models.DomainIDPConfig, error) {
	var cfg models.DomainIDPConfig
	if err := s.db.WithContext(ctx).
		Where("domain_id = ? AND idp_type = ?", domainID, idpType).
		First(&cfg).Error; err != nil {
		return nil, fmt.Errorf("获取域 IDP 配置失败: %w", err)
	}
	return &cfg, nil
}

// CreateDomainIDPConfig 创建域 IDP 配置（同时表示该 IDP 在此域下可用）
func (s *Service) CreateDomainIDPConfig(ctx context.Context, domainID string, req *dto.DomainIDPConfigCreateRequest) (*models.DomainIDPConfig, error) {
	if _, err := s.getDomain(ctx, domainID); err != nil {
		return nil, err
	}
	cfg := &models.DomainIDPConfig{
		DomainID: domainID,
		IDPType:  req.IDPType,
		Priority: req.Priority,
		Strategy: req.Strategy,
		TAppID:   req.TAppID,
	}
	if err := s.db.WithContext(ctx).Create(cfg).Error; err != nil {
		return nil, fmt.Errorf("创建域 IDP 配置失败: %w", err)
	}
	return cfg, nil
}

// UpdateDomainIDPConfig 更新域 IDP 配置（JSON Merge Patch 语义）
func (s *Service) UpdateDomainIDPConfig(ctx context.Context, domainID, idpType string, req *dto.DomainIDPConfigUpdateRequest) error {
	updates := patch.Collect(
		patch.Field("priority", req.Priority),
		patch.Field("strategy", req.Strategy),
		patch.Field("t_app_id", req.TAppID),
	)
	if len(updates) == 0 {
		return nil
	}
	result := s.db.WithContext(ctx).Model(&models.DomainIDPConfig{}).
		Where("domain_id = ? AND idp_type = ?", domainID, idpType).Updates(updates)
	if result.Error != nil {
		return fmt.Errorf("更新域 IDP 配置失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("域 IDP 配置不存在: domain_id=%s, idp_type=%s", domainID, idpType)
	}
	return nil
}

// DeleteDomainIDPConfig 删除域 IDP 配置
func (s *Service) DeleteDomainIDPConfig(ctx context.Context, domainID, idpType string) error {
	result := s.db.WithContext(ctx).
		Where("domain_id = ? AND idp_type = ?", domainID, idpType).
		Delete(&models.DomainIDPConfig{})
	if result.Error != nil {
		return fmt.Errorf("删除域 IDP 配置失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("域 IDP 配置不存在: domain_id=%s, idp_type=%s", domainID, idpType)
	}
	return nil
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

// CreateApplicationIDPConfig 创建应用 IDP 配置（仅允许添加该应用所属域下的 IDP）
func (s *Service) CreateApplicationIDPConfig(ctx context.Context, appID string, req *dto.ApplicationIDPConfigCreateRequest) (*models.ApplicationIDPConfig, error) {
	if err := s.ensureIDPAllowedForApplication(ctx, appID, req.Type); err != nil {
		return nil, err
	}
	cfg := &models.ApplicationIDPConfig{
		AppID:    appID,
		Type:     req.Type,
		Priority: req.Priority,
		Strategy: req.Strategy,
		TAppID:   req.TAppID,
	}
	if err := s.db.WithContext(ctx).Create(cfg).Error; err != nil {
		return nil, fmt.Errorf("创建应用 IDP 配置失败: %w", err)
	}
	return cfg, nil
}

// UpdateApplicationIDPConfig 更新应用 IDP 配置（JSON Merge Patch 语义）
func (s *Service) UpdateApplicationIDPConfig(ctx context.Context, appID, idpType string, req *dto.ApplicationIDPConfigUpdateRequest) error {
	updates := patch.Collect(
		patch.Field("priority", req.Priority),
		patch.Field("strategy", req.Strategy),
		patch.Field("t_app_id", req.TAppID),
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

// GetServiceChallengeSetting 获取服务 Challenge 配置
func (s *Service) GetServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) (*models.ServiceChallengeSetting, error) {
	var cfg models.ServiceChallengeSetting
	if err := s.db.WithContext(ctx).
		Where("service_id = ? AND `type` = ?", serviceID, challengeType).
		First(&cfg).Error; err != nil {
		return nil, fmt.Errorf("获取 Challenge 配置失败: %w", err)
	}
	return &cfg, nil
}

// ListServiceChallengeSettings 获取服务下所有 Challenge 配置
func (s *Service) ListServiceChallengeSettings(ctx context.Context, serviceID string) ([]models.ServiceChallengeSetting, error) {
	var settings []models.ServiceChallengeSetting
	if err := s.db.WithContext(ctx).Where("service_id = ?", serviceID).Find(&settings).Error; err != nil {
		return nil, fmt.Errorf("获取 Challenge 配置列表失败: %w", err)
	}
	return settings, nil
}

// CreateServiceChallengeSetting 创建服务 Challenge 配置
func (s *Service) CreateServiceChallengeSetting(ctx context.Context, serviceID string, req *dto.ServiceChallengeSettingCreateRequest) (*models.ServiceChallengeSetting, error) {
	if _, err := s.GetService(ctx, serviceID); err != nil {
		return nil, err
	}
	setting := &models.ServiceChallengeSetting{
		ServiceID: serviceID,
		Type:      req.Type,
		ExpiresIn: req.ExpiresIn,
		Limits:    req.Limits,
	}
	if setting.ExpiresIn == 0 {
		setting.ExpiresIn = 300
	}
	if err := s.db.WithContext(ctx).Create(setting).Error; err != nil {
		return nil, fmt.Errorf("创建 Challenge 配置失败: %w", err)
	}
	return setting, nil
}

// UpdateServiceChallengeSetting 更新服务 Challenge 配置（JSON Merge Patch 语义）
func (s *Service) UpdateServiceChallengeSetting(ctx context.Context, serviceID, challengeType string, req *dto.ServiceChallengeSettingUpdateRequest) error {
	updates := patch.Collect(
		patch.Field("expires_in", req.ExpiresIn),
	)
	if req.Limits.IsPresent() {
		if req.Limits.IsNull() {
			updates["limits"] = nil
		} else {
			updates["limits"] = req.Limits.Value()
		}
	}
	if len(updates) == 0 {
		return nil
	}
	result := s.db.WithContext(ctx).Model(&models.ServiceChallengeSetting{}).
		Where("service_id = ? AND `type` = ?", serviceID, challengeType).Updates(updates)
	if result.Error != nil {
		return fmt.Errorf("更新 Challenge 配置失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("challenge 配置不存在: service_id=%s, type=%s", serviceID, challengeType)
	}
	return nil
}

// DeleteServiceChallengeSetting 删除服务 Challenge 配置
func (s *Service) DeleteServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) error {
	result := s.db.WithContext(ctx).
		Where("service_id = ? AND `type` = ?", serviceID, challengeType).
		Delete(&models.ServiceChallengeSetting{})
	if result.Error != nil {
		return fmt.Errorf("删除 Challenge 配置失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("challenge 配置不存在: service_id=%s, type=%s", serviceID, challengeType)
	}
	return nil
}

// ==================== 内部辅助方法 ====================

func (s *Service) getDomain(ctx context.Context, domainID string) (*models.DomainRecord, error) {
	var rec models.DomainRecord
	if err := s.db.WithContext(ctx).Where("domain_id = ?", domainID).First(&rec).Error; err != nil {
		return nil, fmt.Errorf("域 %s 不存在: %w", domainID, err)
	}
	return &rec, nil
}

func (s *Service) ensureIDPAllowedForApplication(ctx context.Context, appID, idpType string) error {
	app, err := s.GetApplication(ctx, appID)
	if err != nil {
		return err
	}
	configs, err := s.GetDomainIDPConfigs(ctx, app.DomainID)
	if err != nil {
		return err
	}
	for _, cfg := range configs {
		if cfg.IDPType == idpType {
			return nil
		}
	}
	return fmt.Errorf("IDP %s 未在域 %s 中配置", idpType, app.DomainID)
}

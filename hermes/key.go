package hermes

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/hermes/config"
	"github.com/heliannuuthus/helios/hermes/dto"
	"github.com/heliannuuthus/helios/hermes/models"
	cryptoutil "github.com/heliannuuthus/helios/pkg/crypto"
)

// generateEncryptedKey 生成 48 字节 seed（16-byte salt + 32-byte key）并用数据库加密密钥加密
func generateEncryptedKey(aad string) (string, error) {
	key := make([]byte, 48)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("生成密钥失败: %w", err)
	}

	domainEncryptKey, err := config.GetDBEncKeyRaw()
	if err != nil {
		return "", fmt.Errorf("获取数据库加密密钥失败: %w", err)
	}

	encryptedKey, err := cryptoutil.EncryptAESGCM(key, domainEncryptKey, aad)
	if err != nil {
		return "", fmt.Errorf("加密密钥失败: %w", err)
	}

	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// GetDomainKeys 获取域的所有有效密钥（已解密），回退到配置文件兼容旧部署
func (s *Service) GetDomainKeys(ctx context.Context, domainID string) ([][]byte, error) {
	keys, err := s.getKeys(ctx, models.KeyOwnerDomain, domainID)
	if err != nil {
		return nil, fmt.Errorf("获取域密钥失败: %w", err)
	}
	if len(keys) == 0 {
		keys, err = config.GetDomainSignKeysBytes(domainID)
		if err != nil {
			return nil, fmt.Errorf("获取域签名密钥失败: %w", err)
		}
	}
	return keys, nil
}

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
		return s.CreateKey(tx, ownerType, ownerID)
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

func (s *Service) encryptIDPKey(plaintext, aad string) (string, error) {
	dbEncKey, err := config.GetDBEncKeyRaw()
	if err != nil {
		return "", fmt.Errorf("获取数据库加密密钥失败: %w", err)
	}
	encrypted, err := cryptoutil.EncryptAESGCM(dbEncKey, []byte(plaintext), aad)
	if err != nil {
		return "", fmt.Errorf("加密 IDP secret 失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (s *Service) decryptIDPKey(cipherBase64, aad string) (string, error) {
	dbEncKey, err := config.GetDBEncKeyRaw()
	if err != nil {
		return "", fmt.Errorf("获取数据库加密密钥失败: %w", err)
	}
	encrypted, err := base64.StdEncoding.DecodeString(cipherBase64)
	if err != nil {
		return "", fmt.Errorf("Base64 解码失败: %w", err)
	}
	decrypted, err := cryptoutil.DecryptAESGCM(dbEncKey, encrypted, aad)
	if err != nil {
		return "", fmt.Errorf("解密 IDP secret 失败: %w", err)
	}
	return string(decrypted), nil
}

// CreateKey 为 owner 创建新密钥（在事务中调用）
func (s *Service) CreateKey(tx *gorm.DB, ownerType, ownerID string) error {
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

// ==================== IDP Key 相关 ====================

// GetIDPKeys 获取所有 IDP 密钥
func (s *Service) GetIDPKeys(ctx context.Context) ([]*models.IDPKey, error) {
	var secrets []*models.IDPKey
	if err := s.db.WithContext(ctx).Find(&secrets).Error; err != nil {
		return nil, fmt.Errorf("获取 IDP 密钥列表失败: %w", err)
	}
	return secrets, nil
}

// GetIDPKey 获取指定 IDP 密钥
func (s *Service) GetIDPKey(ctx context.Context, idpType, tAppID string) (*models.IDPKey, error) {
	var secret models.IDPKey
	if err := s.db.WithContext(ctx).
		Where("idp_type = ? AND t_app_id = ?", idpType, tAppID).
		First(&secret).Error; err != nil {
		return nil, fmt.Errorf("获取 IDP 密钥失败: %w", err)
	}
	return &secret, nil
}

// CreateIDPKey 创建 IDP 密钥
func (s *Service) CreateIDPKey(ctx context.Context, req *dto.IDPKeyCreateRequest) (*models.IDPKey, error) {
	aad := req.IDPType + ":" + req.TAppID
	encryptedSecret, err := s.encryptIDPKey(req.TSecret, aad)
	if err != nil {
		return nil, err
	}
	secret := &models.IDPKey{
		IDPType: req.IDPType,
		TAppID:  req.TAppID,
		TSecret: encryptedSecret,
	}
	if err := s.db.WithContext(ctx).Create(secret).Error; err != nil {
		return nil, fmt.Errorf("创建 IDP 密钥失败: %w", err)
	}
	return secret, nil
}

// UpdateIDPKey 更新 IDP 密钥
func (s *Service) UpdateIDPKey(ctx context.Context, idpType, tAppID string, req *dto.IDPKeyUpdateRequest) error {
	if !req.TSecret.IsPresent() || req.TSecret.IsNull() {
		return nil
	}
	aad := idpType + ":" + tAppID
	encryptedSecret, err := s.encryptIDPKey(req.TSecret.Value(), aad)
	if err != nil {
		return err
	}
	result := s.db.WithContext(ctx).Model(&models.IDPKey{}).
		Where("idp_type = ? AND t_app_id = ?", idpType, tAppID).
		Update("t_secret", encryptedSecret)
	if result.Error != nil {
		return fmt.Errorf("更新 IDP 密钥失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("IDP 密钥不存在: idp_type=%s, t_app_id=%s", idpType, tAppID)
	}
	return nil
}

// DeleteIDPKey 删除 IDP 密钥
func (s *Service) DeleteIDPKey(ctx context.Context, idpType, tAppID string) error {
	result := s.db.WithContext(ctx).
		Where("idp_type = ? AND t_app_id = ?", idpType, tAppID).
		Delete(&models.IDPKey{})
	if result.Error != nil {
		return fmt.Errorf("删除 IDP 密钥失败: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("IDP 密钥不存在: idp_type=%s, t_app_id=%s", idpType, tAppID)
	}
	return nil
}

// ResolveIDPKey 解析应用的有效 IDP 密钥
func (s *Service) ResolveIDPKey(ctx context.Context, appID, idpType string) (tAppID, tSecret string, err error) {
	var appCfg models.ApplicationIDPConfig
	if findErr := s.db.WithContext(ctx).
		Where("app_id = ? AND `type` = ?", appID, idpType).
		First(&appCfg).Error; findErr != nil {
		return "", "", fmt.Errorf("应用 IDP 配置不存在: %w", findErr)
	}

	resolvedAppID := ""
	if appCfg.TAppID != nil && *appCfg.TAppID != "" {
		resolvedAppID = *appCfg.TAppID
	} else {
		var app models.Application
		if appErr := s.db.WithContext(ctx).Where("app_id = ?", appID).First(&app).Error; appErr != nil {
			return "", "", fmt.Errorf("获取应用失败: %w", appErr)
		}
		var domainCfg models.DomainIDPConfig
		if findErr := s.db.WithContext(ctx).
			Where("domain_id = ? AND idp_type = ?", app.DomainID, idpType).
			First(&domainCfg).Error; findErr != nil {
			return "", "", fmt.Errorf("域 IDP 配置未配置: domain_id=%s, idp_type=%s", app.DomainID, idpType)
		}
		resolvedAppID = domainCfg.TAppID
	}

	var idpSecret models.IDPKey
	if findErr := s.db.WithContext(ctx).
		Where("idp_type = ? AND t_app_id = ?", idpType, resolvedAppID).
		First(&idpSecret).Error; findErr != nil {
		return "", "", fmt.Errorf("IDP 密钥不存在: idp_type=%s, t_app_id=%s", idpType, resolvedAppID)
	}

	aad := idpType + ":" + resolvedAppID
	secret, decErr := s.decryptIDPKey(idpSecret.TSecret, aad)
	if decErr != nil {
		return "", "", decErr
	}
	return resolvedAppID, secret, nil
}

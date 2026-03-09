package cache

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/hermes/models"
	pasetokit "github.com/heliannuuthus/helios/pkg/aegis/utils/paseto"
)

// ==================== Hermes 数据（本地缓存 + DB）====================

// GetApplication 获取应用（带缓存，密钥已派生）
func (cm *Manager) GetApplication(ctx context.Context, appID string) (*ApplicationWithKey, error) {
	cacheKey := config.GetCacheKeyPrefix("application") + appID

	if cm.applicationCache != nil {
		if cached, ok := cm.applicationCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	raw, err := cm.hermesSvc.GetApplicationWithKey(ctx, appID)
	if err != nil {
		return nil, err
	}

	result, err := DeriveApplicationKeys(raw)
	if err != nil {
		return nil, fmt.Errorf("derive application keys: %w", err)
	}

	if cm.applicationCache != nil {
		ttl := config.GetCacheTTL("application")
		cm.applicationCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetService 获取服务（带缓存，密钥已派生）
func (cm *Manager) GetService(ctx context.Context, serviceID string) (*ServiceWithKey, error) {
	cacheKey := config.GetCacheKeyPrefix("service") + serviceID

	if cm.serviceCache != nil {
		if cached, ok := cm.serviceCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	raw, err := cm.hermesSvc.GetServiceWithKey(ctx, serviceID)
	if err != nil {
		return nil, err
	}

	result, err := DeriveServiceKeys(raw)
	if err != nil {
		return nil, fmt.Errorf("derive service keys: %w", err)
	}

	if cm.serviceCache != nil {
		ttl := config.GetCacheTTL("service")
		cm.serviceCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetDomain 获取域（带缓存，密钥已派生）
func (cm *Manager) GetDomain(ctx context.Context, domainID string) (*DomainWithKey, error) {
	cacheKey := config.GetCacheKeyPrefix("domain") + domainID

	if cm.domainCache != nil {
		if cached, ok := cm.domainCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	raw, err := cm.hermesSvc.GetDomainWithKey(ctx, domainID)
	if err != nil {
		return nil, err
	}

	result, err := DeriveDomainKeys(raw)
	if err != nil {
		return nil, fmt.Errorf("derive domain keys: %w", err)
	}

	if cm.domainCache != nil {
		ttl := config.GetCacheTTL("domain")
		cm.domainCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetAppServiceRelations 获取应用可访问的服务关系
func (cm *Manager) GetAppServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error) {
	cacheKey := config.GetCacheKeyPrefix("application-service-relation") + appID

	// 尝试从缓存获取
	if cm.relationCache != nil {
		if cached, ok := cm.relationCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	relations, err := cm.hermesSvc.GetApplicationServiceRelations(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.relationCache != nil {
		ttl := config.GetCacheTTL("application-service-relation")
		cm.relationCache.SetWithTTL(cacheKey, relations, 1, ttl)
	}

	return relations, nil
}

// GetApplicationIDPConfigs 获取应用 IDP 配置（带缓存）
func (cm *Manager) GetApplicationIDPConfigs(ctx context.Context, appID string) ([]*models.ApplicationIDPConfig, error) {
	cacheKey := config.GetCacheKeyPrefix("app-idp-config") + appID

	// 尝试从缓存获取
	if cm.appIDPConfigCache != nil {
		if cached, ok := cm.appIDPConfigCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	configs, err := cm.hermesSvc.GetApplicationIDPConfigs(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.appIDPConfigCache != nil {
		ttl := config.GetCacheTTL("app-idp-config")
		cm.appIDPConfigCache.SetWithTTL(cacheKey, configs, 1, ttl)
	}

	return configs, nil
}

// GetServiceChallengeSetting 获取服务的 Challenge 配置（带本地缓存）
func (cm *Manager) GetServiceChallengeSetting(ctx context.Context, serviceID, challengeType string) (*models.ServiceChallengeSetting, error) {
	cacheKey := serviceChallengeCacheKey(serviceID, challengeType)

	// 尝试从缓存获取
	if cm.challengeConfigCache != nil {
		if cached, ok := cm.challengeConfigCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	result, err := cm.hermesSvc.GetServiceChallengeSetting(ctx, serviceID, challengeType)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.challengeConfigCache != nil {
		ttl := config.GetCacheTTL("service-challenge-setting")
		cm.challengeConfigCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// serviceChallengeCacheKey 构造 ServiceChallengeSetting 缓存 key
func serviceChallengeCacheKey(serviceID, challengeType string) string {
	return config.GetCacheKeyPrefix("service-challenge-setting") + serviceID + ":" + challengeType
}

const ssoKeyName = "sso"

// GetSSOKeys 获取 SSO 密钥组（已派生，走 ristretto TTL 自动过期）
func (cm *Manager) GetSSOKeys() (*Keys, error) {
	if k, ok := cm.ssoKeyCache.Get(ssoKeyName); ok {
		return k, nil
	}

	seeds, err := config.GetSSOMasterKeys()
	if err != nil {
		return nil, fmt.Errorf("fetch sso master keys: %w", err)
	}
	if len(seeds) == 0 {
		return nil, fmt.Errorf("sso master key not configured")
	}

	keys, err := deriveKeys(seeds)
	if err != nil {
		return nil, fmt.Errorf("derive sso keys: %w", err)
	}

	cm.ssoKeyCache.SetWithTTL(ssoKeyName, keys, 1, config.GetCacheTTL("sso"))
	return keys, nil
}

// ==================== Seed → Key 派生 ====================

// deriveKeys 从多个 seed 派生密钥组（第一个为 Main，全部放入 Keys）
func deriveKeys(seeds [][]byte) (*Keys, error) {
	if len(seeds) == 0 {
		return nil, nil
	}
	all := make([]Key, 0, len(seeds))
	for i, s := range seeds {
		k, err := deriveKey(s)
		if err != nil {
			return nil, fmt.Errorf("derive key[%d]: %w", i, err)
		}
		all = append(all, *k)
	}
	return &Keys{Main: all[0], Keys: all}, nil
}

// deriveKey 从 48 字节 seed 同时派生签名密钥和加密密钥（三个字段全填充）
func deriveKey(seedBytes []byte) (*Key, error) {
	sign, err := deriveSigningKey(seedBytes)
	if err != nil {
		return nil, err
	}
	encrypt, err := deriveEncryptionKey(seedBytes)
	if err != nil {
		return nil, err
	}
	return &Key{
		SecretKey:  encrypt.SecretKey,
		PrivateKey: sign.PrivateKey,
		PublicKey:  sign.PublicKey,
	}, nil
}

// deriveSigningKey 从 48 字节 seed 派生签名密钥（PrivateKey + PublicKey）
func deriveSigningKey(seedBytes []byte) (Key, error) {
	seed, err := pasetokit.ParseSeed(seedBytes)
	if err != nil {
		return Key{}, err
	}
	sk, err := seed.DeriveSecretKey()
	if err != nil {
		return Key{}, fmt.Errorf("derive secret key: %w", err)
	}
	return Key{
		PrivateKey: sk.ExportBytes(),
		PublicKey:  sk.Public().ExportBytes(),
	}, nil
}

// deriveEncryptionKey 从 48 字节 seed 派生加密密钥（SecretKey）
func deriveEncryptionKey(seedBytes []byte) (Key, error) {
	seed, err := pasetokit.ParseSeed(seedBytes)
	if err != nil {
		return Key{}, err
	}
	symKey, err := seed.DeriveSymmetricKey()
	if err != nil {
		return Key{}, fmt.Errorf("derive symmetric key: %w", err)
	}
	return Key{SecretKey: symKey.ExportBytes()}, nil
}

func deriveSigningKeys(seeds [][]byte) (*Keys, error) {
	if len(seeds) == 0 {
		return nil, nil
	}
	all := make([]Key, 0, len(seeds))
	for i, s := range seeds {
		k, err := deriveSigningKey(s)
		if err != nil {
			return nil, fmt.Errorf("derive signing key[%d]: %w", i, err)
		}
		all = append(all, k)
	}
	return &Keys{Main: all[0], Keys: all}, nil
}

func deriveEncryptionKeys(seeds [][]byte) (*Keys, error) {
	if len(seeds) == 0 {
		return nil, nil
	}
	all := make([]Key, 0, len(seeds))
	for i, s := range seeds {
		k, err := deriveEncryptionKey(s)
		if err != nil {
			return nil, fmt.Errorf("derive encryption key[%d]: %w", i, err)
		}
		all = append(all, k)
	}
	return &Keys{Main: all[0], Keys: all}, nil
}

func DeriveDomainKeys(raw *models.DomainWithKey) (*DomainWithKey, error) {
	keys, err := deriveSigningKeys(raw.Keys)
	if err != nil {
		return nil, err
	}
	result := &DomainWithKey{Domain: raw.Domain}
	if keys != nil {
		result.Keys = *keys
	}
	return result, nil
}

func DeriveServiceKeys(raw *models.ServiceWithKey) (*ServiceWithKey, error) {
	keys, err := deriveEncryptionKeys(raw.Keys)
	if err != nil {
		return nil, err
	}
	result := &ServiceWithKey{Service: raw.Service}
	if keys != nil {
		result.Keys = *keys
	}
	return result, nil
}

func DeriveApplicationKeys(raw *models.ApplicationWithKey) (*ApplicationWithKey, error) {
	keys, err := deriveSigningKeys(raw.Keys)
	if err != nil {
		return nil, err
	}
	result := &ApplicationWithKey{Application: raw.Application}
	if keys != nil {
		result.Keys = *keys
	}
	return result, nil
}

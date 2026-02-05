package cache

import (
	"context"
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/dgraph-io/ristretto/v2"
	"golang.org/x/sync/singleflight"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/aegis/keys"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// 公钥缓存相关字段（在 Manager 中初始化）
var (
	pubKeySF singleflight.Group
)

// initPubKeyCache 初始化公钥缓存
func (cm *Manager) initPubKeyCache() {
	pubKeyCache, err := ristretto.NewCache(&ristretto.Config[string, *keys.KeyEntry]{
		NumCounters: config.GetAegisCacheNumCounters("pubkey"),
		MaxCost:     config.GetAegisCacheSize("pubkey"),
		BufferItems: config.GetAegisCacheBufferItems("pubkey"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 PubKey 缓存失败: %v", err)
	} else {
		cm.pubKeyCache = pubKeyCache
	}
}

// GetPublicKey 获取公钥（观察者模式：获取时检查过期并触发异步刷新）
// clientID 可以是应用 ID 或服务 ID
func (cm *Manager) GetPublicKey(ctx context.Context, clientID string) (paseto.V4AsymmetricPublicKey, error) {
	cacheKey := config.GetAegisCacheKeyPrefix("pubkey") + clientID

	// 1. 检查缓存
	if cm.pubKeyCache != nil {
		if entry, ok := cm.pubKeyCache.Get(cacheKey); ok {
			// 已过期 -> 阻塞获取
			if entry.IsExpired() {
				return cm.fetchPublicKey(ctx, clientID, cacheKey)
			}

			// 需要刷新 -> 异步刷新，返回旧值
			if entry.NeedsRefresh() {
				go cm.asyncRefreshPublicKey(clientID, cacheKey)
			}

			return entry.Key, nil
		}
	}

	// 2. 缓存未命中 -> 阻塞获取
	return cm.fetchPublicKey(ctx, clientID, cacheKey)
}

// fetchPublicKey 获取公钥（使用 singleflight 防止并发请求）
func (cm *Manager) fetchPublicKey(ctx context.Context, clientID, cacheKey string) (paseto.V4AsymmetricPublicKey, error) {
	result, err, _ := pubKeySF.Do(clientID, func() (interface{}, error) {
		// 1. 获取 Application
		app, err := cm.GetApplication(ctx, clientID)
		if err != nil {
			return nil, fmt.Errorf("get application: %w", err)
		}

		// 2. 获取域信息
		domain, err := cm.GetDomain(ctx, app.DomainID)
		if err != nil {
			return nil, fmt.Errorf("get domain: %w", err)
		}

		// 3. 从域密钥（32 字节 Ed25519 seed）直接解析公钥
		publicKey, err := keys.ParsePublicKeyFromSeed(domain.Main)
		if err != nil {
			return nil, fmt.Errorf("parse public key from seed: %w", err)
		}

		// 4. 更新缓存
		ttl := config.GetAegisCacheTTL("pubkey")
		now := time.Now()
		entry := &keys.KeyEntry{
			Key:       publicKey,
			ExpiresAt: now.Add(ttl),
			FetchedAt: now,
		}

		if cm.pubKeyCache != nil {
			cm.pubKeyCache.SetWithTTL(cacheKey, entry, 1, ttl)
		}

		return publicKey, nil
	})

	if err != nil {
		return paseto.V4AsymmetricPublicKey{}, err
	}

	publicKey, ok := result.(paseto.V4AsymmetricPublicKey)
	if !ok {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("unexpected type: %T", result)
	}
	return publicKey, nil
}

// asyncRefreshPublicKey 异步刷新公钥
func (cm *Manager) asyncRefreshPublicKey(clientID, cacheKey string) {
	// 使用 singleflight 防止重复刷新
	// 异步刷新场景下，错误已在内部记录日志，调用方不需要处理返回值
	_, err, _ := pubKeySF.Do("refresh:"+clientID, func() (interface{}, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := cm.fetchPublicKey(ctx, clientID, cacheKey)
		if err != nil {
			logger.Warnf("[Manager] 异步刷新公钥失败 clientID=%s: %v", clientID, err)
		}
		return nil, err
	})
	if err != nil {
		logger.Debugf("[Manager] 异步刷新公钥 singleflight 错误 clientID=%s: %v", clientID, err)
	}
}

// GetAllPublicKeys 获取所有有效公钥（用于验证轮换期间的 token）
// 返回主密钥和所有轮换中的旧密钥
func (cm *Manager) GetAllPublicKeys(ctx context.Context, clientID string) ([]paseto.V4AsymmetricPublicKey, error) {
	// 1. 获取 Application
	app, err := cm.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	// 2. 获取域信息
	domain, err := cm.GetDomain(ctx, app.DomainID)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}

	// 3. 从所有域密钥（32 字节 Ed25519 seed）直接解析公钥
	publicKeys := make([]paseto.V4AsymmetricPublicKey, 0, len(domain.Keys))
	for _, signKey := range domain.Keys {
		publicKey, err := keys.ParsePublicKeyFromSeed(signKey)
		if err != nil {
			logger.Warnf("[Manager] 解析公钥失败: %v", err)
			continue
		}
		publicKeys = append(publicKeys, publicKey)
	}

	return publicKeys, nil
}

// UpdatePublicKey 直接更新公钥缓存（供外部调用）
func (cm *Manager) UpdatePublicKey(clientID string, entry *keys.KeyEntry) {
	if cm.pubKeyCache == nil {
		return
	}

	cacheKey := config.GetAegisCacheKeyPrefix("pubkey") + clientID
	ttl := time.Until(entry.ExpiresAt)
	if ttl <= 0 {
		ttl = config.GetAegisCacheTTL("pubkey")
	}
	cm.pubKeyCache.SetWithTTL(cacheKey, entry, 1, ttl)
}

// InvalidatePublicKey 使公钥缓存失效
func (cm *Manager) InvalidatePublicKey(clientID string) {
	if cm.pubKeyCache == nil {
		return
	}

	cacheKey := config.GetAegisCacheKeyPrefix("pubkey") + clientID
	cm.pubKeyCache.Del(cacheKey)
}

package cache

import (
	"context"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// ==================== User（read-through 缓存）====================

// CacheUser 将用户写入本地缓存
func (cm *Manager) CacheUser(user *models.UserWithDecrypted) {
	if cm.userCache != nil && user != nil {
		cacheKey := config.GetAegisCacheKeyPrefix("user") + user.OpenID
		ttl := config.GetAegisCacheTTL("user")
		cm.userCache.SetWithTTL(cacheKey, user, 1, ttl)
	}
}

// GetUser 获取用户（带缓存）
func (cm *Manager) GetUser(ctx context.Context, openid string) (*models.UserWithDecrypted, error) {
	cacheKey := config.GetAegisCacheKeyPrefix("user") + openid

	// 尝试从缓存获取
	if cm.userCache != nil {
		if cached, ok := cm.userCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 UserService 获取
	result, err := cm.userSvc.GetUserWithDecrypted(ctx, openid)
	if err != nil {
		return nil, err
	}

	cm.CacheUser(result)
	return result, nil
}

// GetUserByIdentity 根据身份模型获取用户（带缓存）
func (cm *Manager) GetUserByIdentity(ctx context.Context, identity *models.UserIdentity) (*models.UserWithDecrypted, error) {
	result, err := cm.userSvc.GetUserWithDecryptedByIdentity(ctx, identity)
	if err != nil {
		return nil, err
	}

	cm.CacheUser(result)
	return result, nil
}

// InvalidateUser 清除用户缓存
func (cm *Manager) InvalidateUser(ctx context.Context, openid string) {
	if cm.userCache != nil {
		cacheKey := config.GetAegisCacheKeyPrefix("user") + openid
		cm.userCache.Del(cacheKey)
	}
}

// ==================== WebAuthn 凭证管理 ====================

// GetUserWebAuthnCredentials 获取用户的 WebAuthn 凭证列表
func (cm *Manager) GetUserWebAuthnCredentials(ctx context.Context, openid string) ([]*StoredWebAuthnCredential, error) {
	// 从数据库获取用户的 WebAuthn 类型凭证
	credentials, err := cm.userSvc.GetEnabledUserCredentialsByType(ctx, openid, string(models.CredentialTypeWebAuthn))
	if err != nil {
		return nil, err
	}

	// 转换为 StoredWebAuthnCredential
	result := make([]*StoredWebAuthnCredential, 0, len(credentials))
	for _, cred := range credentials {
		stored, err := ParseStoredWebAuthnCredential(&cred)
		if err != nil {
			continue // 跳过解析失败的凭证
		}
		result = append(result, stored)
	}

	return result, nil
}

// SaveUserWebAuthnCredential 保存用户的 WebAuthn 凭证
func (cm *Manager) SaveUserWebAuthnCredential(ctx context.Context, openid string, cred *StoredWebAuthnCredential) error {
	// 序列化凭证数据
	secretJSON, err := SerializeWebAuthnCredential(cred)
	if err != nil {
		return err
	}

	// 创建数据库凭证记录
	credentialID := EncodeCredentialID(cred.ID)
	dbCred := &models.UserCredential{
		OpenID:       openid,
		CredentialID: &credentialID,
		Type:         string(models.CredentialTypeWebAuthn),
		Secret:       secretJSON,
		Enabled:      true, // 默认启用
	}

	return cm.userSvc.CreateCredential(ctx, dbCred)
}

// UpdateWebAuthnCredentialSignCount 更新 WebAuthn 凭证签名计数
func (cm *Manager) UpdateWebAuthnCredentialSignCount(ctx context.Context, credentialID string, signCount uint32) error {
	return cm.userSvc.UpdateCredentialSignCount(ctx, credentialID, signCount)
}

// DeleteUserWebAuthnCredential 删除用户的 WebAuthn 凭证
func (cm *Manager) DeleteUserWebAuthnCredential(ctx context.Context, openid, credentialID string) error {
	return cm.userSvc.DeleteCredential(ctx, openid, credentialID)
}

// GetOpenIDByCredentialID 根据凭证 ID 获取用户 OpenID
func (cm *Manager) GetOpenIDByCredentialID(ctx context.Context, credentialID string) (string, error) {
	return cm.userSvc.GetOpenIDByCredentialID(ctx, credentialID)
}

package cache

import (
	"context"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// ==================== User（本地缓存 + DB）====================

// GetUser 获取用户（带缓存）
func (cm *Manager) GetUser(ctx context.Context, openID string) (*models.UserWithDecrypted, error) {
	cacheKey := config.GetAegisCacheKeyPrefix("user") + openID

	// 尝试从缓存获取
	if cm.userCache != nil {
		if cached, ok := cm.userCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 UserService 获取
	result, err := cm.userSvc.GetUserWithDecrypted(ctx, openID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.userCache != nil {
		ttl := config.GetAegisCacheTTL("user")
		cm.userCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetUserByIdentity 根据身份获取用户（带缓存）
func (cm *Manager) GetUserByIdentity(ctx context.Context, idp, providerID string) (*models.UserWithDecrypted, error) {
	// 先从 DB 查找（身份关联不缓存）
	result, err := cm.userSvc.GetUserWithDecryptedByIdentity(ctx, idp, providerID)
	if err != nil {
		return nil, err
	}

	// 存入用户缓存
	if cm.userCache != nil {
		cacheKey := config.GetAegisCacheKeyPrefix("user") + result.OpenID
		ttl := config.GetAegisCacheTTL("user")
		cm.userCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetUserIdentities 获取用户已绑定的身份类型列表
func (cm *Manager) GetUserIdentities(ctx context.Context, openID string) ([]string, error) {
	// 从 UserService 获取用户的身份绑定信息
	identities, err := cm.userSvc.GetIdentities(ctx, openID)
	if err != nil {
		return nil, err
	}

	// 提取 IDP 类型列表
	idpTypes := make([]string, 0, len(identities))
	for _, identity := range identities {
		idpTypes = append(idpTypes, identity.IDP)
	}
	return idpTypes, nil
}

// FindOrCreateUser 查找或创建用户
func (cm *Manager) FindOrCreateUser(ctx context.Context, req *models.FindOrCreateUserRequest) (*models.UserWithDecrypted, bool, error) {
	user, isNew, err := cm.userSvc.FindOrCreate(ctx, req)
	if err != nil {
		return nil, false, err
	}

	// 存入缓存
	if cm.userCache != nil {
		cacheKey := config.GetAegisCacheKeyPrefix("user") + user.OpenID
		ttl := config.GetAegisCacheTTL("user")
		cm.userCache.SetWithTTL(cacheKey, user, 1, ttl)
	}

	return user, isNew, nil
}

// InvalidateUser 清除用户缓存
func (cm *Manager) InvalidateUser(ctx context.Context, openID string) {
	if cm.userCache != nil {
		cacheKey := config.GetAegisCacheKeyPrefix("user") + openID
		cm.userCache.Del(cacheKey)
	}
}

// ==================== WebAuthn 凭证管理 ====================

// GetUserWebAuthnCredentials 获取用户的 WebAuthn 凭证列表
// 注意：这里返回的是 webauthn 包中定义的 StoredCredential 类型
// 需要在调用处进行类型转换
func (cm *Manager) GetUserWebAuthnCredentials(ctx context.Context, openID string) ([]*StoredWebAuthnCredential, error) {
	// 从数据库获取用户的 WebAuthn 类型凭证
	credentials, err := cm.userSvc.GetEnabledUserCredentialsByType(ctx, openID, string(models.CredentialTypeWebAuthn))
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
func (cm *Manager) SaveUserWebAuthnCredential(ctx context.Context, openID string, cred *StoredWebAuthnCredential) error {
	// 序列化凭证数据
	secretJSON, err := SerializeWebAuthnCredential(cred)
	if err != nil {
		return err
	}

	// 创建数据库凭证记录
	credentialID := EncodeCredentialID(cred.ID)
	dbCred := &models.UserCredential{
		OpenID:       openID,
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
func (cm *Manager) DeleteUserWebAuthnCredential(ctx context.Context, openID, credentialID string) error {
	return cm.userSvc.DeleteCredential(ctx, openID, credentialID)
}

// GetUserIDByCredentialID 根据凭证 ID 获取用户 OpenID
func (cm *Manager) GetUserIDByCredentialID(ctx context.Context, credentialID string) (string, error) {
	return cm.userSvc.GetUserIDByCredentialID(ctx, credentialID)
}

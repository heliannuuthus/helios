package keys

import (
	"context"

	"aidanwoods.dev/go-paseto"
)

// KeyProvider 密钥提供者接口
// 底层接口，返回原始密钥（string 类型，实际是 []byte 转换）
type KeyProvider interface {
	// AllOfKey 获取所有相关密钥（根据 id 获取该实体的所有密钥）
	AllOfKey(ctx context.Context, id string) (map[string]struct{}, error)

	// OneOfKey 获取单个密钥（取第一个）
	OneOfKey(ctx context.Context, id string) (string, error)
}

// KeyProviderFunc 函数式 KeyProvider（实现 AllOfKey）
type KeyProviderFunc func(ctx context.Context, id string) (map[string]struct{}, error)

// AllOfKey 实现 KeyProvider 接口
func (f KeyProviderFunc) AllOfKey(ctx context.Context, id string) (map[string]struct{}, error) {
	return f(ctx, id)
}

// OneOfKey 取第一个密钥
func (f KeyProviderFunc) OneOfKey(ctx context.Context, id string) (string, error) {
	keys, err := f(ctx, id)
	if err != nil {
		return "", err
	}
	for key := range keys {
		return key, nil
	}
	return "", ErrKeyNotFound
}

// PublicKeyProvider 公钥提供者接口
type PublicKeyProvider interface {
	Get(ctx context.Context, id string) (paseto.V4AsymmetricPublicKey, error)
}

// PublicKeyProviderFunc 函数式 PublicKeyProvider
type PublicKeyProviderFunc func(ctx context.Context, id string) (paseto.V4AsymmetricPublicKey, error)

// Get 实现 PublicKeyProvider 接口
func (f PublicKeyProviderFunc) Get(ctx context.Context, id string) (paseto.V4AsymmetricPublicKey, error) {
	return f(ctx, id)
}

// SecretKeyProvider 私钥提供者接口
type SecretKeyProvider interface {
	Get(ctx context.Context, id string) (paseto.V4AsymmetricSecretKey, error)
}

// SecretKeyProviderFunc 函数式 SecretKeyProvider
type SecretKeyProviderFunc func(ctx context.Context, id string) (paseto.V4AsymmetricSecretKey, error)

// Get 实现 SecretKeyProvider 接口
func (f SecretKeyProviderFunc) Get(ctx context.Context, id string) (paseto.V4AsymmetricSecretKey, error) {
	return f(ctx, id)
}

// SymmetricKeyProvider 对称密钥提供者接口
type SymmetricKeyProvider interface {
	Get(ctx context.Context, id string) (paseto.V4SymmetricKey, error)
}

// SymmetricKeyProviderFunc 函数式 SymmetricKeyProvider
type SymmetricKeyProviderFunc func(ctx context.Context, id string) (paseto.V4SymmetricKey, error)

// Get 实现 SymmetricKeyProvider 接口
func (f SymmetricKeyProviderFunc) Get(ctx context.Context, id string) (paseto.V4SymmetricKey, error) {
	return f(ctx, id)
}

// ==================== 工厂函数 ====================

// NewPublicKeyProvider 基于 KeyProvider 创建公钥提供者
// 从密钥字节派生 Ed25519 公钥（使用 Argon2id KDF）
func NewPublicKeyProvider(kp KeyProvider) PublicKeyProviderFunc {
	return func(ctx context.Context, id string) (paseto.V4AsymmetricPublicKey, error) {
		keyStr, err := kp.OneOfKey(ctx, id)
		if err != nil {
			return paseto.V4AsymmetricPublicKey{}, err
		}

		secretKey, err := DeriveSecretKey([]byte(keyStr))
		if err != nil {
			return paseto.V4AsymmetricPublicKey{}, err
		}

		return secretKey.Public(), nil
	}
}

// NewSecretKeyProvider 基于 KeyProvider 创建私钥提供者
// 从密钥字节派生 Ed25519 私钥（使用 Argon2id KDF）
func NewSecretKeyProvider(kp KeyProvider) SecretKeyProviderFunc {
	return func(ctx context.Context, id string) (paseto.V4AsymmetricSecretKey, error) {
		keyStr, err := kp.OneOfKey(ctx, id)
		if err != nil {
			return paseto.V4AsymmetricSecretKey{}, err
		}

		return DeriveSecretKey([]byte(keyStr))
	}
}

// NewSymmetricKeyProvider 基于 KeyProvider 创建对称密钥提供者
// 从密钥字节派生对称密钥（使用 Argon2id KDF）
func NewSymmetricKeyProvider(kp KeyProvider) SymmetricKeyProviderFunc {
	return func(ctx context.Context, id string) (paseto.V4SymmetricKey, error) {
		keyStr, err := kp.OneOfKey(ctx, id)
		if err != nil {
			return paseto.V4SymmetricKey{}, err
		}

		return DeriveSymmetricKey([]byte(keyStr))
	}
}

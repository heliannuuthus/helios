package token

import (
	"context"
	"fmt"
	"sync"

	"aidanwoods.dev/go-paseto"
)

// PublicKeyProvider 公钥提供者接口（用于验证签名）
type PublicKeyProvider interface {
	Get(ctx context.Context, keyID string) (paseto.V4AsymmetricPublicKey, error)
}

// PublicKeyProviderFunc 函数式 PublicKeyProvider
type PublicKeyProviderFunc func(ctx context.Context, keyID string) (paseto.V4AsymmetricPublicKey, error)

// Get 实现 PublicKeyProvider 接口
func (f PublicKeyProviderFunc) Get(ctx context.Context, keyID string) (paseto.V4AsymmetricPublicKey, error) {
	return f(ctx, keyID)
}

// SymmetricKeyProvider 对称密钥提供者接口（用于加解密 footer）
type SymmetricKeyProvider interface {
	Get(ctx context.Context, keyID string) (paseto.V4SymmetricKey, error)
}

// SymmetricKeyProviderFunc 函数式 SymmetricKeyProvider
type SymmetricKeyProviderFunc func(ctx context.Context, keyID string) (paseto.V4SymmetricKey, error)

// Get 实现 SymmetricKeyProvider 接口
func (f SymmetricKeyProviderFunc) Get(ctx context.Context, keyID string) (paseto.V4SymmetricKey, error) {
	return f(ctx, keyID)
}

// SecretKeyProvider 私钥提供者接口（用于签名）
type SecretKeyProvider interface {
	Get(ctx context.Context, keyID string) (paseto.V4AsymmetricSecretKey, error)
}

// SecretKeyProviderFunc 函数式 SecretKeyProvider
type SecretKeyProviderFunc func(ctx context.Context, keyID string) (paseto.V4AsymmetricSecretKey, error)

// Get 实现 SecretKeyProvider 接口
func (f SecretKeyProviderFunc) Get(ctx context.Context, keyID string) (paseto.V4AsymmetricSecretKey, error) {
	return f(ctx, keyID)
}

// HTTPPublicKeyProvider 基于 HTTP 接口的公钥提供者
// 从远程服务获取公钥（用于分布式场景）
type HTTPPublicKeyProvider struct {
	endpointFunc func() string // 动态获取 endpoint
	mu           sync.RWMutex
	cache        map[string]paseto.V4AsymmetricPublicKey
}

// NewHTTPPublicKeyProvider 创建 HTTP 公钥提供者
// endpointFunc: 动态获取 Auth 服务端点的函数（支持热更新）
func NewHTTPPublicKeyProvider(endpointFunc func() string) *HTTPPublicKeyProvider {
	return &HTTPPublicKeyProvider{
		endpointFunc: endpointFunc,
		cache:        make(map[string]paseto.V4AsymmetricPublicKey),
	}
}

// Get 获取公钥
// URL 固定为: {endpoint}/pubkeys?client_id={clientID}
func (p *HTTPPublicKeyProvider) Get(ctx context.Context, clientID string) (paseto.V4AsymmetricPublicKey, error) {
	// 1. 检查缓存
	p.mu.RLock()
	if key, ok := p.cache[clientID]; ok {
		p.mu.RUnlock()
		return key, nil
	}
	p.mu.RUnlock()

	// 2. 从远程获取（需要实现 HTTP 调用）
	// TODO: 实现 HTTP 调用获取公钥
	return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("HTTP public key fetch not implemented for client %s", clientID)
}

// CachePublicKey 缓存公钥（用于预加载或手动更新）
func (p *HTTPPublicKeyProvider) CachePublicKey(clientID string, publicKey paseto.V4AsymmetricPublicKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cache[clientID] = publicKey
}

// InvalidateCache 清除缓存
func (p *HTTPPublicKeyProvider) InvalidateCache(clientID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.cache, clientID)
}

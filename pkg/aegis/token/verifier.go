package token

import (
	"context"
	"fmt"
	"sync"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/heliannuuthus/helios/pkg/aegis/key"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Verifier 绑定特定 ID 的 Token 验证器
type Verifier struct {
	provider key.Provider
	id       string

	mu         sync.RWMutex
	publicKeys []paseto.V4AsymmetricPublicKey
}

// NewVerifier 创建绑定 ID 的 Verifier（懒加载模式）
func NewVerifier(provider key.Provider, id string) *Verifier {
	v := &Verifier{
		provider: provider,
		id:       id,
	}

	// 如果 provider 支持订阅，订阅密钥变更
	if sub, ok := provider.(key.Subscribable); ok {
		sub.Subscribe(id, func(newKeys [][]byte) {
			if err := v.updateKeys(newKeys); err != nil {
				logger.Warnf("[Verifier] update keys failed for %s: %v", id, err)
			}
		})
	}

	return v
}

// updateKeys 更新公钥（从原始 seed 派生）
func (v *Verifier) updateKeys(keys [][]byte) error {
	publicKeys := make([]paseto.V4AsymmetricPublicKey, 0, len(keys))
	for _, raw := range keys {
		seed, err := key.ParseSeed(raw)
		if err != nil {
			return fmt.Errorf("parse seed: %w", err)
		}
		pk, err := seed.DerivePublicKey()
		if err != nil {
			return fmt.Errorf("derive public key: %w", err)
		}
		publicKeys = append(publicKeys, pk)
	}

	v.mu.Lock()
	v.publicKeys = publicKeys
	v.mu.Unlock()

	return nil
}

// ensure 确保密钥已加载
func (v *Verifier) ensure(ctx context.Context) error {
	v.mu.RLock()
	hasKeys := len(v.publicKeys) > 0
	v.mu.RUnlock()

	if hasKeys {
		return nil
	}

	keys, err := v.provider.AllOfKey(ctx, v.id)
	if err != nil {
		return err
	}

	return v.updateKeys(keys)
}

// Verify 验证 token 签名，尝试所有公钥
func (v *Verifier) Verify(ctx context.Context, tokenString string, tokenType TokenType) (Token, error) {
	if err := v.ensure(ctx); err != nil {
		return nil, fmt.Errorf("load keys: %w", err)
	}

	v.mu.RLock()
	keys := v.publicKeys
	v.mu.RUnlock()

	if len(keys) == 0 {
		return nil, key.ErrNotFound
	}

	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	var lastErr error
	for _, pk := range keys {
		pasetoToken, err := parser.ParseV4Public(pk, tokenString, nil)
		if err == nil {
			return ParseToken(pasetoToken, tokenType)
		}
		lastErr = err
	}

	return nil, fmt.Errorf("signature verification failed: %w", lastErr)
}

// VerifyRaw 验证 token 签名，返回原始 paseto.Token
func (v *Verifier) VerifyRaw(ctx context.Context, tokenString string) (*paseto.Token, error) {
	if err := v.ensure(ctx); err != nil {
		return nil, fmt.Errorf("load keys: %w", err)
	}

	v.mu.RLock()
	keys := v.publicKeys
	v.mu.RUnlock()

	if len(keys) == 0 {
		return nil, key.ErrNotFound
	}

	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	var lastErr error
	for _, pk := range keys {
		pasetoToken, err := parser.ParseV4Public(pk, tokenString, nil)
		if err == nil {
			return pasetoToken, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("signature verification failed: %w", lastErr)
}

package key

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"aidanwoods.dev/go-paseto"
	"github.com/go-json-experiment/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// ErrDecryptFailed 解密失败错误
var ErrDecryptFailed = errors.New("decrypt failed")

// Cryptor 加解密器，持有派生后的对称密钥
type Cryptor struct {
	provider Provider
	id       string

	mu           sync.RWMutex
	symmetricKey paseto.V4SymmetricKey
}

// NewCryptor 创建 Cryptor（懒加载模式）
func NewCryptor(provider Provider, id string) *Cryptor {
	c := &Cryptor{
		provider: provider,
		id:       id,
	}

	// 如果 provider 支持订阅，订阅密钥变更
	if sub, ok := provider.(Subscribable); ok {
		sub.Subscribe(id, func(newKeys [][]byte) {
			if len(newKeys) > 0 {
				if err := c.updateKey(newKeys[0]); err != nil {
					logger.Warnf("[Cryptor] update key failed for %s: %v", id, err)
				}
			}
		})
	}

	return c
}

// updateKey 更新对称密钥（从原始 seed 派生）
func (c *Cryptor) updateKey(rawKey []byte) error {
	seed, err := ParseSeed(rawKey)
	if err != nil {
		return fmt.Errorf("parse seed: %w", err)
	}
	sk, err := seed.DeriveSymmetricKey()
	if err != nil {
		return fmt.Errorf("derive symmetric key: %w", err)
	}

	c.mu.Lock()
	c.symmetricKey = sk
	c.mu.Unlock()

	return nil
}

// ensure 确保密钥已加载
func (c *Cryptor) ensure(ctx context.Context) error {
	c.mu.RLock()
	hasKey := len(c.symmetricKey.ExportBytes()) > 0
	c.mu.RUnlock()

	if hasKey {
		return nil
	}

	rawKey, err := c.provider.OneOfKey(ctx, c.id)
	if err != nil {
		return err
	}

	return c.updateKey(rawKey)
}

// Encrypt 加密 payload，返回 PASETO local token
func (c *Cryptor) Encrypt(ctx context.Context, payload any) (string, error) {
	if err := c.ensure(ctx); err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}

	c.mu.RLock()
	sk := c.symmetricKey
	c.mu.RUnlock()

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}

	t, err := paseto.NewTokenFromClaimsJSON(data, nil)
	if err != nil {
		return "", fmt.Errorf("create token: %w", err)
	}

	return t.V4Encrypt(sk, nil), nil
}

// Decrypt 解密 PASETO local token，将 claims 解析到 dest
func (c *Cryptor) Decrypt(ctx context.Context, encrypted string, dest any) error {
	if err := c.ensure(ctx); err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	c.mu.RLock()
	sk := c.symmetricKey
	c.mu.RUnlock()

	parser := paseto.NewParser()
	t, err := parser.ParseV4Local(sk, encrypted, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}

	return t.Get("", dest)
}

// DecryptRaw 解密 PASETO local token，返回原始 paseto.Token
func (c *Cryptor) DecryptRaw(ctx context.Context, encrypted string) (*paseto.Token, error) {
	if err := c.ensure(ctx); err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}

	c.mu.RLock()
	sk := c.symmetricKey
	c.mu.RUnlock()

	parser := paseto.NewParser()
	return parser.ParseV4Local(sk, encrypted, nil)
}

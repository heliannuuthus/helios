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

// Issuer CAT 签发器（内部持有签名能力）
type Issuer struct {
	provider key.Provider
	id       string

	mu        sync.RWMutex
	secretKey paseto.V4AsymmetricSecretKey
}

// NewIssuer 创建 CAT 签发器（懒加载模式）
func NewIssuer(provider key.Provider, id string) *Issuer {
	i := &Issuer{
		provider: provider,
		id:       id,
	}

	// 如果 provider 支持订阅，订阅密钥变更
	if sub, ok := provider.(key.Subscribable); ok {
		sub.Subscribe(id, func(newKeys [][]byte) {
			if len(newKeys) > 0 {
				if err := i.updateKey(newKeys[0]); err != nil {
					logger.Warnf("[Issuer] update key failed for %s: %v", id, err)
				}
			}
		})
	}

	return i
}

// updateKey 更新私钥（从原始 seed 派生）
func (i *Issuer) updateKey(rawKey []byte) error {
	seed, err := key.ParseSeed(rawKey)
	if err != nil {
		return fmt.Errorf("parse seed: %w", err)
	}
	sk, err := seed.DeriveSecretKey()
	if err != nil {
		return fmt.Errorf("derive secret key: %w", err)
	}

	i.mu.Lock()
	i.secretKey = sk
	i.mu.Unlock()

	return nil
}

// ensure 确保密钥已加载
func (i *Issuer) ensure(ctx context.Context) error {
	i.mu.RLock()
	hasKey := len(i.secretKey.ExportBytes()) > 0
	i.mu.RUnlock()

	if hasKey {
		return nil
	}

	rawKey, err := i.provider.OneOfKey(ctx, i.id)
	if err != nil {
		return err
	}

	return i.updateKey(rawKey)
}

// sign 内部签名方法
func (i *Issuer) sign(ctx context.Context, token *paseto.Token) (string, error) {
	if err := i.ensure(ctx); err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}

	i.mu.RLock()
	sk := i.secretKey
	i.mu.RUnlock()

	return token.V4Sign(sk, nil), nil
}

// Issue 签发 CAT
func (i *Issuer) Issue(ctx context.Context) (string, error) {
	cat := NewClaimsBuilder().
		Issuer(i.id).
		ClientID(i.id).
		Audience("aegis").
		ExpiresIn(5 * time.Minute).
		Build(NewClientAccessTokenBuilder())

	pasetoToken, err := Build(cat)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	return i.sign(ctx, pasetoToken)
}

// IssueWithAudience 签发指定 audience 的 CAT
func (i *Issuer) IssueWithAudience(ctx context.Context, audience string, expiresIn time.Duration) (string, error) {
	cat := NewClaimsBuilder().
		Issuer(i.id).
		ClientID(i.id).
		Audience(audience).
		ExpiresIn(expiresIn).
		Build(NewClientAccessTokenBuilder())

	pasetoToken, err := Build(cat)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	return i.sign(ctx, pasetoToken)
}

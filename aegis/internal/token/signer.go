package token

import (
	"context"
	"fmt"
	"sync"

	"aidanwoods.dev/go-paseto"
	"github.com/heliannuuthus/helios/pkg/aegis/key"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Signer 签名器，持有派生后的私钥
type Signer struct {
	provider key.Provider
	id       string

	mu        sync.RWMutex
	secretKey paseto.V4AsymmetricSecretKey
}

// NewSigner 创建 Signer（懒加载模式）
func NewSigner(provider key.Provider, id string) *Signer {
	s := &Signer{
		provider: provider,
		id:       id,
	}

	// 如果 provider 支持订阅，订阅密钥变更
	if sub, ok := provider.(key.Subscribable); ok {
		sub.Subscribe(id, func(newKeys [][]byte) {
			if len(newKeys) > 0 {
				if err := s.updateKey(newKeys[0]); err != nil {
					logger.Warnf("[Signer] update key failed for %s: %v", id, err)
				}
			}
		})
	}

	return s
}

// updateKey 更新私钥（从原始 seed 派生）
func (s *Signer) updateKey(rawKey []byte) error {
	seed, err := key.ParseSeed(rawKey)
	if err != nil {
		return fmt.Errorf("parse seed: %w", err)
	}
	sk, err := seed.DeriveSecretKey()
	if err != nil {
		return fmt.Errorf("derive secret key: %w", err)
	}

	s.mu.Lock()
	s.secretKey = sk
	s.mu.Unlock()

	return nil
}

// ensure 确保密钥已加载
func (s *Signer) ensure(ctx context.Context) error {
	s.mu.RLock()
	hasKey := len(s.secretKey.ExportBytes()) > 0
	s.mu.RUnlock()

	if hasKey {
		return nil
	}

	rawKey, err := s.provider.OneOfKey(ctx, s.id)
	if err != nil {
		return err
	}

	return s.updateKey(rawKey)
}

// Sign 签名 token
func (s *Signer) Sign(ctx context.Context, token *paseto.Token, footer []byte) (string, error) {
	if err := s.ensure(ctx); err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}

	s.mu.RLock()
	sk := s.secretKey
	s.mu.RUnlock()

	return token.V4Sign(sk, footer), nil
}

// PublicKey 返回对应的公钥
func (s *Signer) PublicKey(ctx context.Context) (paseto.V4AsymmetricPublicKey, error) {
	if err := s.ensure(ctx); err != nil {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("load key: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.secretKey.Public(), nil
}

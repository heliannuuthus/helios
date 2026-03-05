package token

import (
	"context"
	"fmt"
	"sync"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
	pasetokit "github.com/heliannuuthus/helios/pkg/aegis/utils/paseto"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Verifier 验签 PASETO v4.public token。
// 嵌入 Extractor 获取 Provider、audience 和 ExtractKID 能力，
// 自身管理 per-clientID 的 typed key 缓存。
type Verifier struct {
	*extractor
	clientID string

	mu   sync.RWMutex
	keys map[string]paseto.V4AsymmetricPublicKey
}

func newVerifier(ext *extractor, clientID string) *Verifier {
	v := &Verifier{extractor: ext, clientID: clientID}

	if sub, ok := ext.Provider.(key.Subscribable); ok {
		sub.Subscribe(clientID, func(newKeys [][]byte) {
			if err := v.rebuild(newKeys); err != nil {
				logger.Warnf("[Verifier] rebuild keys failed for %s: %v", clientID, err)
			}
		})
	}

	return v
}

func (v *Verifier) Verify(ctx context.Context, tokenString string) (*paseto.Token, error) {
	kid, err := v.ExtractKID(tokenString)
	if err != nil {
		return nil, fmt.Errorf("extract kid: %w", err)
	}

	if err := v.ensure(ctx); err != nil {
		return nil, err
	}

	v.mu.RLock()
	pk, ok := v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", pasetokit.ErrKIDNotFound, kid)
	}

	parser := paseto.NewParser()
	parser.AddRule(paseto.ValidAt(time.Now()))
	if v.audience != "" {
		parser.AddRule(paseto.ForAudience(v.audience))
	}

	pasetoToken, err := parser.ParseV4Public(pk, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return pasetoToken, nil
}

func (v *Verifier) ensure(ctx context.Context) error {
	v.mu.RLock()
	hasKeys := len(v.keys) > 0
	v.mu.RUnlock()
	if hasKeys {
		return nil
	}

	rawKeys, err := v.AllOfKey(ctx, v.clientID)
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}
	return v.rebuild(rawKeys)
}

func (v *Verifier) rebuild(rawKeys [][]byte) error {
	m := make(map[string]paseto.V4AsymmetricPublicKey, len(rawKeys))
	for _, raw := range rawKeys {
		pk, err := paseto.NewV4AsymmetricPublicKeyFromBytes(raw)
		if err != nil {
			return fmt.Errorf("parse public key: %w", err)
		}
		pid, err := pasetokit.ComputePID(pk)
		if err != nil {
			return fmt.Errorf("compute pid: %w", err)
		}
		m[pid] = pk
	}

	v.mu.Lock()
	v.keys = m
	v.mu.Unlock()

	return nil
}

package token

import (
	"context"
	"fmt"
	"sync"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
	pasetokit "github.com/heliannuuthus/helios/pkg/aegis/utils/paseto"
	"github.com/heliannuuthus/helios/pkg/logger"
)

var ErrDecryptFailed = pasetokit.ErrDecryptFailed

// Decryptor decrypts v4.local tokens using lid-based key matching.
// 内部缓存 lid → symmetric key 映射，通过 watcher 通知 rebuild。
// 嵌入 extractor 以管理关联的 Verifier 实例。
type Decryptor struct {
	*Extractor

	provider key.Provider

	mu   sync.RWMutex
	keys map[string]paseto.V4SymmetricKey
}

func NewDecryptor(extractor *Extractor, encryptKeyProvider key.Provider) *Decryptor {
	d := &Decryptor{
		Extractor: extractor,
		provider:  encryptKeyProvider,
	}

	if encryptKeyProvider != nil {
		if sub, ok := encryptKeyProvider.(key.Subscribable); ok {
			sub.Subscribe(d.id, func(newKeys [][]byte) {
				if err := d.rebuild(newKeys); err != nil {
					logger.Warnf("[Decryptor] rebuild keys failed for %s: %v", d.id, err)
				}
			})
		}
	}

	return d
}

func (d *Decryptor) Decrypt(ctx context.Context, encrypted string) (*paseto.Token, error) {
	kid, err := pasetokit.ExtractKID(encrypted)
	if err != nil {
		return nil, fmt.Errorf("extract kid: %w", err)
	}

	if err := d.ensure(ctx); err != nil {
		return nil, err
	}

	d.mu.RLock()
	sk, ok := d.keys[kid]
	d.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", pasetokit.ErrKIDNotFound, kid)
	}

	parser := paseto.NewParserWithoutExpiryCheck()
	t, err := parser.ParseV4Local(sk, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt inner token: %w", err)
	}

	return t, nil
}

func (d *Decryptor) ensure(ctx context.Context) error {
	d.mu.RLock()
	hasKeys := len(d.keys) > 0
	d.mu.RUnlock()
	if hasKeys {
		return nil
	}

	rawKeys, err := d.provider.AllOfKey(ctx, d.id)
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}
	return d.rebuild(rawKeys)
}

func (d *Decryptor) rebuild(rawKeys [][]byte) error {
	m := make(map[string]paseto.V4SymmetricKey, len(rawKeys))
	for _, raw := range rawKeys {
		sk, err := paseto.V4SymmetricKeyFromBytes(raw)
		if err != nil {
			return fmt.Errorf("parse symmetric key: %w", err)
		}
		lid, err := pasetokit.ComputeLID(sk)
		if err != nil {
			return fmt.Errorf("compute lid: %w", err)
		}
		m[lid] = sk
	}

	d.mu.Lock()
	d.keys = m
	d.mu.Unlock()

	return nil
}

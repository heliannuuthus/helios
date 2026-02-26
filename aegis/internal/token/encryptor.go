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

// Encryptor encrypts and decrypts data using PASETO v4.local with kid support.
// It holds a derived symmetric key and its precomputed PASERK lid.
type Encryptor struct {
	provider key.Provider
	id       string

	mu           sync.RWMutex
	symmetricKey paseto.V4SymmetricKey
	lid          string // precomputed PASERK lid
}

func NewEncryptor(provider key.Provider, id string) *Encryptor {
	e := &Encryptor{
		provider: provider,
		id:       id,
	}

	if sub, ok := provider.(key.Subscribable); ok {
		sub.Subscribe(id, func(newKeys [][]byte) {
			if len(newKeys) > 0 {
				if err := e.updateKey(newKeys[0]); err != nil {
					logger.Warnf("[Encryptor] update key failed for %s: %v", id, err)
				}
			}
		})
	}

	return e
}

func (e *Encryptor) updateKey(rawKey []byte) error {
	seed, err := pasetokit.ParseSeed(rawKey)
	if err != nil {
		return fmt.Errorf("parse seed: %w", err)
	}
	sk, err := seed.DeriveSymmetricKey()
	if err != nil {
		return fmt.Errorf("derive symmetric key: %w", err)
	}

	lid, err := pasetokit.ComputeLID(sk)
	if err != nil {
		return fmt.Errorf("compute lid: %w", err)
	}

	e.mu.Lock()
	e.symmetricKey = sk
	e.lid = lid
	e.mu.Unlock()

	return nil
}

func (e *Encryptor) ensure(ctx context.Context) error {
	e.mu.RLock()
	hasKey := e.lid != ""
	e.mu.RUnlock()

	if hasKey {
		return nil
	}

	rawKey, err := e.provider.OneOfKey(ctx, e.id)
	if err != nil {
		return err
	}

	return e.updateKey(rawKey)
}

func (e *Encryptor) Encrypt(ctx context.Context, payload []byte) (string, error) {
	if err := e.ensure(ctx); err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}

	e.mu.RLock()
	sk := e.symmetricKey
	lid := e.lid
	e.mu.RUnlock()

	t, err := paseto.NewTokenFromClaimsJSON(payload, nil)
	if err != nil {
		return "", fmt.Errorf("create inner token: %w", err)
	}
	footerBytes, err := pasetokit.NewFooter(lid).Marshal()
	if err != nil {
		return "", fmt.Errorf("marshal inner footer: %w", err)
	}
	return t.V4Encrypt(sk, footerBytes), nil
}

// GetLID returns the current PASERK lid.
func (e *Encryptor) GetLID(ctx context.Context) (string, error) {
	if err := e.ensure(ctx); err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lid, nil
}

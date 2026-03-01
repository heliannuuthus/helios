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

// Decryptor decrypts the encrypted sub field (v4.local token).
// It holds a symmetric key and its precomputed PASERK lid.
type Decryptor struct {
	provider key.Provider
	id       string

	mu           sync.RWMutex
	symmetricKey paseto.V4SymmetricKey
	lid          string
}

func NewDecryptor(provider key.Provider, id string) *Decryptor {
	d := &Decryptor{
		provider: provider,
		id:       id,
	}

	if sub, ok := provider.(key.Subscribable); ok {
		sub.Subscribe(id, func(newKeys [][]byte) {
			if len(newKeys) > 0 {
				if err := d.updateKey(newKeys[0]); err != nil {
					logger.Warnf("[Decryptor] update key failed for %s: %v", id, err)
				}
			}
		})
	}

	return d
}

func (d *Decryptor) updateKey(rawKey []byte) error {
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

	d.mu.Lock()
	d.symmetricKey = sk
	d.lid = lid
	d.mu.Unlock()

	return nil
}

func (d *Decryptor) ensure(ctx context.Context) error {
	d.mu.RLock()
	hasKey := d.lid != ""
	d.mu.RUnlock()

	if hasKey {
		return nil
	}

	rawKey, err := d.provider.OneOfKey(ctx, d.id)
	if err != nil {
		return err
	}

	return d.updateKey(rawKey)
}

func (d *Decryptor) Decrypt(ctx context.Context, encrypted string) ([]byte, error) {
	if err := d.ensure(ctx); err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}

	d.mu.RLock()
	sk := d.symmetricKey
	d.mu.RUnlock()

	parser := paseto.NewParserWithoutExpiryCheck()
	t, err := parser.ParseV4Local(sk, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt inner token: %w", err)
	}

	return t.ClaimsJSON(), nil
}

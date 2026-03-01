package token

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
	pasetokit "github.com/heliannuuthus/helios/pkg/aegis/utils/paseto"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// keyEntry holds a derived public key alongside its precomputed PASERK pid.
type keyEntry struct {
	pid       string
	publicKey paseto.V4AsymmetricPublicKey
}

// Verifier verifies PASETO v4.public tokens using kid-based key matching.
// It extracts the kid (k4.pid) from the token footer and matches it against
// precomputed pids derived from all available seeds.
type Verifier struct {
	provider key.Provider
	id       string

	mu   sync.RWMutex
	keys []keyEntry
}

func NewVerifier(provider key.Provider, id string) *Verifier {
	v := &Verifier{
		provider: provider,
		id:       id,
	}

	if sub, ok := provider.(key.Subscribable); ok {
		sub.Subscribe(id, func(newKeys [][]byte) {
			if err := v.updateKeys(newKeys); err != nil {
				logger.Warnf("[Verifier] update keys failed for %s: %v", id, err)
			}
		})
	}

	return v
}

func (v *Verifier) updateKeys(rawKeys [][]byte) error {
	entries := make([]keyEntry, 0, len(rawKeys))
	for i, raw := range rawKeys {
		seed, err := pasetokit.ParseSeed(raw)
		if err != nil {
			return fmt.Errorf("parse seed: %w", err)
		}
		pk, err := seed.DerivePublicKey()
		if err != nil {
			return fmt.Errorf("derive public key: %w", err)
		}
		pid, err := pasetokit.ComputePID(pk)
		if err != nil {
			return fmt.Errorf("compute pid: %w", err)
		}
		logger.Debugf("[Verifier] updateKeys id=%s, key[%d] len=%d, salt_hex=%x, derived pid=%s", v.id, i, len(raw), raw[:16], pid)
		entries = append(entries, keyEntry{pid: pid, publicKey: pk})
	}

	v.mu.Lock()
	v.keys = entries
	v.mu.Unlock()

	return nil
}

func (v *Verifier) ensure(ctx context.Context) error {
	v.mu.RLock()
	hasKeys := len(v.keys) > 0
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

// findKeyByKID finds the public key matching the given kid.
// Returns the key and nil error if found, or ErrKIDNotFound if no match.
func (v *Verifier) findKeyByKID(kid string) (paseto.V4AsymmetricPublicKey, error) {
	v.mu.RLock()
	entries := v.keys
	v.mu.RUnlock()

	for _, e := range entries {
		if subtle.ConstantTimeCompare([]byte(e.pid), []byte(kid)) == 1 {
			return e.publicKey, nil
		}
	}
	return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("%w: %s", pasetokit.ErrKIDNotFound, kid)
}

// Verify verifies the token signature and returns the raw paseto.Token.
// It extracts the kid from the footer, matches it against known keys,
// and uses the matched key for signature verification.
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*paseto.Token, error) {
	if err := v.ensure(ctx); err != nil {
		return nil, fmt.Errorf("load keys: %w", err)
	}

	kid, err := pasetokit.ExtractKID(tokenString)
	if err != nil {
		return nil, fmt.Errorf("extract kid: %w", err)
	}

	v.mu.RLock()
	knownPIDs := make([]string, len(v.keys))
	for i, e := range v.keys {
		knownPIDs[i] = e.pid
	}
	v.mu.RUnlock()
	logger.Debugf("[Verifier] id=%s, token kid=%s, known pids=%v", v.id, kid, knownPIDs)

	pk, err := v.findKeyByKID(kid)
	if err != nil {
		return nil, fmt.Errorf("find key: %w", err)
	}

	parser := paseto.NewParser()
	parser.AddRule(paseto.ValidAt(time.Now()))

	pasetoToken, err := parser.ParseV4Public(pk, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	return pasetoToken, nil
}


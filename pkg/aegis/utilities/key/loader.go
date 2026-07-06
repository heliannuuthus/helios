package key

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sync"

	pasetokit "github.com/heliannuuthus/pkg/aegis/utilities/paseto"
)

type derivedEntry struct {
	raw     []byte
	derived []byte
}

type derivedProvider struct {
	source  Provider
	purpose string
	inner   func(pasetokit.Seed) ([]byte, error)

	mu    sync.RWMutex
	cache []derivedEntry
}

func EncryptKeyProvider(source Provider) Provider {
	return &derivedProvider{
		source:  source,
		purpose: pasetokit.PurposeEncrypt,
		inner: func(s pasetokit.Seed) ([]byte, error) {
			sk, err := s.DeriveSymmetricKey()
			if err != nil {
				return nil, err
			}
			return sk.ExportBytes(), nil
		},
	}
}

func SignKeyProvider(source Provider) Provider {
	return &derivedProvider{
		source:  source,
		purpose: pasetokit.PurposeSign,
		inner: func(s pasetokit.Seed) ([]byte, error) {
			sk, err := s.DeriveSecretKey()
			if err != nil {
				return nil, err
			}
			return sk.ExportBytes(), nil
		},
	}
}

func (dp *derivedProvider) OneOfKey(ctx context.Context, id string) ([]byte, error) {
	raw, err := dp.source.OneOfKey(ctx, id)
	if err != nil {
		return nil, err
	}
	return dp.deriveKey(raw)
}

func (dp *derivedProvider) AllOfKey(ctx context.Context, id string) ([][]byte, error) {
	raws, err := dp.source.AllOfKey(ctx, id)
	if err != nil {
		return nil, err
	}
	result := make([][]byte, 0, len(raws))
	for _, raw := range raws {
		derived, err := dp.deriveKey(raw)
		if err != nil {
			return nil, err
		}
		result = append(result, derived)
	}
	return result, nil
}

func (dp *derivedProvider) deriveKey(raw []byte) ([]byte, error) {
	if cached := dp.lookup(raw); cached != nil {
		return cached, nil
	}
	seed, err := pasetokit.ParseSeed(raw)
	if err != nil {
		return nil, fmt.Errorf("parse seed for %s: %w", dp.purpose, err)
	}
	derived, err := dp.inner(seed)
	if err != nil {
		return nil, err
	}
	dp.store(raw, derived)
	return derived, nil
}

func (dp *derivedProvider) lookup(raw []byte) []byte {
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	for _, e := range dp.cache {
		if subtle.ConstantTimeCompare(e.raw, raw) == 1 {
			return e.derived
		}
	}
	return nil
}

func (dp *derivedProvider) store(raw, derived []byte) {
	rawCopy := make([]byte, len(raw))
	copy(rawCopy, raw)

	dp.mu.Lock()
	defer dp.mu.Unlock()

	for _, e := range dp.cache {
		if subtle.ConstantTimeCompare(e.raw, raw) == 1 {
			return
		}
	}
	dp.cache = append(dp.cache, derivedEntry{raw: rawCopy, derived: derived})
}

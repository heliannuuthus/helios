package key

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"

	pasetokit "github.com/heliannuuthus/helios/pkg/aegis/utils/paseto"
)

type derivedEntry struct {
	raw     []byte
	derived []byte
}

// SeedProvider 从 seed 加载函数创建的 Provider，支持按 purpose 派生密钥。
type SeedProvider struct {
	single  func(ctx context.Context, id string) ([]byte, error)
	multi   func(ctx context.Context, id string) ([][]byte, error)
	purpose string
	derive  func(pasetokit.Seed) ([]byte, error)

	mu    sync.RWMutex
	cache []derivedEntry
}

// SingleOf 从单密钥加载函数创建 Provider。
func SingleOf(fn func(ctx context.Context, id string) ([]byte, error)) *SeedProvider {
	return &SeedProvider{single: fn}
}

// MultiOf 从多密钥加载函数创建 Provider。
func MultiOf(fn func(ctx context.Context, id string) ([][]byte, error)) *SeedProvider {
	return &SeedProvider{multi: fn}
}

// Encrypt 返回派生 symmetric key（用于加解密）的新 Provider。
func (dp *SeedProvider) Encrypt() *SeedProvider {
	return &SeedProvider{
		single:  dp.single,
		multi:   dp.multi,
		purpose: pasetokit.PurposeEncrypt,
		derive: func(s pasetokit.Seed) ([]byte, error) {
			sk, err := s.DeriveSymmetricKey()
			if err != nil {
				return nil, err
			}
			return sk.ExportBytes(), nil
		},
	}
}

// Sign 返回派生 secret key（用于签名）的新 Provider。
func (dp *SeedProvider) Sign() *SeedProvider {
	return &SeedProvider{
		single:  dp.single,
		multi:   dp.multi,
		purpose: pasetokit.PurposeSign,
		derive: func(s pasetokit.Seed) ([]byte, error) {
			sk, err := s.DeriveSecretKey()
			if err != nil {
				return nil, err
			}
			return sk.ExportBytes(), nil
		},
	}
}

var errNoKeySource = errors.New("key: no key source configured")

func (dp *SeedProvider) OneOfKey(ctx context.Context, id string) ([]byte, error) {
	if dp.single != nil {
		raw, err := dp.single(ctx, id)
		if err != nil {
			return nil, err
		}
		return dp.maybeDerive(raw)
	}
	if dp.multi != nil {
		keys, err := dp.AllOfKey(ctx, id)
		if err != nil {
			return nil, err
		}
		if len(keys) == 0 {
			return nil, ErrNotFound
		}
		return keys[0], nil
	}
	return nil, errNoKeySource
}

func (dp *SeedProvider) AllOfKey(ctx context.Context, id string) ([][]byte, error) {
	if dp.multi != nil {
		raws, err := dp.multi(ctx, id)
		if err != nil {
			return nil, err
		}
		result := make([][]byte, 0, len(raws))
		for _, raw := range raws {
			derived, err := dp.maybeDerive(raw)
			if err != nil {
				return nil, err
			}
			result = append(result, derived)
		}
		return result, nil
	}
	if dp.single != nil {
		raw, err := dp.single(ctx, id)
		if err != nil {
			return nil, err
		}
		derived, err := dp.maybeDerive(raw)
		if err != nil {
			return nil, err
		}
		return [][]byte{derived}, nil
	}
	return nil, errNoKeySource
}

func (dp *SeedProvider) maybeDerive(raw []byte) ([]byte, error) {
	if dp.derive == nil {
		return raw, nil
	}
	if cached := dp.lookup(raw); cached != nil {
		return cached, nil
	}
	seed, err := pasetokit.ParseSeed(raw)
	if err != nil {
		return nil, fmt.Errorf("parse seed for %s: %w", dp.purpose, err)
	}
	derived, err := dp.derive(seed)
	if err != nil {
		return nil, err
	}
	dp.store(raw, derived)
	return derived, nil
}

func (dp *SeedProvider) lookup(raw []byte) []byte {
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	for _, e := range dp.cache {
		if subtle.ConstantTimeCompare(e.raw, raw) == 1 {
			return e.derived
		}
	}
	return nil
}

func (dp *SeedProvider) store(raw, derived []byte) {
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

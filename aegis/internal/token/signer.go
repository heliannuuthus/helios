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

// Signer signs PASETO v4.public tokens with kid footer.
type Signer struct {
	provider key.Provider
	id       string

	mu        sync.RWMutex
	secretKey paseto.V4AsymmetricSecretKey
	pid       string // precomputed PASERK pid
}

func NewSigner(provider key.Provider, id string) *Signer {
	s := &Signer{
		provider: provider,
		id:       id,
	}

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

func (s *Signer) updateKey(rawKey []byte) error {
	seed, err := pasetokit.ParseSeed(rawKey)
	if err != nil {
		return fmt.Errorf("parse seed: %w", err)
	}
	sk, err := seed.DeriveSecretKey()
	if err != nil {
		return fmt.Errorf("derive secret key: %w", err)
	}

	pid, err := pasetokit.ComputePID(sk.Public())
	if err != nil {
		return fmt.Errorf("compute pid: %w", err)
	}

	logger.Debugf("[Signer] updateKey id=%s, key len=%d, salt_hex=%x, derived pid=%s", s.id, len(rawKey), rawKey[:16], pid)

	s.mu.Lock()
	s.secretKey = sk
	s.pid = pid
	s.mu.Unlock()

	return nil
}

func (s *Signer) ensure(ctx context.Context) error {
	s.mu.RLock()
	hasKey := s.pid != ""
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

// Sign signs the token and includes the kid in the footer.
func (s *Signer) Sign(ctx context.Context, token *paseto.Token) (string, error) {
	if err := s.ensure(ctx); err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}

	s.mu.RLock()
	sk := s.secretKey
	pid := s.pid
	s.mu.RUnlock()

	footer, err := pasetokit.NewFooter(pid).Marshal()
	if err != nil {
		return "", fmt.Errorf("marshal footer: %w", err)
	}

	token.SetFooter(footer)
	logger.Debugf("[Signer] signing token for id=%s with pid=%s", s.id, pid)
	return token.V4Sign(sk, nil), nil
}

// GetPID returns the current PASERK pid.
func (s *Signer) GetPID(ctx context.Context) (string, error) {
	if err := s.ensure(ctx); err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pid, nil
}

// PublicKey returns the corresponding public key.
func (s *Signer) PublicKey(ctx context.Context) (paseto.V4AsymmetricPublicKey, error) {
	if err := s.ensure(ctx); err != nil {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("load key: %w", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.secretKey.Public(), nil
}

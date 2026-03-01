package token

import (
	"context"
	"fmt"
	"sync"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
	pasetokit "github.com/heliannuuthus/helios/pkg/aegis/utils/paseto"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Issuer signs PASETO v4.public tokens with kid in the footer.
// Used by applications to issue CAT (Client Access Tokens).
type Issuer struct {
	provider key.Provider
	id       string

	mu        sync.RWMutex
	secretKey paseto.V4AsymmetricSecretKey
	pid       string // precomputed PASERK pid for the current key
}

func NewIssuer(provider key.Provider, id string) *Issuer {
	i := &Issuer{
		provider: provider,
		id:       id,
	}

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

func (i *Issuer) updateKey(rawKey []byte) error {
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

	i.mu.Lock()
	i.secretKey = sk
	i.pid = pid
	i.mu.Unlock()

	return nil
}

func (i *Issuer) ensure(ctx context.Context) error {
	i.mu.RLock()
	hasKey := i.pid != ""
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

// sign signs the token with the current key and includes the kid footer.
func (i *Issuer) sign(ctx context.Context, token *paseto.Token) (string, error) {
	if err := i.ensure(ctx); err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}

	i.mu.RLock()
	sk := i.secretKey
	pid := i.pid
	i.mu.RUnlock()

	footer, err := pasetokit.NewFooter(pid).Marshal()
	if err != nil {
		return "", fmt.Errorf("marshal footer: %w", err)
	}

	token.SetFooter(footer)
	return token.V4Sign(sk, nil), nil
}

// Issue issues a default CAT token.
func (i *Issuer) Issue(ctx context.Context) (string, error) {
	cat := tokendef.NewClaimsBuilder().
		Issuer(i.id).
		ClientID(i.id).
		Audience("aegis").
		ExpiresIn(5 * time.Minute).
		Build(tokendef.NewClientAccessTokenBuilder())

	pasetoToken, err := tokendef.Build(cat)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	return i.sign(ctx, pasetoToken)
}

// IssueWithAudience issues a CAT token with a specific audience and expiry.
func (i *Issuer) IssueWithAudience(ctx context.Context, audience string, expiresIn time.Duration) (string, error) {
	cat := tokendef.NewClaimsBuilder().
		Issuer(i.id).
		ClientID(i.id).
		Audience(audience).
		ExpiresIn(expiresIn).
		Build(tokendef.NewClientAccessTokenBuilder())

	pasetoToken, err := tokendef.Build(cat)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	return i.sign(ctx, pasetoToken)
}

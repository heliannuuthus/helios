package issuer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/pkg/aegis/utilities/key"
	pasetokit "github.com/heliannuuthus/pkg/aegis/utilities/paseto"
	tokendef "github.com/heliannuuthus/pkg/aegis/utilities/token"
)

// Issuer signs PASETO v4.public tokens with kid in the footer.
// 绑定单个 id，内部懒加载并缓存该 id 对应的签名密钥。
type Issuer struct {
	provider key.Provider
	id       string

	mu        sync.RWMutex
	secretKey paseto.V4AsymmetricSecretKey
	pid       string
}

func NewIssuer(provider key.Provider, id string) *Issuer {
	i := &Issuer{provider: provider, id: id}

	if sub, ok := provider.(key.Subscribable); ok {
		sub.Subscribe(id, func(newKeys [][]byte) {
			if len(newKeys) > 0 {
				if err := i.updateKey(newKeys[0]); err != nil {
					slog.Warn("[Issuer] update key failed", "id", id, "error", err)
				}
			}
		})
	}

	return i
}

// Issue issues a CT token with the bound id.
func (i *Issuer) Issue(ctx context.Context) (string, error) {
	ct := tokendef.NewClaimsBuilder().
		Issuer(i.id).
		ClientID(i.id).
		Audience("aegis").
		ExpiresIn(5 * time.Minute).
		Build(tokendef.NewClientTokenBuilder())

	pasetoToken, err := tokendef.Build(ct)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	return i.sign(ctx, pasetoToken)
}

func (i *Issuer) updateKey(rawKey []byte) error {
	sk, err := paseto.NewV4AsymmetricSecretKeyFromBytes(rawKey)
	if err != nil {
		return fmt.Errorf("parse secret key: %w", err)
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
	loaded := i.pid != ""
	i.mu.RUnlock()
	if loaded {
		return nil
	}

	rawKey, err := i.provider.OneOfKey(ctx, i.id)
	if err != nil {
		return err
	}

	return i.updateKey(rawKey)
}

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

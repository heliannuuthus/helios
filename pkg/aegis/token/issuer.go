package token

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Issuer CAT 签发器
// 用于客户端签发 ClientAccessToken
type Issuer struct {
	keyProvider SecretKeyProvider
}

// NewIssuer 创建 CAT 签发器
func NewIssuer(keyProvider SecretKeyProvider) *Issuer {
	return &Issuer{
		keyProvider: keyProvider,
	}
}

// Issue 签发 CAT
// clientID: 应用/服务 ID
func (i *Issuer) Issue(ctx context.Context, clientID string) (string, error) {
	secretKey, err := i.keyProvider.Get(ctx, clientID)
	if err != nil {
		return "", fmt.Errorf("get signing key: %w", err)
	}

	cat := NewClientAccessToken(clientID, clientID, "aegis", 5*time.Minute)

	pasetoToken, err := cat.build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}
	pasetoToken.SetJti(uuid.New().String())

	return pasetoToken.V4Sign(secretKey, nil), nil
}

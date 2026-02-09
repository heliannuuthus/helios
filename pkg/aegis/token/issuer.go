// Package token 定义 PASETO Token 类型和接口
package token

import (
	"context"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/pkg/aegis/keys"
)

// Issuer CAT 签发器
// 用于客户端签发 ClientAccessToken
type Issuer struct {
	keyProvider keys.SecretKeyProvider
}

// NewIssuer 创建 CAT 签发器
func NewIssuer(keyProvider keys.SecretKeyProvider) *Issuer {
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

	cat := NewClaimsBuilder().
		Issuer(clientID).
		ClientID(clientID).
		Audience("aegis").
		ExpiresIn(5 * time.Minute).
		Build(NewClientAccessTokenBuilder())

	pasetoToken, err := Build(cat)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	return pasetoToken.V4Sign(secretKey, nil), nil
}

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
// clientID: 应用/服务 ID（调用时传入）
func (i *Issuer) Issue(ctx context.Context, clientID string) (string, error) {
	// 获取私钥
	secretKey, err := i.keyProvider.Get(ctx, clientID)
	if err != nil {
		return "", fmt.Errorf("get signing key: %w", err)
	}

	// 构建 PASETO Token
	cat := NewClientAccessToken(
		clientID, // issuer = clientID
		clientID, // sub = clientID
		"aegis",  // aud = aegis
		5*time.Minute,
	)

	// 设置 JTI
	token, err := cat.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}
	token.SetJti(uuid.New().String())

	// 签名（无 footer）
	signed := token.V4Sign(secretKey, nil)

	return signed, nil
}

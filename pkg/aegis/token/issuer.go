package token

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// issuer CAT 签发器（内部使用）
type issuer struct {
	keyProvider KeyProvider
}

// newIssuer 创建 CAT 签发器（内部使用）
func newIssuer(keyProvider KeyProvider) *issuer {
	return &issuer{
		keyProvider: keyProvider,
	}
}

// issue 签发 CAT
// clientID: 应用/服务 ID（调用时传入）
func (i *issuer) issue(ctx context.Context, clientID string) (string, error) {
	// 获取私钥
	key, err := i.keyProvider.Get(ctx, clientID)
	if err != nil {
		return "", fmt.Errorf("get signing key: %w", err)
	}

	// 构建 JWT
	now := time.Now()
	token, err := jwt.NewBuilder().
		Subject(clientID).
		Audience([]string{"aegis"}).
		IssuedAt(now).
		Expiration(now.Add(5 * time.Minute)).
		JwtID(uuid.New().String()).
		Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 签名
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.HS256(), key))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

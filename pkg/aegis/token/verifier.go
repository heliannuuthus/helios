// Package token 定义 PASETO Token 类型和接口
package token

import (
	"context"
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/pkg/aegis/keys"
	"github.com/heliannuuthus/helios/pkg/aegis/pasetokit"
)

// Verifier 负责验证 PASETO 签名
// 通用实现，自动从 token 中提取 clientID 获取对应公钥
type Verifier struct {
	keyProvider keys.PublicKeyProvider
}

// NewVerifier 创建 Verifier
func NewVerifier(keyProvider keys.PublicKeyProvider) *Verifier {
	return &Verifier{
		keyProvider: keyProvider,
	}
}

// VerifySignature 验证 PASETO 签名（不解析为具体 Token 类型）
// 返回原始的 paseto.Token，供调用方进一步处理
func VerifySignature(publicKey paseto.V4AsymmetricPublicKey, tokenString string) (*paseto.Token, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	pasetoToken, err := parser.ParseV4Public(publicKey, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", pasetokit.ErrInvalidSignature, err)
	}

	return pasetoToken, nil
}

// Verify 验证 token 签名，返回具体的 Token 类型
// 自动从 token 中提取 clientID 和 audience，获取对应公钥进行验签
func (v *Verifier) Verify(ctx context.Context, tokenString string, info *TokenInfo) (Token, error) {
	if info == nil {
		var err error
		info, err = Extract(tokenString)
		if err != nil {
			return nil, err
		}
	}

	// 1. 获取公钥（使用 token 中提取的 clientID）
	publicKey, err := v.keyProvider.Get(ctx, info.ClientID)
	if err != nil {
		return nil, fmt.Errorf("get public key for client %s: %w", info.ClientID, err)
	}

	// 2. 验证签名
	pasetoToken, err := VerifySignature(publicKey, tokenString)
	if err != nil {
		return nil, err
	}

	// 3. 验证 audience
	audience, err := pasetoToken.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("get audience: %w", err)
	}
	if audience != info.Audience {
		return nil, fmt.Errorf("%w: audience mismatch", pasetokit.ErrInvalidSignature)
	}

	// 4. 根据类型解析为具体 Token
	return ParseToken(pasetoToken, info.TokenType)
}

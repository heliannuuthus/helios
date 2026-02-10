// Package interpreter 提供 PASETO Token 的验证和解释功能
package interpreter

import (
	"context"
	"fmt"
	"sync"

	"github.com/heliannuuthus/helios/pkg/aegis/keys"
	"github.com/heliannuuthus/helios/pkg/aegis/pasetokit"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	"github.com/heliannuuthus/helios/pkg/json"
)

// 错误定义
var ErrUnsupportedAudience = fmt.Errorf("unsupported audience")

// footerUserInfo footer 中存储的用户信息结构（用于 JSON 反序列化）
type footerUserInfo struct {
	Subject  string `json:"sub,omitempty"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

// Interpreter Token 解释器
// 负责验证和解释 token，提取身份信息
// 内部缓存 decryptor 实例，避免重复构造
type Interpreter struct {
	verifier           *token.Verifier          // 通用验证器（自动从 token 中提取 clientID）
	encryptKeyProvider keys.SymmetricKeyProvider // 加密密钥提供者（根据 audience 获取）

	decryptors map[string]*decryptor // 缓存：key = audience
	mu         sync.RWMutex
}

// NewInterpreter 创建解释器
func NewInterpreter(signKeyProvider keys.PublicKeyProvider, encryptKeyProvider keys.SymmetricKeyProvider) *Interpreter {
	return &Interpreter{
		verifier:           token.NewVerifier(signKeyProvider),
		encryptKeyProvider: encryptKeyProvider,
		decryptors:         make(map[string]*decryptor),
	}
}

// Interpret 验证并解释 token，返回 Token 接口
// 这是最完整的验证方法，会解密 footer 中的用户信息（仅 UAT）
func (i *Interpreter) Interpret(ctx context.Context, tokenString string) (token.Token, error) {
	// 1. 提取 token 信息
	info, err := token.Extract(tokenString)
	if err != nil {
		return nil, err
	}

	if info.Audience == "" {
		return nil, fmt.Errorf("%w: missing audience", token.ErrMissingClaims)
	}

	// 2. 验证签名（Verifier 自动从 info 获取 clientID）
	t, err := i.verifier.Verify(ctx, tokenString, info)
	if err != nil {
		return nil, err
	}

	// 3. 解密 footer 中的用户信息（仅 UAT）
	if uat, ok := token.AsUAT(t); ok {
		footer := token.ExtractFooter(tokenString)
		if footer != "" {
			userInfo, err := i.getDecryptor(info.Audience).decrypt(ctx, footer)
			if err != nil {
				return nil, err
			}
			if userInfo != nil {
				uat.SetUserInfo(userInfo.Subject, userInfo.Nickname, userInfo.Picture, userInfo.Email, userInfo.Phone)
			}
		}
	}

	return t, nil
}

// Verify 只验证签名，不解密 footer
func (i *Interpreter) Verify(ctx context.Context, tokenString string) (token.Token, error) {
	info, err := token.Extract(tokenString)
	if err != nil {
		return nil, err
	}

	if info.Audience == "" {
		return nil, fmt.Errorf("%w: missing audience", token.ErrMissingClaims)
	}

	return i.verifier.Verify(ctx, tokenString, info)
}

// getDecryptor 获取或创建绑定特定 audience 的 decryptor
func (i *Interpreter) getDecryptor(audience string) *decryptor {
	return getOrCreate(&i.mu, i.decryptors, audience, func() *decryptor {
		return &decryptor{
			keyProvider: i.encryptKeyProvider,
			audience:    audience,
		}
	})
}

// ==================== decryptor ====================

type decryptor struct {
	keyProvider keys.SymmetricKeyProvider
	audience    string
}

func (d *decryptor) decrypt(ctx context.Context, footer string) (*footerUserInfo, error) {
	if footer == "" {
		return nil, nil
	}

	symmetricKey, err := d.keyProvider.Get(ctx, d.audience)
	if err != nil {
		return nil, fmt.Errorf("%w: get key for audience %s: %w", ErrUnsupportedAudience, d.audience, err)
	}

	data, err := pasetokit.DecryptFooter(symmetricKey, footer)
	if err != nil {
		return nil, fmt.Errorf("decrypt footer: %w", err)
	}

	var userInfo footerUserInfo
	if err := json.Unmarshal(data, &userInfo); err != nil {
		return nil, fmt.Errorf("unmarshal user info: %w", err)
	}

	return &userInfo, nil
}

// ==================== 辅助函数 ====================

func getOrCreate[T any](mu *sync.RWMutex, cache map[string]*T, key string, create func() *T) *T {
	mu.RLock()
	if v, ok := cache[key]; ok {
		mu.RUnlock()
		return v
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()

	if v, ok := cache[key]; ok {
		return v
	}

	v := create()
	cache[key] = v
	return v
}

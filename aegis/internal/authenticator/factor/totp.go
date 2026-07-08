package factor

import (
	"context"
	"fmt"

	"github.com/pquerna/otp/totp"

	"github.com/heliannuuthus/aegis/contract"
	"github.com/heliannuuthus/aegis/internal/types"
	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/pkg/logger"
)

var (
	_ Provider = (*TOTPFactor)(nil)
)

// TOTPFactor TOTP 认证因子
type TOTPFactor struct {
	store contract.CredentialStore
}

// NewTOTPFactor 创建 TOTP 认证因子
func NewTOTPFactor(store contract.CredentialStore) *TOTPFactor {
	return &TOTPFactor{
		store: store,
	}
}

// Type 返回因子类型标识
func (*TOTPFactor) Type() string {
	return TypeTOTP
}

func (p *TOTPFactor) Initiate(_ context.Context, challenge *types.Challenge) error {
	if challenge.Channel == "" {
		return fmt.Errorf("user_id is required for totp")
	}
	return nil
}

// Verify 验证 TOTP 验证码
// proof: TOTP 码
// params[0]: openid (string)
func (p *TOTPFactor) Verify(ctx context.Context, proof string, params ...any) (bool, error) {
	if proof == "" {
		return false, nil
	}

	if len(params) < 1 {
		return false, nil
	}
	openid, ok := params[0].(string)
	if !ok || openid == "" {
		return false, nil
	}

	creds, err := p.store.ListUserCredentialsByType(ctx, openid, string(models.CredentialTypeTOTP))
	if err != nil {
		return false, fmt.Errorf("query totp credentials: %w", err)
	}
	for i := range creds {
		if !isActiveTOTPCredential(&creds[i]) {
			continue
		}
		if totp.Validate(proof, creds[i].Secret) {
			logger.Infof("[TOTP] 验证成功 - OpenID: %s", openid)
			return true, nil
		}
	}

	logger.Debugf("[TOTP] 验证失败 - OpenID: %s", openid)
	return false, nil
}

// Prepare 准备前端公开配置
func (*TOTPFactor) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: TypeTOTP,
	}
}

func isActiveTOTPCredential(c *models.UserCredential) bool {
	if c.Type != string(models.CredentialTypeTOTP) {
		return false
	}
	if c.LastUsedAt != nil {
		return true
	}
	return c.Enabled
}

package totp

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"time"

	pquerna_totp "github.com/pquerna/otp/totp"

	"github.com/heliannuuthus/aegis/internal/cache"
	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/aegis/rpc/hermes"
	"github.com/heliannuuthus/pkg/logger"
)

const (
	defaultTOTPLabel = "身份验证器 App"
)

// Service owns TOTP enrollment and code verification.
type Service struct {
	credentials *hermes.Client
	cache       *cache.Manager
}

type Enrollment struct {
	UID        string
	Secret     string
	OTPAuthURI string
}

func NewService(credentials *hermes.Client, cacheManager *cache.Manager) *Service {
	return &Service{
		credentials: credentials,
		cache:       cacheManager,
	}
}

func (s *Service) BeginEnrollment(ctx context.Context, openid, appName string) (*Enrollment, error) {
	creds, err := s.credentials.ListUserCredentialsByType(ctx, openid, string(models.CredentialTypeTOTP))
	if err != nil {
		return nil, fmt.Errorf("查询 TOTP 失败: %w", err)
	}
	for i := range creds {
		if isActiveTOTPCredential(&creds[i]) {
			return nil, errors.New("用户已绑定 TOTP")
		}
	}
	if len(creds) > 0 {
		if err := s.credentials.DeleteUserCredentialsByType(ctx, openid, string(models.CredentialTypeTOTP)); err != nil {
			return nil, fmt.Errorf("清理历史未激活 TOTP 失败: %w", err)
		}
	}

	secret, err := generateTOTPSecret()
	if err != nil {
		return nil, err
	}

	issuer := appName
	if issuer == "" {
		issuer = "Helios"
	}

	session := &cache.TOTPEnrollmentSession{
		OpenID: openid,
		Secret: secret,
		Label:  defaultTOTPLabel,
	}
	uid, err := s.cache.SaveTOTPEnrollmentSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("保存 TOTP 注册会话失败: %w", err)
	}

	return &Enrollment{
		UID:        uid,
		Secret:     secret,
		OTPAuthURI: otpauthURI(issuer, openid, secret),
	}, nil
}

func (s *Service) ConfirmEnrollment(ctx context.Context, openid, uid, code string) error {
	session, err := s.cache.GetTOTPEnrollmentSession(ctx, uid)
	if err != nil {
		return errors.New("TOTP 注册会话不存在或已过期")
	}
	if session.OpenID != openid {
		return errors.New("TOTP 注册会话不存在")
	}

	if session.Secret == "" {
		return errors.New("TOTP 注册会话数据无效")
	}
	if !pquerna_totp.Validate(code, session.Secret) {
		return errors.New("验证码错误")
	}

	now := time.Now()
	credential := &models.UserCredential{
		OpenID:     openid,
		Type:       string(models.CredentialTypeTOTP),
		Label:      session.Label,
		Enabled:    true,
		LastUsedAt: &now,
		Secret:     session.Secret,
	}
	if credential.Label == "" {
		credential.Label = defaultTOTPLabel
	}
	if err := s.credentials.CreateCredential(ctx, credential); err != nil {
		return fmt.Errorf("保存 TOTP 凭证失败: %w", err)
	}
	if err := s.cache.DeleteTOTPEnrollmentSession(ctx, uid); err != nil {
		logger.Warnf("[Credential] 删除 TOTP 注册会话失败 - UID: %s, err: %v", uid, err)
	}

	logger.Infof("[Credential] TOTP 绑定成功 - OpenID: %s", openid)
	return nil
}

func (s *Service) VerifyCode(ctx context.Context, openid, code string) (bool, error) {
	if code == "" || openid == "" {
		return false, nil
	}

	creds, err := s.credentials.ListUserCredentialsByType(ctx, openid, string(models.CredentialTypeTOTP))
	if err != nil {
		return false, fmt.Errorf("query totp credentials: %w", err)
	}
	for i := range creds {
		if !isActiveTOTPCredential(&creds[i]) {
			continue
		}
		if pquerna_totp.Validate(code, creds[i].Secret) {
			logger.Infof("[TOTP] 验证成功 - OpenID: %s", openid)
			return true, nil
		}
	}

	logger.Debugf("[TOTP] 验证失败 - OpenID: %s", openid)
	return false, nil
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

func generateTOTPSecret() (string, error) {
	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", fmt.Errorf("生成密钥失败: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes), nil
}

func otpauthURI(issuer, openid, secret string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		url.PathEscape(issuer),
		url.PathEscape(openid),
		secret,
		url.QueryEscape(issuer),
	)
}

package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// ==================== ClientAccessToken (CAT) ====================

// ClientAccessToken 客户端访问令牌
// 用于 Client-Credentials 流程，应用使用自己的 Ed25519 密钥签发
// 特点：sub = clientID（与其他 Token 不同，其他使用 cli 字段）
type ClientAccessToken struct {
	c claims
}

// NewClientAccessToken 创建 CAT
func NewClientAccessToken(issuer, clientID, audience string, expiresIn time.Duration) *ClientAccessToken {
	c := newClaims(issuer, clientID, audience, expiresIn)
	c.Subject = clientID // CAT 的 sub = clientID
	return &ClientAccessToken{c: c}
}

// ParseClientAccessToken 从 PASETO Token 解析 CAT
func ParseClientAccessToken(pasetoToken *paseto.Token) (*ClientAccessToken, error) {
	issuer, err := pasetoToken.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("get issuer: %w", err)
	}

	clientID, err := pasetoToken.GetSubject() // CAT 使用 sub = clientID
	if err != nil {
		return nil, fmt.Errorf("get subject: %w", err)
	}

	audience, err := pasetoToken.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("get audience: %w", err)
	}

	issuedAt, err := pasetoToken.GetIssuedAt()
	if err != nil {
		return nil, fmt.Errorf("get issued_at: %w", err)
	}

	expiresAt, err := pasetoToken.GetExpiration()
	if err != nil {
		return nil, fmt.Errorf("get expiration: %w", err)
	}

	jti, err := pasetoToken.GetJti()
	if err != nil {
		return nil, fmt.Errorf("get jti: %w", err)
	}

	return &ClientAccessToken{
		c: claims{
			Issuer:    issuer,
			ClientID:  clientID,
			Audience:  audience,
			Subject:   clientID,
			IssuedAt:  issuedAt,
			ExpiresAt: expiresAt,
			JTI:       jti,
		},
	}, nil
}

func (t *ClientAccessToken) Type() TokenType        { return TokenTypeCAT }
func (t *ClientAccessToken) GetIssuer() string       { return t.c.Issuer }
func (t *ClientAccessToken) GetClientID() string     { return t.c.ClientID }
func (t *ClientAccessToken) GetAudience() string     { return t.c.Audience }
func (t *ClientAccessToken) GetSubject() string      { return t.c.Subject }
func (t *ClientAccessToken) GetIssuedAt() time.Time  { return t.c.IssuedAt }
func (t *ClientAccessToken) GetExpiresAt() time.Time { return t.c.ExpiresAt }
func (t *ClientAccessToken) GetJTI() string          { return t.c.JTI }
func (t *ClientAccessToken) IsExpired() bool         { return time.Now().After(t.c.ExpiresAt) }

// build 构建 PASETO Token（内部使用）
// CAT 使用 sub 字段存储 clientID，不使用 cli 字段
func (t *ClientAccessToken) build() (*paseto.Token, error) {
	now := time.Now()
	pt := paseto.NewToken()

	pt.SetIssuer(t.c.Issuer)
	pt.SetSubject(t.c.ClientID) // sub = client_id
	pt.SetAudience(t.c.Audience)
	pt.SetIssuedAt(now)
	pt.SetExpiration(now.Add(t.c.ExpiresIn))
	pt.SetNotBefore(now)
	pt.SetJti(t.c.JTI)

	return &pt, nil
}

// ==================== UserAccessToken (UAT) ====================

// UserAccessToken 用户访问令牌
// 包含用户身份信息，用户信息加密后存储在 footer 中
type UserAccessToken struct {
	c     claims
	scope string    // 授权范围
	user  *UserInfo // 用户信息
}

// NewUserAccessToken 创建 UAT
func NewUserAccessToken(issuer, clientID, audience, scope string, expiresIn time.Duration, user *UserInfo) *UserAccessToken {
	return &UserAccessToken{
		c:     newClaims(issuer, clientID, audience, expiresIn),
		scope: scope,
		user:  user,
	}
}

// ParseUserAccessToken 从 PASETO Token 解析 UAT
func ParseUserAccessToken(pasetoToken *paseto.Token) (*UserAccessToken, error) {
	c, err := parseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	var scope string
	_ = pasetoToken.Get("scope", &scope)

	return &UserAccessToken{
		c:     c,
		scope: scope,
	}, nil
}

func (t *UserAccessToken) Type() TokenType        { return TokenTypeUAT }
func (t *UserAccessToken) GetIssuer() string       { return t.c.Issuer }
func (t *UserAccessToken) GetClientID() string     { return t.c.ClientID }
func (t *UserAccessToken) GetAudience() string     { return t.c.Audience }
func (t *UserAccessToken) GetSubject() string      { return t.c.Subject }
func (t *UserAccessToken) GetIssuedAt() time.Time  { return t.c.IssuedAt }
func (t *UserAccessToken) GetExpiresAt() time.Time { return t.c.ExpiresAt }
func (t *UserAccessToken) GetJTI() string          { return t.c.JTI }
func (t *UserAccessToken) IsExpired() bool         { return time.Now().After(t.c.ExpiresAt) }
func (t *UserAccessToken) GetScope() string        { return t.scope }
func (t *UserAccessToken) GetUser() *UserInfo      { return t.user }
func (t *UserAccessToken) SetUser(user *UserInfo)  { t.user = user }

// HasScope 检查是否包含某个 scope
func (t *UserAccessToken) HasScope(scope string) bool {
	return hasScope(t.scope, scope)
}

// build 构建 PASETO Token（内部使用）
func (t *UserAccessToken) build() (*paseto.Token, error) {
	pt := paseto.NewToken()
	if err := t.c.setStandardClaims(&pt); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	if err := pt.Set("scope", t.scope); err != nil {
		return nil, fmt.Errorf("set scope: %w", err)
	}
	return &pt, nil
}

// ==================== ServiceAccessToken (SAT) ====================

// ServiceAccessToken 服务访问令牌
// 用于 M2M（机器对机器）通信，不包含用户信息
type ServiceAccessToken struct {
	c     claims
	scope string // 授权范围
}

// NewServiceAccessToken 创建 SAT
func NewServiceAccessToken(issuer, clientID, audience, scope string, expiresIn time.Duration) *ServiceAccessToken {
	return &ServiceAccessToken{
		c:     newClaims(issuer, clientID, audience, expiresIn),
		scope: scope,
	}
}

// ParseServiceAccessToken 从 PASETO Token 解析 SAT
func ParseServiceAccessToken(pasetoToken *paseto.Token) (*ServiceAccessToken, error) {
	c, err := parseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	var scope string
	_ = pasetoToken.Get("scope", &scope)

	return &ServiceAccessToken{
		c:     c,
		scope: scope,
	}, nil
}

func (t *ServiceAccessToken) Type() TokenType        { return TokenTypeSAT }
func (t *ServiceAccessToken) GetIssuer() string       { return t.c.Issuer }
func (t *ServiceAccessToken) GetClientID() string     { return t.c.ClientID }
func (t *ServiceAccessToken) GetAudience() string     { return t.c.Audience }
func (t *ServiceAccessToken) GetSubject() string      { return t.c.Subject }
func (t *ServiceAccessToken) GetIssuedAt() time.Time  { return t.c.IssuedAt }
func (t *ServiceAccessToken) GetExpiresAt() time.Time { return t.c.ExpiresAt }
func (t *ServiceAccessToken) GetJTI() string          { return t.c.JTI }
func (t *ServiceAccessToken) IsExpired() bool         { return time.Now().After(t.c.ExpiresAt) }
func (t *ServiceAccessToken) GetScope() string        { return t.scope }

// build 构建 PASETO Token（内部使用）
func (t *ServiceAccessToken) build() (*paseto.Token, error) {
	pt := paseto.NewToken()
	if err := t.c.setStandardClaims(&pt); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	if err := pt.Set("scope", t.scope); err != nil {
		return nil, fmt.Errorf("set scope: %w", err)
	}
	return &pt, nil
}

// ==================== ChallengeToken ====================

// ChallengeType 挑战类型
type ChallengeType string

const (
	ChallengeTypeCaptcha  ChallengeType = "captcha"   // 人机验证
	ChallengeTypeEmailOTP ChallengeType = "email-otp" // 邮箱 OTP
	ChallengeTypeTOTP     ChallengeType = "totp"      // TOTP 动态口令
	ChallengeTypeSmsOTP   ChallengeType = "sms-otp"   // 短信 OTP
	ChallengeTypeTgOTP    ChallengeType = "tg-otp"    // Telegram OTP
	ChallengeTypeWebAuthn ChallengeType = "webauthn"  // WebAuthn/Passkey
)

// ChallengeToken 验证挑战令牌
// 用于证明某个 principal 已完成特定的身份验证挑战
type ChallengeToken struct {
	c             claims
	challengeType ChallengeType
}

// NewChallengeToken 创建 ChallengeToken
// subject: 完成挑战的 principal（如 email、phone、credential_id）
func NewChallengeToken(issuer, subject, audience, clientID string, challengeType ChallengeType, expiresIn time.Duration) *ChallengeToken {
	c := newClaims(issuer, clientID, audience, expiresIn)
	c.Subject = subject
	return &ChallengeToken{
		c:             c,
		challengeType: challengeType,
	}
}

// ParseChallengeToken 从 PASETO Token 解析 ChallengeToken
func ParseChallengeToken(pasetoToken *paseto.Token) (*ChallengeToken, error) {
	c, err := parseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	var challengeType string
	if err := pasetoToken.Get("typ", &challengeType); err != nil {
		return nil, fmt.Errorf("get typ: %w", err)
	}

	return &ChallengeToken{
		c:             c,
		challengeType: ChallengeType(challengeType),
	}, nil
}

func (t *ChallengeToken) Type() TokenType                 { return TokenTypeChallenge }
func (t *ChallengeToken) GetIssuer() string               { return t.c.Issuer }
func (t *ChallengeToken) GetClientID() string             { return t.c.ClientID }
func (t *ChallengeToken) GetAudience() string             { return t.c.Audience }
func (t *ChallengeToken) GetSubject() string              { return t.c.Subject }
func (t *ChallengeToken) GetIssuedAt() time.Time          { return t.c.IssuedAt }
func (t *ChallengeToken) GetExpiresAt() time.Time         { return t.c.ExpiresAt }
func (t *ChallengeToken) GetJTI() string                  { return t.c.JTI }
func (t *ChallengeToken) IsExpired() bool                 { return time.Now().After(t.c.ExpiresAt) }
func (t *ChallengeToken) GetChallengeType() ChallengeType { return t.challengeType }

// build 构建 PASETO Token（内部使用）
func (t *ChallengeToken) build() (*paseto.Token, error) {
	pt := paseto.NewToken()
	if err := t.c.setStandardClaims(&pt); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	if err := pt.Set("typ", string(t.challengeType)); err != nil {
		return nil, fmt.Errorf("set typ: %w", err)
	}
	return &pt, nil
}

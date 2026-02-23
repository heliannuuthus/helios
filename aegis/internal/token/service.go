package token

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/internal/cache"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/pkg/aegis/key"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
)

// Service Token 服务
type Service struct {
	issuer string
	cache  *cache.Manager

	domainKeyStore  *key.Store // clientID → domain.Main
	serviceKeyStore *key.Store // audience → service.Key
	appKeyStore     *key.Store // clientID → app.Key
	ssoKeyStore     *key.Store // "" → sso master key

	// 缓存派生后的密钥组件（懒加载）
	domainSigners    map[string]*Signer
	serviceEncryptors map[string]*Encryptor
	appVerifiers     map[string]*token.Verifier
	ssoSigner        *Signer
	ssoEncryptor     *Encryptor
	ssoVerifier      *token.Verifier
	mu               sync.RWMutex
}

// NewService 创建 Token 服务
func NewService(
	cache *cache.Manager,
	domainKeyStore *key.Store,
	serviceKeyStore *key.Store,
	appKeyStore *key.Store,
	ssoKeyStore *key.Store,
) *Service {
	return &Service{
		issuer:          config.GetIssuer(),
		cache:           cache,
		domainKeyStore:  domainKeyStore,
		serviceKeyStore: serviceKeyStore,
		appKeyStore:     appKeyStore,
		ssoKeyStore:     ssoKeyStore,
		domainSigners:     make(map[string]*Signer),
		serviceEncryptors: make(map[string]*Encryptor),
		appVerifiers:      make(map[string]*token.Verifier),
	}
}

// GetIssuer 返回签发者名称
func (s *Service) GetIssuer() string {
	return s.issuer
}

// ============= 签发 =============

// Issue 签发 token（统一入口）
func (s *Service) Issue(ctx context.Context, v any) (string, error) {
	switch t := v.(type) {
	case *types.Challenge:
		return s.issueChallengeTokenFromChallenge(ctx, t)

	case token.Token:
		return s.issueToken(ctx, t)

	default:
		return "", fmt.Errorf("%w: unsupported type %T", token.ErrUnsupportedToken, v)
	}
}

func (s *Service) issueToken(ctx context.Context, t token.Token) (string, error) {
	switch t.Type() {
	case token.TokenTypeUAT:
		uat, ok := t.(*token.UserAccessToken)
		if !ok {
			return "", fmt.Errorf("%w: expected UserAccessToken", token.ErrUnsupportedToken)
		}
		return s.issueUserToken(ctx, uat)

	case token.TokenTypeSAT:
		sat, ok := t.(*token.ServiceAccessToken)
		if !ok {
			return "", fmt.Errorf("%w: expected ServiceAccessToken", token.ErrUnsupportedToken)
		}
		return s.issueServiceToken(ctx, sat)

	case token.TokenTypeChallenge:
		ct, ok := t.(*token.ChallengeToken)
		if !ok {
			return "", fmt.Errorf("%w: expected ChallengeToken", token.ErrUnsupportedToken)
		}
		return s.issueChallengeToken(ctx, ct)

	case token.TokenTypeCAT:
		return "", fmt.Errorf("%w: CAT should be issued by client using pkg/aegis/token.Issuer", token.ErrUnsupportedToken)

	default:
		return "", fmt.Errorf("%w: %s", token.ErrUnsupportedToken, t.Type())
	}
}

func (s *Service) issueUserToken(ctx context.Context, uat *token.UserAccessToken) (string, error) {
	if !uat.HasUser() {
		return "", errors.New("user claims required for UserAccessToken")
	}
	return s.buildSignAndEncrypt(ctx, uat, uat.GetUserForFooter())
}

func (s *Service) issueServiceToken(ctx context.Context, sat *token.ServiceAccessToken) (string, error) {
	return s.buildAndSign(ctx, sat)
}

func (s *Service) issueChallengeToken(ctx context.Context, ct *token.ChallengeToken) (string, error) {
	return s.buildAndSign(ctx, ct)
}

func (s *Service) issueChallengeTokenFromChallenge(ctx context.Context, ch *types.Challenge) (string, error) {
	ctBuilder := token.NewChallengeTokenBuilder().
		Subject(ch.Channel).
		Type(ch.Type).
		ChannelType(token.ChannelType(ch.ChannelType))

	t := token.NewClaimsBuilder().
		Issuer(s.issuer).
		ClientID(ch.ClientID).
		Audience(ch.Audience).
		ExpiresIn(ch.ExpiresIn()).
		Build(ctBuilder)

	return s.issueToken(ctx, t)
}

// ============= SSO =============

func (s *Service) IssueSSO(ctx context.Context, sso *SSOToken) (string, error) {
	if !sso.HasUser() {
		return "", errors.New("identity required for SSOToken")
	}

	footer, err := s.encryptSSOFooter(ctx, sso.GetFooterData())
	if err != nil {
		return "", fmt.Errorf("encrypt sso footer: %w", err)
	}

	pasetoToken, err := sso.BuildPaseto()
	if err != nil {
		return "", fmt.Errorf("build sso token: %w", err)
	}

	return s.signSSO(ctx, pasetoToken, footer)
}

// ============= 验证 =============

func (s *Service) VerifyCAT(ctx context.Context, tokenString string) (*token.ClientAccessToken, error) {
	pasetoToken, err := token.UnsafeParse(tokenString)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	clientID, err := token.GetClientID(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("get client_id: %w", err)
	}

	verifier := s.getAppVerifier(clientID)

	pasetoToken, err = verifier.VerifyRaw(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}

	return token.ParseClientAccessToken(pasetoToken)
}

func (s *Service) Verify(ctx context.Context, tokenString string) (Token, error) {
	return s.VerifyCAT(ctx, tokenString)
}

func (s *Service) VerifySSO(ctx context.Context, tokenString string) (*SSOToken, error) {
	if s.ssoKeyStore == nil {
		return nil, errors.New("SSO not configured")
	}

	ssoVerifier := s.getSSOVerifier()

	pasetoToken, err := ssoVerifier.VerifyRaw(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("verify sso token: %w", err)
	}

	sso, err := ParseSSOToken(pasetoToken)
	if err != nil {
		return nil, err
	}

	if sso.GetIssuer() != SSOIssuer || sso.GetAudience() != SSOAudience {
		return nil, fmt.Errorf("invalid SSO token: iss=%s, aud=%s", sso.GetIssuer(), sso.GetAudience())
	}

	footer := token.ExtractFooter(tokenString)
	if footer == "" {
		return nil, errors.New("invalid SSO token: no footer")
	}

	var identities map[string]string
	if err := s.decryptSSOFooter(ctx, footer, &identities); err != nil {
		return nil, fmt.Errorf("decrypt sso footer: %w", err)
	}

	sso.SetIdentities(identities)

	if !sso.HasUser() {
		return nil, errors.New("invalid SSO token: no identities")
	}

	return sso, nil
}

// ============= 内部方法 =============

func (s *Service) buildSignAndEncrypt(ctx context.Context, t token.Token, footerData any) (string, error) {
	encryptor := s.getServiceEncryptor(t.GetAudience())

	footer, err := encryptor.Encrypt(ctx, footerData)
	if err != nil {
		return "", fmt.Errorf("encrypt footer: %w", err)
	}

	pasetoToken, err := token.Build(t)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	return s.signDomainToken(ctx, pasetoToken, t.GetClientID(), []byte(footer))
}

func (s *Service) buildAndSign(ctx context.Context, t token.Token) (string, error) {
	pasetoToken, err := token.Build(t)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	return s.signDomainToken(ctx, pasetoToken, t.GetClientID(), nil)
}

func (s *Service) signDomainToken(ctx context.Context, pasetoToken *paseto.Token, clientID string, footer []byte) (string, error) {
	signer := s.getDomainSigner(clientID)
	return signer.Sign(ctx, pasetoToken, footer)
}

func (s *Service) signSSO(ctx context.Context, pasetoToken *paseto.Token, footer []byte) (string, error) {
	signer := s.getSSOSigner()
	return signer.Sign(ctx, pasetoToken, footer)
}

func (s *Service) encryptSSOFooter(ctx context.Context, footerData any) ([]byte, error) {
	encryptor := s.getSSOEncryptor()

	encrypted, err := encryptor.Encrypt(ctx, footerData)
	if err != nil {
		return nil, fmt.Errorf("encrypt sso footer: %w", err)
	}

	return []byte(encrypted), nil
}

func (s *Service) decryptSSOFooter(ctx context.Context, footer string, dest any) error {
	encryptor := s.getSSOEncryptor()
	t, err := encryptor.DecryptRaw(ctx, footer)
	if err != nil {
		return err
	}
	return t.Get("", dest)
}

// ============= 懒加载组件获取 =============

func (s *Service) getDomainSigner(clientID string) *Signer {
	s.mu.RLock()
	signer, ok := s.domainSigners[clientID]
	s.mu.RUnlock()
	if ok {
		return signer
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// double check
	if signer, ok := s.domainSigners[clientID]; ok {
		return signer
	}

	signer = NewSigner(s.domainKeyStore, clientID)
	s.domainSigners[clientID] = signer
	return signer
}

func (s *Service) getServiceEncryptor(audience string) *Encryptor {
	s.mu.RLock()
	encryptor, ok := s.serviceEncryptors[audience]
	s.mu.RUnlock()
	if ok {
		return encryptor
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// double check
	if encryptor, ok := s.serviceEncryptors[audience]; ok {
		return encryptor
	}

	encryptor = NewEncryptor(s.serviceKeyStore, audience)
	s.serviceEncryptors[audience] = encryptor
	return encryptor
}

func (s *Service) getAppVerifier(clientID string) *token.Verifier {
	s.mu.RLock()
	verifier, ok := s.appVerifiers[clientID]
	s.mu.RUnlock()
	if ok {
		return verifier
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// double check
	if verifier, ok := s.appVerifiers[clientID]; ok {
		return verifier
	}

	verifier = token.NewVerifier(s.appKeyStore, clientID)
	s.appVerifiers[clientID] = verifier
	return verifier
}

func (s *Service) getSSOSigner() *Signer {
	s.mu.RLock()
	if s.ssoSigner != nil {
		s.mu.RUnlock()
		return s.ssoSigner
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	// double check
	if s.ssoSigner != nil {
		return s.ssoSigner
	}

	s.ssoSigner = NewSigner(s.ssoKeyStore, "")
	return s.ssoSigner
}

func (s *Service) getSSOEncryptor() *Encryptor {
	s.mu.RLock()
	if s.ssoEncryptor != nil {
		s.mu.RUnlock()
		return s.ssoEncryptor
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	// double check
	if s.ssoEncryptor != nil {
		return s.ssoEncryptor
	}

	s.ssoEncryptor = NewEncryptor(s.ssoKeyStore, "")
	return s.ssoEncryptor
}

func (s *Service) getSSOVerifier() *token.Verifier {
	s.mu.RLock()
	if s.ssoVerifier != nil {
		s.mu.RUnlock()
		return s.ssoVerifier
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	// double check
	if s.ssoVerifier != nil {
		return s.ssoVerifier
	}

	s.ssoVerifier = token.NewVerifier(s.ssoKeyStore, "")
	return s.ssoVerifier
}

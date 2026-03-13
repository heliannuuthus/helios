package token

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"aidanwoods.dev/go-paseto"
	pkgtoken "github.com/heliannuuthus/aegis-go/service"
	"github.com/heliannuuthus/aegis-go/utilities/key"
	tokendef "github.com/heliannuuthus/aegis-go/utilities/token"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/internal/cache"
)

// Service is the token service that handles issuing and verifying all token types.
type Service struct {
	issuer string
	cache  *cache.Manager

	domainSignProvider   key.Provider // clientID → domain PrivateKey (signing)
	domainVerifyProvider key.Provider // clientID → domain PublicKey[] (verification)
	serviceKeyProvider   key.Provider // audience → service SecretKey[] (encrypt/decrypt)
	appVerifyProvider    key.Provider // clientID → app PublicKey[] (CT verification)

	domainSigners     map[string]*Signer
	serviceEncryptors map[string]*Encryptor
	domainDecryptors  map[string]*pkgtoken.Decryptor // audience → Decryptor (signKey=domain, encryptKey=service)
	appDecryptor      *pkgtoken.Decryptor            // CT 专用（signKey=app, 只验签, encryptKey=nil）
	mu                sync.RWMutex
}

func NewService(
	cache *cache.Manager,
	domainSignProvider key.Provider,
	domainVerifyProvider key.Provider,
	serviceKeyProvider key.Provider,
	appVerifyProvider key.Provider,
) *Service {
	return &Service{
		issuer:               config.GetIssuer(),
		cache:                cache,
		domainSignProvider:   domainSignProvider,
		domainVerifyProvider: domainVerifyProvider,
		serviceKeyProvider:   serviceKeyProvider,
		appVerifyProvider:    appVerifyProvider,
		domainSigners:        make(map[string]*Signer),
		serviceEncryptors:    make(map[string]*Encryptor),
		domainDecryptors:     make(map[string]*pkgtoken.Decryptor),
		appDecryptor:         pkgtoken.NewDecryptor("", nil, appVerifyProvider),
	}
}

func (s *Service) GetIssuer() string {
	return s.issuer
}

// ============= Issue =============

// Issue builds, optionally encrypts the sub field, and signs any Token.
// For EncryptableToken (UAT, SSO), payload is encrypted into sub as a nested v4.local token.
// For plain tokens (SAT, Challenge), the token is signed directly.
func (s *Service) Issue(ctx context.Context, t tokendef.Token) (string, error) {
	if t.Type() == tokendef.TokenTypeCT {
		return "", fmt.Errorf("%w: CT should be issued by client using pkg/aegis/token.Issuer", tokendef.ErrUnsupportedToken)
	}

	pasetoToken, err := tokendef.Build(t)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	if payload, ok := s.marshalPayload(t); ok {
		encryptedSub, err := s.serviceEncryptor(t.Audience()).Encrypt(ctx, payload)
		if err != nil {
			return "", fmt.Errorf("encrypt sub: %w", err)
		}
		pasetoToken.SetSubject(encryptedSub)
	}

	signer := s.domainSigner(t.ClientID())
	return signer.Sign(ctx, pasetoToken)
}

// ============= Verify =============

// Verify verifies the token signature, detects type, parses claims,
// and decrypts the sub field for tokens that carry encrypted payload (UAT, SSO).
func (s *Service) Verify(ctx context.Context, tokenString string) (Token, error) {
	pasetoToken, err := tokendef.UnsafeParse(tokenString)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	tokenType := tokendef.DetectType(pasetoToken)

	clientID, err := tokendef.GetClientID(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("get client_id: %w", err)
	}

	if tokenType == tokendef.TokenTypeCT {
		pasetoToken, err = s.appDecryptor.Verifier(clientID).Verify(ctx, tokenString)
		if err != nil {
			return nil, fmt.Errorf("verify signature: %w", err)
		}
		return tokendef.ParseToken(pasetoToken, tokenType)
	}

	audience, err := tokendef.GetAudience(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("get audience: %w", err)
	}

	decryptor := s.domainDecryptor(audience)
	pasetoToken, err = decryptor.Verifier(clientID).Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}

	var t Token
	if tokenType == tokendef.TokenTypeSSO {
		t, err = ParseSSOToken(pasetoToken)
	} else {
		t, err = tokendef.ParseToken(pasetoToken, tokenType)
	}
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	if s.needsDecryption(tokenType) {
		encryptedSub := t.Subject()
		if encryptedSub == "" {
			return nil, errors.New("missing encrypted sub")
		}

		innerToken, err := decryptor.Decrypt(ctx, encryptedSub)
		if err != nil {
			return nil, fmt.Errorf("decrypt sub: %w", err)
		}

		s.applyPayload(t, innerToken)
	}

	return t, nil
}

// ============= Lazy Component Getters =============

func (s *Service) domainSigner(clientID string) *Signer {
	s.mu.RLock()
	signer, ok := s.domainSigners[clientID]
	s.mu.RUnlock()
	if ok {
		return signer
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if signer, ok := s.domainSigners[clientID]; ok {
		return signer
	}

	signer = NewSigner(s.domainSignProvider, clientID)
	s.domainSigners[clientID] = signer
	return signer
}

func (s *Service) serviceEncryptor(audience string) *Encryptor {
	s.mu.RLock()
	encryptor, ok := s.serviceEncryptors[audience]
	s.mu.RUnlock()
	if ok {
		return encryptor
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if encryptor, ok := s.serviceEncryptors[audience]; ok {
		return encryptor
	}

	encryptor = NewEncryptor(s.serviceKeyProvider, audience)
	s.serviceEncryptors[audience] = encryptor
	return encryptor
}

func (s *Service) domainDecryptor(audience string) *pkgtoken.Decryptor {
	s.mu.RLock()
	decryptor, ok := s.domainDecryptors[audience]
	s.mu.RUnlock()
	if ok {
		return decryptor
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if decryptor, ok := s.domainDecryptors[audience]; ok {
		return decryptor
	}

	decryptor = pkgtoken.NewDecryptor(audience, s.serviceKeyProvider, s.domainVerifyProvider)
	s.domainDecryptors[audience] = decryptor
	return decryptor
}

// ============= Payload Encryption Helpers =============

// marshalPayload extracts the payload that needs encryption for UAT and SSO tokens.
func (*Service) marshalPayload(t tokendef.Token) ([]byte, bool) {
	switch v := t.(type) {
	case *tokendef.UserAccessToken:
		if !v.Identified() {
			return nil, false
		}
		data, err := v.MarshalIdentity()
		if err != nil {
			return nil, false
		}
		return data, true
	case *SSOToken:
		if v.GetIdentities() == nil {
			return nil, false
		}
		data, err := v.MarshalIdentities()
		if err != nil {
			return nil, false
		}
		return data, true
	default:
		return nil, false
	}
}

func (*Service) needsDecryption(tokenType tokendef.TokenType) bool {
	return tokenType == tokendef.TokenTypeUAT || tokenType == tokendef.TokenTypeSSO
}

func (*Service) applyPayload(t tokendef.Token, inner *paseto.Token) {
	switch v := t.(type) {
	case *tokendef.UserAccessToken:
		v.SetIdentity(inner)
	case *SSOToken:
		v.SetIdentities(inner)
	}
}

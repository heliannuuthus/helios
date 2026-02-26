package token

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/internal/cache"
	"github.com/heliannuuthus/helios/pkg/aegis/key"
	pkgtoken "github.com/heliannuuthus/helios/pkg/aegis/token"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// encryptableToken is a Token whose payload should be encrypted into the sub field.
type encryptableToken interface {
	Token
	HasUser() bool
	MarshalPayload() ([]byte, error)
}

// decryptableToken is a Token whose sub field contains encrypted payload to be decrypted.
type decryptableToken interface {
	Token
	UnmarshalPayload(data []byte) error
}

// Service is the token service that handles issuing and verifying all token types.
type Service struct {
	issuer string
	cache  *cache.Manager

	domainKeyStore  *key.Store // clientID → domain.Main (includes SSO with id="aegis")
	serviceKeyStore *key.Store // audience → service.Key (includes SSO with id="aegis")
	appKeyStore     *key.Store // clientID → app.Key

	domainSigners     map[string]*Signer
	domainVerifiers   map[string]*pkgtoken.Verifier
	serviceEncryptors map[string]*Encryptor
	serviceDecryptors map[string]*pkgtoken.Decryptor
	appVerifiers      map[string]*pkgtoken.Verifier
	mu                sync.RWMutex
}

func NewService(
	cache *cache.Manager,
	domainKeyStore *key.Store,
	serviceKeyStore *key.Store,
	appKeyStore *key.Store,
) *Service {
	return &Service{
		issuer:            config.GetIssuer(),
		cache:             cache,
		domainKeyStore:    domainKeyStore,
		serviceKeyStore:   serviceKeyStore,
		appKeyStore:       appKeyStore,
		domainSigners:     make(map[string]*Signer),
		domainVerifiers:   make(map[string]*pkgtoken.Verifier),
		serviceEncryptors: make(map[string]*Encryptor),
		serviceDecryptors: make(map[string]*pkgtoken.Decryptor),
		appVerifiers:      make(map[string]*pkgtoken.Verifier),
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
	if t.Type() == tokendef.TokenTypeCAT {
		return "", fmt.Errorf("%w: CAT should be issued by client using pkg/aegis/token.Issuer", tokendef.ErrUnsupportedToken)
	}

	pasetoToken, err := tokendef.Build(t)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	if et, ok := t.(encryptableToken); ok && et.HasUser() {
		payload, err := et.MarshalPayload()
		if err != nil {
			return "", fmt.Errorf("marshal payload: %w", err)
		}

		encryptor := s.getServiceEncryptor(t.GetAudience())
		encryptedSub, err := encryptor.Encrypt(ctx, payload)
		if err != nil {
			return "", fmt.Errorf("encrypt sub: %w", err)
		}
		pasetoToken.SetSubject(encryptedSub)
	}

	signer := s.getDomainSigner(t.GetClientID())
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

	var verifier *pkgtoken.Verifier
	if tokenType == tokendef.TokenTypeCAT {
		verifier = s.getAppVerifier(clientID)
	} else {
		verifier = s.getDomainVerifier(clientID)
	}

	pasetoToken, err = verifier.Verify(ctx, tokenString)
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

	if dt, ok := t.(decryptableToken); ok {
		encryptedSub := t.GetSubject()
		if encryptedSub == "" {
			return nil, errors.New("missing encrypted sub")
		}

		audience, err := tokendef.GetAudience(pasetoToken)
		if err != nil {
			logger.Warnf("failed to get audience from token: %v", err)
		}
		decryptor := s.getServiceDecryptor(audience)
		claimsJSON, _, err := decryptor.Decrypt(ctx, encryptedSub)
		if err != nil {
			return nil, fmt.Errorf("decrypt sub: %w", err)
		}

		if err := dt.UnmarshalPayload(claimsJSON); err != nil {
			return nil, fmt.Errorf("unmarshal payload: %w", err)
		}
	}

	return t, nil
}

// ============= Lazy Component Getters =============

func (s *Service) getDomainSigner(clientID string) *Signer {
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

	signer = NewSigner(s.domainKeyStore, clientID)
	s.domainSigners[clientID] = signer
	return signer
}

func (s *Service) getDomainVerifier(clientID string) *pkgtoken.Verifier {
	s.mu.RLock()
	verifier, ok := s.domainVerifiers[clientID]
	s.mu.RUnlock()
	if ok {
		return verifier
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if verifier, ok := s.domainVerifiers[clientID]; ok {
		return verifier
	}

	verifier = pkgtoken.NewVerifier(s.domainKeyStore, clientID)
	s.domainVerifiers[clientID] = verifier
	return verifier
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

	if encryptor, ok := s.serviceEncryptors[audience]; ok {
		return encryptor
	}

	encryptor = NewEncryptor(s.serviceKeyStore, audience)
	s.serviceEncryptors[audience] = encryptor
	return encryptor
}

func (s *Service) getServiceDecryptor(audience string) *pkgtoken.Decryptor {
	s.mu.RLock()
	decryptor, ok := s.serviceDecryptors[audience]
	s.mu.RUnlock()
	if ok {
		return decryptor
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if decryptor, ok := s.serviceDecryptors[audience]; ok {
		return decryptor
	}

	decryptor = pkgtoken.NewDecryptor(s.serviceKeyStore, audience)
	s.serviceDecryptors[audience] = decryptor
	return decryptor
}

func (s *Service) getAppVerifier(clientID string) *pkgtoken.Verifier {
	s.mu.RLock()
	verifier, ok := s.appVerifiers[clientID]
	s.mu.RUnlock()
	if ok {
		return verifier
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if verifier, ok := s.appVerifiers[clientID]; ok {
		return verifier
	}

	verifier = pkgtoken.NewVerifier(s.appKeyStore, clientID)
	s.appVerifiers[clientID] = verifier
	return verifier
}

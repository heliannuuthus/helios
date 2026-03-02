package token

import (
	"fmt"

	"aidanwoods.dev/go-paseto"
	"github.com/go-json-experiment/json"

	pkgtoken "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
)

const (
	SSOIssuer   = "aegis"
	SSOAudience = "aegis"
)

// SSOToken represents a single sign-on session token.
// Claims are signed (public token), identities are encrypted into the sub field
// as a nested v4.local token.
//
// Footer: {"kid":"k4.pid.xxxx"} (signing key)
// Sub:    v4.local.<encrypted identities>.<inner footer with k4.lid>
type SSOToken struct {
	pkgtoken.Claims
	identities map[string]string // domain → openID
}

// ==================== Builder ====================

type SSOTokenBuilder struct {
	identities map[string]string
}

func NewSSOTokenBuilder() *SSOTokenBuilder {
	return &SSOTokenBuilder{
		identities: make(map[string]string),
	}
}

func (b *SSOTokenBuilder) Identity(domain, openID string) *SSOTokenBuilder {
	b.identities[domain] = openID
	return b
}

func (b *SSOTokenBuilder) Identities(identities map[string]string) *SSOTokenBuilder {
	for domain, openID := range identities {
		b.identities[domain] = openID
	}
	return b
}

func (b *SSOTokenBuilder) Build(claims pkgtoken.Claims) pkgtoken.Token {
	cp := make(map[string]string, len(b.identities))
	for k, v := range b.identities {
		cp[k] = v
	}

	return &SSOToken{
		Claims:     claims,
		identities: cp,
	}
}

// ==================== Token Interface ====================

func (s *SSOToken) Type() pkgtoken.TokenType {
	return pkgtoken.TokenTypeSSO
}

// Build builds the PASETO claims token. The sub field will be set
// by the service layer after encrypting identities.
func (s *SSOToken) Build() (*paseto.Token, error) {
	t := paseto.NewToken()
	if err := s.SetStandardClaims(&t); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	return &t, nil
}

// ==================== Parse ====================

func ParseSSOToken(pasetoToken *paseto.Token) (*SSOToken, error) {
	claims, err := pkgtoken.ParseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	return &SSOToken{
		Claims: claims,
	}, nil
}

// ==================== Identity Data ====================

// MarshalIdentities serializes identity mapping as JSON for inner token encryption.
func (s *SSOToken) MarshalIdentities() ([]byte, error) {
	if len(s.identities) == 0 {
		return nil, fmt.Errorf("no identities to marshal")
	}
	return json.Marshal(s.identities)
}

// UnmarshalIdentities deserializes identity mapping from decrypted inner token claims.
func UnmarshalIdentities(data []byte) (map[string]string, error) {
	var identities map[string]string
	if err := json.Unmarshal(data, &identities); err != nil {
		return nil, fmt.Errorf("unmarshal identities: %w", err)
	}
	return identities, nil
}

func (s *SSOToken) SetIdentities(identities map[string]string) {
	s.identities = identities
}

func (s *SSOToken) HasUser() bool {
	return len(s.identities) > 0
}

func (s *SSOToken) GetOpenID(domain string) string {
	if s.identities == nil {
		return ""
	}
	return s.identities[domain]
}

func (s *SSOToken) GetIdentities() map[string]string {
	if s.identities == nil {
		return nil
	}
	cp := make(map[string]string, len(s.identities))
	for k, v := range s.identities {
		cp[k] = v
	}
	return cp
}

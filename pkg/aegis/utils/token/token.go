// Package token 定义 PASETO Token 类型和接口
package token

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"

	pasetokit "github.com/heliannuuthus/helios/pkg/aegis/utils/paseto"
)

var (
	ErrMissingClaims    = errors.New("missing required claims")
	ErrUnsupportedToken = errors.New("unsupported token type")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidFooter    = pasetokit.ErrInvalidFooter
	ErrKIDNotFound      = pasetokit.ErrKIDNotFound
)

// ==================== Token Interface ====================

// Token is the unified read-only interface for all credential types.
type Token interface {
	Type() TokenType

	GetIssuer() string
	GetClientID() string
	GetAudience() string
	GetSubject() string
	GetIssuedAt() time.Time
	GetExpiresAt() time.Time
	GetJTI() string

	IsExpired() bool
}

// TokenBuilder is the interface for building PASETO tokens.
type TokenBuilder interface {
	Token
	Build() (*paseto.Token, error)
}

// Build constructs a paseto.Token from a Token that implements TokenBuilder.
func Build(t Token) (*paseto.Token, error) {
	if builder, ok := t.(TokenBuilder); ok {
		return builder.Build()
	}
	return nil, fmt.Errorf("%w: token does not support building", ErrUnsupportedToken)
}

// ==================== TokenType ====================

type TokenType string

const (
	TokenTypeCAT       TokenType = "cat"
	TokenTypeUAT       TokenType = "uat"
	TokenTypeSAT       TokenType = "sat"
	TokenTypeChallenge TokenType = "challenge"
	TokenTypeSSO       TokenType = "sso"
)

// DetectType infers the token type from claims.
// Rules: iss==aud==cli → SSO, has typ → Challenge, has cli → UAT, otherwise → CAT
func DetectType(t *paseto.Token) TokenType {
	iss, err := t.GetIssuer()
	if err != nil {
		iss = ""
	}
	aud, err := t.GetAudience()
	if err != nil {
		aud = ""
	}
	var cli string
	if err := t.Get(ClaimCli, &cli); err != nil {
		cli = ""
	}

	if iss != "" && iss == aud && iss == cli {
		return TokenTypeSSO
	}

	var typ string
	if t.Get(ClaimType, &typ) == nil && typ != "" {
		return TokenTypeChallenge
	}

	if cli != "" {
		return TokenTypeUAT
	}

	return TokenTypeCAT
}

// GetClientID extracts clientID from a paseto.Token.
// UAT/Challenge use cli field, CAT uses sub field.
func GetClientID(t *paseto.Token) (string, error) {
	var cli string
	if t.Get(ClaimCli, &cli) == nil && cli != "" {
		return cli, nil
	}

	sub, err := t.GetSubject()
	if err != nil || sub == "" {
		return "", errors.New("missing cli and sub (client_id)")
	}
	return sub, nil
}

// GetAudience extracts audience from a paseto.Token.
func GetAudience(t *paseto.Token) (string, error) {
	return t.GetAudience()
}

// ==================== Token Parsing ====================

// ParseToken parses a PASETO token into a concrete Token type.
func ParseToken(pasetoToken *paseto.Token, tokenType TokenType) (Token, error) {
	switch tokenType {
	case TokenTypeCAT:
		return ParseClientAccessToken(pasetoToken)
	case TokenTypeUAT:
		return ParseUserAccessToken(pasetoToken)
	case TokenTypeSAT:
		return ParseServiceAccessToken(pasetoToken)
	case TokenTypeChallenge:
		return ParseChallengeToken(pasetoToken)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedToken, tokenType)
	}
}

// ==================== Unsafe Parsing ====================

// UnsafeParse parses claims from a token string without signature verification.
// WARNING: returned data is untrusted. Only use to extract clientID/audience for key lookup.
var UnsafeParse = UnsafeParseToken

// UnsafeParseToken parses claims without verifying the signature.
// PASETO v4.public uses Ed25519 with a fixed 64-byte signature appended to the payload.
func UnsafeParseToken(tokenString string) (*paseto.Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 3 || parts[0] != PasetoVersion || parts[1] != PasetoPurpose {
		return nil, fmt.Errorf("%w: invalid PASETO token format", ErrInvalidSignature)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %w", ErrInvalidSignature, err)
	}

	if len(payloadBytes) < 64 {
		return nil, fmt.Errorf("%w: payload too short", ErrInvalidSignature)
	}

	claimsJSON := payloadBytes[:len(payloadBytes)-64]

	var footer []byte
	if len(parts) >= 4 && parts[3] != "" {
		footer, err = base64.RawURLEncoding.DecodeString(parts[3])
		if err != nil {
			return nil, fmt.Errorf("%w: decode footer: %w", ErrInvalidSignature, err)
		}
	}

	t, err := paseto.NewTokenFromClaimsJSON(claimsJSON, footer)
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", ErrInvalidSignature, err)
	}

	return t, nil
}

// ExtractFooter extracts the raw footer string from a token string.
func ExtractFooter(tokenString string) string {
	parts := strings.Split(tokenString, ".")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

// ==================== Scope Helpers ====================

// HasScope checks whether a space-separated scope string contains a specific scope.
func HasScope(scopeStr, scope string) bool {
	for _, s := range strings.Fields(scopeStr) {
		if s == scope {
			return true
		}
	}
	return false
}

func parseScopeSet(scope string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		set[s] = true
	}
	return set
}

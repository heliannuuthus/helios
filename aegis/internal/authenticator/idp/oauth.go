package idp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"time"

	"github.com/heliannuuthus/aegis/internal/types"
)

const oauthRandomBytes = 32

// OAuthTransaction binds one upstream OAuth authorization request to an AuthFlow.
// State and CodeVerifier are server-only, short-lived, and consumed atomically.
type OAuthTransaction struct {
	FlowID        string    `json:"flow_id"`
	Connection    string    `json:"connection"`
	RedirectURI   string    `json:"redirect_uri"`
	State         string    `json:"state"`
	CodeVerifier  string    `json:"code_verifier"`
	CodeChallenge string    `json:"code_challenge"`
	CreatedAt     time.Time `json:"created_at"`
}

// InitiateContext contains the trusted AuthFlow and, for redirect IDPs, its OAuth transaction.
type InitiateContext struct {
	Flow        *types.AuthFlow
	Transaction *OAuthTransaction
}

// OAuthLoginContext carries server-side PKCE material into a Provider during callback completion.
type OAuthLoginContext struct {
	RedirectURI  string
	CodeVerifier string
}

// NewOAuthTransaction creates state and an S256 PKCE pair for one upstream authorization request.
func NewOAuthTransaction(flowID, connection, redirectURI string) (*OAuthTransaction, error) {
	if flowID == "" || connection == "" || redirectURI == "" {
		return nil, errors.New("oauth transaction context is incomplete")
	}
	u, err := url.ParseRequestURI(redirectURI)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("oauth redirect URI must be an absolute HTTPS URL")
	}

	state, err := randomBase64URL(oauthRandomBytes)
	if err != nil {
		return nil, err
	}
	verifier, err := randomBase64URL(oauthRandomBytes)
	if err != nil {
		return nil, err
	}

	return &OAuthTransaction{
		FlowID:        flowID,
		Connection:    connection,
		RedirectURI:   redirectURI,
		State:         state,
		CodeVerifier:  verifier,
		CodeChallenge: S256Challenge(verifier),
		CreatedAt:     time.Now().UTC(),
	}, nil
}

// S256Challenge derives the RFC 7636 S256 challenge for a verifier.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomBase64URL(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// IsOAuthRedirectConnection reports whether a connection uses an upstream browser redirect.
// The connection name is the discriminator; no transport-level mode field is involved.
func IsOAuthRedirectConnection(connection string) bool {
	return connection == TypeGoogle || connection == TypeGithub
}

// OAuthLoginContextFromParams finds callback-only OAuth material appended by IDPAuthenticator.
func OAuthLoginContextFromParams(params []any) *OAuthLoginContext {
	for i := len(params) - 1; i >= 0; i-- {
		if value, ok := params[i].(*OAuthLoginContext); ok {
			return value
		}
	}
	return nil
}

package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"

	pkgtoken "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
)

const ClaimNickname = "nic"
const ClaimPicture = "pic"
const ClaimNonce = "nonce"

const TokenTypeIDToken pkgtoken.TokenType = "id"

// IDToken represents an OpenID Connect-style ID Token.
// Signed with the domain key (v4.public), no payload encryption.
// Contains basic user profile for frontend display only.
type IDToken struct {
	pkgtoken.Claims
	nickname string
	picture  string
	nonce    string
}

// ==================== Builder ====================

type IDTokenBuilder struct {
	openID   string
	nickname string
	picture  string
	nonce    string
}

func NewIDTokenBuilder() *IDTokenBuilder {
	return &IDTokenBuilder{}
}

func (b *IDTokenBuilder) OpenID(openID string) *IDTokenBuilder {
	b.openID = openID
	return b
}

func (b *IDTokenBuilder) Nickname(nickname string) *IDTokenBuilder {
	b.nickname = nickname
	return b
}

func (b *IDTokenBuilder) Picture(picture string) *IDTokenBuilder {
	b.picture = picture
	return b
}

func (b *IDTokenBuilder) Nonce(nonce string) *IDTokenBuilder {
	b.nonce = nonce
	return b
}

func (b *IDTokenBuilder) Build(claims pkgtoken.Claims) pkgtoken.Token {
	claims.Subject = b.openID
	return &IDToken{
		Claims:   claims,
		nickname: b.nickname,
		picture:  b.picture,
		nonce:    b.nonce,
	}
}

// ==================== Token Interface ====================

func (t *IDToken) Type() pkgtoken.TokenType {
	return TokenTypeIDToken
}

func (t *IDToken) Build() (*paseto.Token, error) {
	pt := paseto.NewToken()
	if err := t.SetStandardClaims(&pt); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	if t.nickname != "" {
		if err := pt.Set(ClaimNickname, t.nickname); err != nil {
			return nil, fmt.Errorf("set nickname: %w", err)
		}
	}
	if t.picture != "" {
		if err := pt.Set(ClaimPicture, t.picture); err != nil {
			return nil, fmt.Errorf("set picture: %w", err)
		}
	}
	if t.nonce != "" {
		if err := pt.Set(ClaimNonce, t.nonce); err != nil {
			return nil, fmt.Errorf("set nonce: %w", err)
		}
	}
	return &pt, nil
}

func (t *IDToken) ExpiresIn() time.Duration {
	return t.GetExpiresIn()
}

func (t *IDToken) GetClientID() string { return t.Audience }

func (t *IDToken) GetNickname() string { return t.nickname }

func (t *IDToken) GetPicture() string { return t.picture }

// ==================== Parse ====================

func ParseIDToken(pasetoToken *paseto.Token) (*IDToken, error) {
	claims, err := pkgtoken.ParseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	var nickname string
	if err := pasetoToken.Get(ClaimNickname, &nickname); err != nil {
		nickname = ""
	}

	var picture string
	if err := pasetoToken.Get(ClaimPicture, &picture); err != nil {
		picture = ""
	}

	return &IDToken{
		Claims:   claims,
		nickname: nickname,
		picture:  picture,
	}, nil
}

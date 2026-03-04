package idtoken

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"

	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
)

const ClaimNickname = "nic"
const ClaimPicture = "pic"

const TokenTypeIDToken tokendef.TokenType = "id"

// IDToken represents an OpenID Connect-style ID Token.
// Signed with the domain key (v4.public), no payload encryption.
// Contains basic user profile for frontend display only.
type IDToken struct {
	tokendef.Claims
	nickname string
	picture  string
}

// ==================== Builder ====================

type Builder struct {
	openID   string
	nickname string
	picture  string
}

func Parse(pasetoToken *paseto.Token) (*IDToken, error) {
	claims, err := tokendef.ParseClaims(pasetoToken)
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

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) OpenID(openID string) *Builder {
	b.openID = openID
	return b
}

func (b *Builder) Nickname(nickname string) *Builder {
	b.nickname = nickname
	return b
}

func (b *Builder) Picture(picture string) *Builder {
	b.picture = picture
	return b
}

func (b *Builder) Build(claims tokendef.Claims) tokendef.Token {
	claims.Subject = b.openID
	return &IDToken{
		Claims:   claims,
		nickname: b.nickname,
		picture:  b.picture,
	}
}

func (t *IDToken) Type() tokendef.TokenType {
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
	return &pt, nil
}

func (t *IDToken) ExpiresIn() time.Duration {
	return t.GetExpiresIn()
}

func (t *IDToken) GetNickname() string { return t.nickname }

func (t *IDToken) GetPicture() string { return t.picture }

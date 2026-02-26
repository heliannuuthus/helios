package paseto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/go-json-experiment/json"
)

var (
	ErrInvalidFooter = errors.New("invalid footer")
	ErrKIDNotFound   = errors.New("kid not found in footer")
)

// Footer represents the JSON footer of a PASETO token.
//
//	{"kid":"k4.pid.xxxx"}
type Footer struct {
	KID string `json:"kid"`
}

func NewFooter(kid string) Footer {
	return Footer{KID: kid}
}

func ParseFooter(data []byte) (Footer, error) {
	if len(data) == 0 {
		return Footer{}, fmt.Errorf("%w: empty footer", ErrInvalidFooter)
	}
	var f Footer
	if err := json.Unmarshal(data, &f); err != nil {
		return Footer{}, fmt.Errorf("%w: %w", ErrInvalidFooter, err)
	}
	if f.KID == "" {
		return Footer{}, fmt.Errorf("%w: missing kid field", ErrInvalidFooter)
	}
	return f, nil
}

func (f Footer) Marshal() ([]byte, error) {
	return json.Marshal(f)
}

// ExtractKID extracts the kid from a raw PASETO token string's footer segment.
func ExtractKID(tokenString string) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 4 || parts[3] == "" {
		return "", fmt.Errorf("%w: no footer segment", ErrKIDNotFound)
	}
	footerBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("%w: decode footer: %w", ErrInvalidFooter, err)
	}
	f, err := ParseFooter(footerBytes)
	if err != nil {
		return "", err
	}
	return f.KID, nil
}

package paseto

import (
	"errors"
	"fmt"

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

func (f *Footer) Unmarshal(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: empty footer", ErrInvalidFooter)
	}
	if err := json.Unmarshal(data, f); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidFooter, err)
	}
	if f.KID == "" {
		return fmt.Errorf("%w: missing kid field", ErrKIDNotFound)
	}
	return nil
}

func (f Footer) Marshal() ([]byte, error) {
	return json.Marshal(f)
}

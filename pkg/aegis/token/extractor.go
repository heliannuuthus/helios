package token

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
	pasetokit "github.com/heliannuuthus/helios/pkg/aegis/utils/paseto"
)

// extractor per-audience 的公共基底，持有公钥 Provider 和 audience，
// 提供 ExtractKID 能力供 Verifier 和 Decryptor 使用。
type extractor struct {
	audience string
	key.Provider
}

func NewExtractor(audience string, signKeyProvider key.Provider) *extractor {
	return &extractor{
		audience: audience,
		Provider: signKeyProvider,
	}
}

// ExtractKID 从 token string 的 footer 段解析 kid。
func (e *extractor) ExtractKID(tokenString string) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 4 || parts[3] == "" {
		return "", fmt.Errorf("%w: no footer segment", pasetokit.ErrKIDNotFound)
	}
	footerBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("%w: decode footer: %w", pasetokit.ErrInvalidFooter, err)
	}
	var f pasetokit.Footer
	if err := f.Unmarshal(footerBytes); err != nil {
		return "", err
	}
	return f.KID, nil
}

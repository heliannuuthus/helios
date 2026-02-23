package token

import "github.com/heliannuuthus/helios/pkg/aegis/key"

// Decryptor 解密器类型别名（SDK 层只暴露解密能力）
type Decryptor = key.Cryptor

// NewDecryptor 创建 Decryptor
func NewDecryptor(provider key.Provider, id string) *Decryptor {
	return key.NewCryptor(provider, id)
}

// ErrDecryptFailed 解密失败错误
var ErrDecryptFailed = key.ErrDecryptFailed

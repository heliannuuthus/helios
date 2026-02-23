package token

import "github.com/heliannuuthus/helios/pkg/aegis/key"

// Encryptor 加解密器类型别名（内部使用完整能力）
type Encryptor = key.Cryptor

// NewEncryptor 创建 Encryptor
func NewEncryptor(provider key.Provider, id string) *Encryptor {
	return key.NewCryptor(provider, id)
}

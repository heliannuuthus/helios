package cache

import "github.com/heliannuuthus/helios/aegis/internal/models"

// Key 统一密钥结构（派生后的 raw bytes）。
// 不同场景按需填充：
//   - 签名域/应用：PrivateKey + PublicKey
//   - 加密服务：SecretKey
type Key struct {
	SecretKey  []byte // 对称密钥（32 字节，v4.local 加解密）
	PrivateKey []byte // Ed25519 私钥（64 字节，v4.public 签名）
	PublicKey  []byte // Ed25519 公钥（32 字节，v4.public 验签）
}

type Keys struct {
	Main Key
	Keys []Key
}

// DomainWithKey aegis 内部的域（含派生后密钥）
type DomainWithKey struct {
	models.Domain
	Keys Keys
}

// ServiceWithKey aegis 内部的服务（含派生后密钥）
type ServiceWithKey struct {
	models.Service
	Keys Keys
}

// ApplicationWithKey aegis 内部的应用（含派生后密钥）
type ApplicationWithKey struct {
	models.Application
	Keys Keys
}

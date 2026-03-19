package models

// Domain 域（从 proto 转换，不含 GORM 标签）
type Domain struct {
	DomainID    string   `json:"domain_id"`
	Name        string   `json:"name"`
	Description *string  `json:"description"`
	AllowedIDPs []string `json:"allowed_idps"`
}

// DomainWithKey 带签名密钥的 Domain（Main/Keys 不序列化到 API）
type DomainWithKey struct {
	Domain
	Main []byte   `json:"-"` // 当前主密钥（48 字节 seed）
	Keys [][]byte `json:"-"` // 所有有效密钥
}

package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Client OAuth2 客户端
type Client struct {
	ID                    string    `gorm:"primaryKey;column:id;size:64"`
	Name                  string    `gorm:"column:name;size:128;not null"`
	Domain                Domain    `gorm:"column:domain;size:32;not null;index"`
	AccessTokenExpiresIn  int       `gorm:"column:access_token_expires_in;default:7200"`
	RefreshTokenExpiresIn int       `gorm:"column:refresh_token_expires_in;default:604800"`
	CreatedAt             time.Time `gorm:"column:created_at"`
	UpdatedAt             time.Time `gorm:"column:updated_at"`

	// 关联（不存储在 client 表）
	RedirectURIs []ClientRedirectURI `gorm:"foreignKey:ClientID"`
	AllowedIDPs  []ClientIDP         `gorm:"foreignKey:ClientID"`
}

func (Client) TableName() string {
	return "t_auth_client"
}

// ValidateRedirectURI 验证重定向 URI
func (c *Client) ValidateRedirectURI(uri string) bool {
	for _, r := range c.RedirectURIs {
		if r.URI == uri {
			return true
		}
	}
	return false
}

// ValidateIDP 验证 IDP 是否允许
func (c *Client) ValidateIDP(idp IDP) bool {
	// IDP 所属域必须匹配
	if idp.GetDomain() != c.Domain {
		return false
	}
	// 没有配置则允许该域下所有 IDP
	if len(c.AllowedIDPs) == 0 {
		return true
	}
	for _, allowed := range c.AllowedIDPs {
		if allowed.IDP == idp {
			return true
		}
	}
	return false
}

// ClientRedirectURI 客户端重定向 URI
type ClientRedirectURI struct {
	ID       uint   `gorm:"primaryKey;autoIncrement"`
	ClientID string `gorm:"column:client_id;size:64;not null;index"`
	URI      string `gorm:"column:uri;size:512;not null"`
}

func (ClientRedirectURI) TableName() string {
	return "t_auth_client_redirect_uri"
}

// ClientIDP 客户端允许的 IDP
type ClientIDP struct {
	ID       uint   `gorm:"primaryKey;autoIncrement"`
	ClientID string `gorm:"column:client_id;size:64;not null;index"`
	IDP      IDP    `gorm:"column:idp;size:64;not null"`
}

func (ClientIDP) TableName() string {
	return "t_auth_client_idp"
}

// GenerateClientID 生成客户端 ID
func GenerateClientID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

package cache

import (
	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// Service 带解密密钥的 Service
type Service struct {
	models.Service
	Key []byte // 解密后的密钥
}

// Application 带解密密钥的 Application
type Application struct {
	models.Application
	Key []byte // 解密后的密钥（如果存在）
}

// Domain 带签名密钥的 Domain
type Domain struct {
	models.Domain
	SignKey []byte // 签名密钥
}

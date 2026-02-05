// Package pasetokit 提供 PASETO token 相关的加解密功能
package pasetokit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// 错误定义
var (
	ErrInvalidSignature = errors.New("invalid signature")
)

// ==================== Footer 加密解密 ====================

// EncryptFooter 使用对称密钥加密数据（用于 footer）
func EncryptFooter(key paseto.V4SymmetricKey, data []byte) string {
	token := paseto.NewToken()
	token.SetString("data", string(data))
	return token.V4Encrypt(key, nil)
}

// DecryptFooter 使用对称密钥解密 footer
func DecryptFooter(key paseto.V4SymmetricKey, encrypted string) ([]byte, error) {
	parser := paseto.NewParser()
	token, err := parser.ParseV4Local(key, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt footer: %w", err)
	}

	data, err := token.GetString("data")
	if err != nil {
		return nil, fmt.Errorf("get footer data: %w", err)
	}

	return []byte(data), nil
}

// ==================== Token 签名与验证 ====================

// SignToken 签名 Token
func SignToken(token *paseto.Token, secretKey paseto.V4AsymmetricSecretKey, footer []byte) string {
	var footerPtr []byte
	if len(footer) > 0 {
		footerPtr = footer
	}
	return token.V4Sign(secretKey, footerPtr)
}

// VerifyToken 验证并解析 Token
func VerifyToken(tokenString string, publicKey paseto.V4AsymmetricPublicKey) (*paseto.Token, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	token, err := parser.ParseV4Public(publicKey, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	return token, nil
}

// ==================== Base64 工具函数 ====================

// Base64URLDecode Base64URL 解码（无填充）
func Base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// Base64StdDecode Base64 标准解码
func Base64StdDecode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

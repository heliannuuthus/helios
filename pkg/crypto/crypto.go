package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// Hash 对数据进行 SHA256 哈希，返回 hex 编码
func Hash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Encrypt 使用 AES-256-GCM 加密
// key: 32 字节密钥
// plaintext: 明文
// aad: 附加认证数据（可选）
// 返回: Base64 编码的 (IV || 密文 || Tag)
func Encrypt(key []byte, plaintext string, aad string) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("密钥长度错误: 期望 32 字节, 实际 %d 字节", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建 AES cipher 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建 GCM 失败: %w", err)
	}

	// 生成随机 IV（12 字节）
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("生成 IV 失败: %w", err)
	}

	// 加密
	var aadBytes []byte
	if aad != "" {
		aadBytes = []byte(aad)
	}
	ciphertext := gcm.Seal(nil, iv, []byte(plaintext), aadBytes)

	// IV || 密文
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:len(iv)], iv)
	copy(result[len(iv):], ciphertext)

	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypt 使用 AES-256-GCM 解密
// key: 32 字节密钥
// encrypted: Base64 编码的 (IV || 密文 || Tag)
// aad: 附加认证数据（必须与加密时一致）
func Decrypt(key []byte, encrypted string, aad string) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("密钥长度错误: 期望 32 字节, 实际 %d 字节", len(key))
	}

	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("解码密文失败: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建 AES cipher 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建 GCM 失败: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("密文长度不足")
	}

	iv := data[:nonceSize]
	ciphertext := data[nonceSize:]

	// 解密
	var aadBytes []byte
	if aad != "" {
		aadBytes = []byte(aad)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, aadBytes)
	if err != nil {
		return "", fmt.Errorf("解密失败: %w", err)
	}

	return string(plaintext), nil
}

// Mask 脱敏处理
// 保留前 prefixLen 位和后 suffixLen 位，中间用 mask 替换
func Mask(data string, prefixLen, suffixLen int, mask string) string {
	if len(data) <= prefixLen+suffixLen {
		return data
	}
	return data[:prefixLen] + mask + data[len(data)-suffixLen:]
}

// MaskPhone 手机号脱敏 13800138000 -> 138****8000
func MaskPhone(phone string) string {
	return Mask(phone, 3, 4, "****")
}

// EncryptAESGCM 使用 AES-256-GCM 加密（字节数组版本）
// key: 32 字节密钥
// plaintext: 明文字节数组
// aad: 附加认证数据（可选）
// 返回: Base64 编码的 (IV || 密文 || Tag)
func EncryptAESGCM(key []byte, plaintext []byte, aad string) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("密钥长度错误: 期望 32 字节, 实际 %d 字节", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AES cipher 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}

	// 生成随机 IV（12 字节）
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("生成 IV 失败: %w", err)
	}

	// 加密
	var aadBytes []byte
	if aad != "" {
		aadBytes = []byte(aad)
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, aadBytes)

	// IV || 密文
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result[:len(iv)], iv)
	copy(result[len(iv):], ciphertext)

	return result, nil
}

// DecryptAESGCM 使用 AES-256-GCM 解密（字节数组版本）
// key: 32 字节密钥
// encrypted: (IV || 密文 || Tag) 字节数组
// aad: 附加认证数据（必须与加密时一致）
func DecryptAESGCM(key []byte, encrypted []byte, aad string) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("密钥长度错误: 期望 32 字节, 实际 %d 字节", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AES cipher 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, errors.New("密文长度不足")
	}

	iv := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	// 解密
	var aadBytes []byte
	if aad != "" {
		aadBytes = []byte(aad)
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, aadBytes)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %w", err)
	}

	return plaintext, nil
}

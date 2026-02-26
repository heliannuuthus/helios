package alipay

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// parsePrivateKey 解析 RSA 私钥（支持 PEM 和 DER Base64 格式）
func parsePrivateKey(privateKeyData string) (*rsa.PrivateKey, error) {
	var keyBytes []byte
	var err error

	// 尝试解析为 PEM 格式
	block, _ := pem.Decode([]byte(privateKeyData))
	if block != nil {
		keyBytes = block.Bytes
	} else {
		// 尝试解析为 DER Base64 格式
		keyBytes, err = base64.StdEncoding.DecodeString(privateKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode private key (not PEM or Base64): %w", err)
		}
	}

	// 尝试 PKCS8 格式
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err == nil {
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		return priv, nil
	}

	// 尝试 PKCS1 格式
	priv, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key (tried PKCS8 and PKCS1): %w", err)
	}

	return priv, nil
}

// parsePublicKey 解析 RSA 公钥（支持 PEM 和 DER Base64 格式）
func parsePublicKey(publicKeyData string) (*rsa.PublicKey, error) {
	var keyBytes []byte
	var err error

	// 尝试解析为 PEM 格式
	block, _ := pem.Decode([]byte(publicKeyData))
	if block != nil {
		keyBytes = block.Bytes
	} else {
		// 尝试解析为 DER Base64 格式
		keyBytes, err = base64.StdEncoding.DecodeString(publicKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode public key (not PEM or Base64): %w", err)
		}
	}

	pub, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return rsaPub, nil
}

// buildSignContent 构建待签名字符串
func buildSignContent(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		if k == "sign" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	items := make([]string, 0, len(keys))
	for _, k := range keys {
		items = append(items, fmt.Sprintf("%s=%s", k, params[k]))
	}
	return strings.Join(items, "&")
}

// signWithRSA2 使用 RSA2 算法签名
func signWithRSA2(privateKey *rsa.PrivateKey, data string) (string, error) {
	h := sha256.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sigBytes), nil
}

// verifySign 验证支付宝响应签名
func verifySign(publicKey *rsa.PublicKey, signData, sign string) error {
	signBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return fmt.Errorf("failed to decode sign: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(signData))
	hashed := h.Sum(nil)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed, signBytes)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

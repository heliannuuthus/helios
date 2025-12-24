package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// JWK 结构
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x,omitempty"` // Ed25519 公钥
	D   string `json:"d,omitempty"` // Ed25519 私钥
	K   string `json:"k,omitempty"` // 对称密钥
}

func b64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func generateKid() string {
	bytes := make([]byte, 8)
	_, _ = rand.Read(bytes)
	return b64URLEncode(bytes)
}

func generateEd25519JWK() *JWK {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)

	// Ed25519 私钥的前 32 字节是种子
	seed := privateKey.Seed()

	return &JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		Kid: generateKid(),
		Use: "sig",
		Alg: "EdDSA",
		X:   b64URLEncode(publicKey),
		D:   b64URLEncode(seed),
	}
}

func generateAESJWK() *JWK {
	keyBytes := make([]byte, 32) // AES-256
	_, _ = rand.Read(keyBytes)

	return &JWK{
		Kty: "oct",
		Kid: generateKid(),
		Use: "enc",
		Alg: "A256GCM",
		K:   b64URLEncode(keyBytes),
	}
}

func main() {
	fmt.Println("============================================================")
	fmt.Println("生成 JWK 密钥")
	fmt.Println("============================================================")
	fmt.Println()

	// 生成 JWS 私钥（Ed25519）
	jwsKey := generateEd25519JWK()

	// 生成 JWE 密钥（AES-256-GCM）
	jweKey := generateAESJWK()

	// JSON 序列化后 base64url 编码
	jwsKeyJSON, _ := json.Marshal(jwsKey)
	jweKeyJSON, _ := json.Marshal(jweKey)

	jwsKeyB64 := b64URLEncode(jwsKeyJSON)
	jweKeyB64 := b64URLEncode(jweKeyJSON)

	fmt.Println("请将以下内容添加到 .env 文件：")
	fmt.Println("------------------------------------------------------------")
	fmt.Println()
	fmt.Printf("SIGN_KEY=%s\n", jwsKeyB64)
	fmt.Println()
	fmt.Printf("ENC_KEY=%s\n", jweKeyB64)
	fmt.Println()
	fmt.Println("------------------------------------------------------------")
	fmt.Println()

	// 提取公钥
	publicJWK := &JWK{
		Kty: jwsKey.Kty,
		Crv: jwsKey.Crv,
		Kid: jwsKey.Kid,
		Use: jwsKey.Use,
		Alg: jwsKey.Alg,
		X:   jwsKey.X,
	}

	publicJWKJSON, _ := json.MarshalIndent(publicJWK, "", "  ")
	fmt.Println("签名公钥（JWKS 端点返回，可公开）：")
	fmt.Println(string(publicJWKJSON))
	fmt.Println()

	fmt.Println("============================================================")
	fmt.Println("✅ 密钥生成完成")
	fmt.Println("============================================================")
}

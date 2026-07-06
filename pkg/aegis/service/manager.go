package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/pkg/aegis/utilities/client"
	"github.com/heliannuuthus/pkg/aegis/utilities/issuer"
	"github.com/heliannuuthus/pkg/aegis/utilities/key"
	tokendef "github.com/heliannuuthus/pkg/aegis/utilities/token"
)

const maxResponseBody = 1 << 20

type checkRequest struct {
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	Relation    string `json:"relation"`
	ObjectType  string `json:"object_type"`
	ObjectID    string `json:"object_id"`
}

type checkResponse struct {
	Allowed bool   `json:"allowed"`
	Error   string `json:"error,omitempty"`
}

// Manager 管理多 audience 的 Decryptor（token 解析）和 Issuer（CT 签发）。
// 同时内化关系检查逻辑，通过 Check 方法远程校验权限。
type Manager struct {
	endpoint           string
	encryptKeyProvider key.Provider
	signKeyProvider    key.Provider

	mu         sync.RWMutex
	decryptors map[string]*Decryptor
	issuers    map[string]*issuer.Issuer
}

// NewManager 创建 Manager。seedProvider 提供原始 seed，内部自动派生加解密和签名密钥。
func NewManager(endpoint string, seedProvider key.Provider) *Manager {
	return &Manager{
		endpoint:           strings.TrimSuffix(endpoint, "/"),
		encryptKeyProvider: key.EncryptKeyProvider(seedProvider),
		signKeyProvider:    key.SignKeyProvider(seedProvider),
		decryptors:         make(map[string]*Decryptor),
		issuers:            make(map[string]*issuer.Issuer),
	}
}

// Decryptor 按 audience 获取或创建 Decryptor。
func (m *Manager) Decryptor(audience string) *Decryptor {
	m.mu.RLock()
	d, ok := m.decryptors[audience]
	m.mu.RUnlock()
	if ok {
		return d
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if d, ok := m.decryptors[audience]; ok {
		return d
	}

	d = NewDecryptor(audience, m.encryptKeyProvider, key.NewPublicKeyFetcher(m.endpoint))
	m.decryptors[audience] = d
	return d
}

// Check 检查主体是否对资源具备指定关系。
// 内部用 audience 签发 CT 做服务间认证。
func (m *Manager) Check(ctx context.Context, audience, subjectType, subjectID, rel, objectType, objectID string) (bool, error) {
	ct, err := m.getIssuer(audience).Issue(ctx)
	if err != nil {
		return false, fmt.Errorf("issue CT: %w", err)
	}

	req := checkRequest{
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Relation:    rel,
		ObjectType:  objectType,
		ObjectID:    objectID,
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("marshal request: %w", err)
	}

	checkURL := m.endpoint + "/check"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, checkURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", tokendef.TokenTypeBearer+" "+ct)

	resp, err := client.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Warn("[Manager] close response body", "error", err)
		}
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return false, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("check failed with status %d: %s", resp.StatusCode, body)
	}

	var checkResp checkResponse
	if err := json.Unmarshal(body, &checkResp); err != nil {
		return false, fmt.Errorf("unmarshal response: %w", err)
	}

	return checkResp.Allowed, nil
}

func (m *Manager) getIssuer(id string) *issuer.Issuer {
	m.mu.RLock()
	iss, ok := m.issuers[id]
	m.mu.RUnlock()
	if ok {
		return iss
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if iss, ok := m.issuers[id]; ok {
		return iss
	}

	iss = issuer.NewIssuer(m.signKeyProvider, id)
	m.issuers[id] = iss
	return iss
}

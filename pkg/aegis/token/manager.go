package token

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	subjectTypeUser = "user"
	subjectTypeApp  = "app"
	maxResponseBody = 1 << 20
)

type checkRequest struct {
	SubjectType string   `json:"subject_type"`
	SubjectID   string   `json:"subject_id"`
	Relations   []string `json:"relations"`
	ObjectType  string   `json:"object_type"`
	ObjectID    string   `json:"object_id"`
}

type checkResponse struct {
	Results map[string]bool `json:"results"`
	Error   string          `json:"error,omitempty"`
	Message string          `json:"message,omitempty"`
}

// Manager 管理多 audience 的 Decryptor（token 解析）和 Issuer（CT 签发）。
// 同时内化关系检查逻辑，通过 Check 方法远程校验权限。
type Manager struct {
	endpoint           string
	encryptKeyProvider key.Provider
	signKeyProvider    key.Provider
	httpClient         *http.Client

	mu         sync.RWMutex
	decryptors map[string]*Decryptor
	issuers    map[string]*Issuer
}

// NewManager 创建 Manager。seedProvider 提供原始 seed，内部自动派生加解密和签名密钥。
func NewManager(endpoint string, seedProvider key.Provider) *Manager {
	return &Manager{
		endpoint:           strings.TrimSuffix(endpoint, "/"),
		encryptKeyProvider: key.EncryptKeyProvider(seedProvider),
		signKeyProvider:    key.SignKeyProvider(seedProvider),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		decryptors: make(map[string]*Decryptor),
		issuers:    make(map[string]*Issuer),
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

// Check 批量检查主体是否具备指定关系。
// subjectType/subjectID 为空时从 token 自动推断。
func (m *Manager) Check(ctx context.Context, t tokendef.AccessToken, relations []string, objectType, objectID, subjectType, subjectID string) (map[string]bool, error) {
	if subjectType == "" || subjectID == "" {
		subjectType = subjectTypeApp
		subjectID = t.ClientID()
		if t.Identified() {
			subjectType = subjectTypeUser
			subjectID = t.OpenID()
		}
	}

	ct, err := m.issuer(t.Audience()).Issue(ctx)
	if err != nil {
		return nil, fmt.Errorf("issue CT: %w", err)
	}

	req := checkRequest{
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Relations:   relations,
		ObjectType:  objectType,
		ObjectID:    objectID,
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	checkURL := m.endpoint + "/check"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, checkURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", tokendef.TokenTypeBearer+" "+ct)

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[Manager] close response body: %v", err)
		}
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check failed with status %d: %s", resp.StatusCode, body)
	}

	var checkResp checkResponse
	if err := json.Unmarshal(body, &checkResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return checkResp.Results, nil
}

func (m *Manager) issuer(audience string) *Issuer {
	m.mu.RLock()
	iss, ok := m.issuers[audience]
	m.mu.RUnlock()
	if ok {
		return iss
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if iss, ok := m.issuers[audience]; ok {
		return iss
	}

	iss = NewIssuer(m.signKeyProvider, audience)
	m.issuers[audience] = iss
	return iss
}

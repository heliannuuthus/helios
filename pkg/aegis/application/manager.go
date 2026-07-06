// Package application 提供面向应用的 client_credentials token 管理能力。
// 向 Aegis 签发 CT 并请求凭证，按 clientID-audience-scope 维度缓存，
// 凭证剩余寿命不足 1/5 时惰性异步刷新，过期时同步等待刷新。
//
// client_credentials 流程不签发 refresh_token（RFC 6749 §4.4.3: "A refresh token SHOULD NOT be included"），
// 刷新通过重新签发 CT 请求新的 access_token 实现。
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc6749#section-4.4.3
//   - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-4.2.1
package application

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/pkg/aegis/utilities/client"
	"github.com/heliannuuthus/pkg/aegis/utilities/issuer"
	"github.com/heliannuuthus/pkg/aegis/utilities/key"
	"github.com/heliannuuthus/pkg/aegis/utilities/syncx"
	tokendef "github.com/heliannuuthus/pkg/aegis/utilities/token"
)

const maxResponseBody = 1 << 20

type tokenEntry struct {
	accessToken string
	deadline    time.Time
	refreshAt   time.Time
}

func (e *tokenEntry) expired() bool {
	return time.Now().After(e.deadline)
}

func (e *tokenEntry) unhealthy() bool {
	return time.Now().After(e.refreshAt)
}

type slot struct {
	mu       sync.Mutex
	entry    *tokenEntry
	inflight chan struct{}
	err      error
}

// TokenManager 面向应用的 client_credentials token 管理器。
type TokenManager struct {
	endpoint        string
	signKeyProvider key.Provider
	slots           syncx.Map[string, *slot]

	mu      sync.RWMutex
	issuers map[string]*issuer.Issuer
}

// NewTokenManager 创建 TokenManager。
//
//	endpoint: aegis 服务地址（如 https://aegis.example.com/auth）
//	seedProvider: 48 字节 seed，内部自动派生签名密钥
func NewTokenManager(endpoint string, seedProvider key.Provider) *TokenManager {
	return &TokenManager{
		endpoint:        strings.TrimSuffix(endpoint, "/"),
		signKeyProvider: key.SignKeyProvider(seedProvider),
		issuers:         make(map[string]*issuer.Issuer),
	}
}

// GetToken 获取单个 audience 的 access token。
func (m *TokenManager) GetToken(ctx context.Context, clientID, audience string, scopes ...string) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("audience is required")
	}
	entry, err := m.resolve(ctx, clientID, audience, scopes)
	if err != nil {
		return "", err
	}
	return entry.accessToken, nil
}

// GetTokens 批量获取多个 audience 的 access token。
// 先检查缓存，仅对缺失 / 过期的 audience 发起单次批量请求。
func (m *TokenManager) GetTokens(ctx context.Context, clientID string, audiences map[string][]string) (map[string]string, error) {
	if len(audiences) == 0 {
		return nil, fmt.Errorf("audiences is required")
	}

	result := make(map[string]string, len(audiences))
	missing := make(map[string][]string)

	for aud, scopes := range audiences {
		k := buildKey(clientID, aud, scopes)
		if s, ok := m.slots.Load(k); ok {
			s.mu.Lock()
			if s.entry != nil && !s.entry.expired() {
				if s.entry.unhealthy() {
					m.refresh(s, clientID, aud, scopes)
				}
				result[aud] = s.entry.accessToken
				s.mu.Unlock()
				continue
			}
			s.mu.Unlock()
		}
		missing[aud] = scopes
	}

	if len(missing) == 0 {
		return result, nil
	}

	entries, err := m.fetchTokens(ctx, clientID, missing)
	if err != nil {
		return nil, err
	}

	for aud, entry := range entries {
		scopes := missing[aud]
		k := buildKey(clientID, aud, scopes)
		s, _ := m.slots.LoadOrStore(k, &slot{})
		s.mu.Lock()
		s.entry = entry
		s.mu.Unlock()
		result[aud] = entry.accessToken
	}

	return result, nil
}

// Invalidate 清除指定 clientID-audience-scope 的缓存。
func (m *TokenManager) Invalidate(clientID, audience string, scopes ...string) {
	m.slots.Delete(buildKey(clientID, audience, scopes))
}

// InvalidateAll 清除所有缓存。
func (m *TokenManager) InvalidateAll() {
	m.slots.Clear()
}

func (m *TokenManager) getIssuer(id string) *issuer.Issuer {
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

func (m *TokenManager) resolve(ctx context.Context, clientID, audience string, scopes []string) (*tokenEntry, error) {
	s, _ := m.slots.LoadOrStore(buildKey(clientID, audience, scopes), &slot{})

	s.mu.Lock()
	switch {
	case s.entry == nil || s.entry.expired():
		done := m.refresh(s, clientID, audience, scopes)
		s.mu.Unlock()

		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		if s.err != nil {
			return nil, s.err
		}
		return s.entry, nil

	case s.entry.unhealthy():
		m.refresh(s, clientID, audience, scopes)
		entry := s.entry
		s.mu.Unlock()
		return entry, nil

	default:
		entry := s.entry
		s.mu.Unlock()
		return entry, nil
	}
}

func (m *TokenManager) refresh(s *slot, clientID, aud string, scopes []string) <-chan struct{} {
	if s.inflight != nil {
		return s.inflight
	}
	s.inflight = make(chan struct{})
	s.err = nil
	go m.doRefresh(s, clientID, aud, scopes)
	return s.inflight
}

func (m *TokenManager) doRefresh(s *slot, clientID, aud string, scopes []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	entry, err := m.fetchToken(ctx, clientID, aud, scopes)

	s.mu.Lock()
	if err != nil {
		slog.Warn("[application.TokenManager] refresh failed", "audience", aud, "error", err)
		s.err = err
	} else {
		s.entry = entry
		s.err = nil
	}
	ch := s.inflight
	s.inflight = nil
	s.mu.Unlock()

	close(ch)
}

type tokenRequest struct {
	GrantType string                       `json:"grant_type"`
	Audience  string                       `json:"audience,omitempty"`
	Scope     string                       `json:"scope,omitempty"`
	Audiences map[string]*audienceScopeReq `json:"audiences,omitempty"`
}

type audienceScopeReq struct {
	Scope string `json:"scope"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

func (m *TokenManager) fetchToken(ctx context.Context, clientID, aud string, scopes []string) (*tokenEntry, error) {
	req := tokenRequest{GrantType: "client_credentials", Audience: aud}
	if scope := strings.Join(scopes, " "); scope != "" {
		req.Scope = scope
	}

	tr, err := m.exchange(ctx, clientID, req)
	if err != nil {
		return nil, err
	}
	return toEntry(tr), nil
}

func (m *TokenManager) fetchTokens(ctx context.Context, clientID string, audiences map[string][]string) (map[string]*tokenEntry, error) {
	req := tokenRequest{
		GrantType: "client_credentials",
		Audiences: make(map[string]*audienceScopeReq, len(audiences)),
	}
	for aud, scopes := range audiences {
		req.Audiences[aud] = &audienceScopeReq{Scope: strings.Join(scopes, " ")}
	}

	respMap, err := m.multiExchange(ctx, clientID, req)
	if err != nil {
		return nil, err
	}

	entries := make(map[string]*tokenEntry, len(respMap))
	for aud, tr := range respMap {
		entries[aud] = toEntry(tr)
	}
	return entries, nil
}

func (m *TokenManager) doExchange(ctx context.Context, clientID string, reqBody tokenRequest) ([]byte, error) {
	ct, err := m.getIssuer(clientID).Issue(ctx)
	if err != nil {
		return nil, fmt.Errorf("issue CT: %w", err)
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint+"/token", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", tokendef.TokenTypeBearer+" "+ct)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			slog.Warn("[application.TokenManager] close response body", "error", closeErr)
		}
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed (status %d): %s", resp.StatusCode, body)
	}

	return body, nil
}

func (m *TokenManager) exchange(ctx context.Context, clientID string, reqBody tokenRequest) (*tokenResponse, error) {
	body, err := m.doExchange(ctx, clientID, reqBody)
	if err != nil {
		return nil, err
	}

	var result tokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return &result, nil
}

func (m *TokenManager) multiExchange(ctx context.Context, clientID string, reqBody tokenRequest) (map[string]*tokenResponse, error) {
	body, err := m.doExchange(ctx, clientID, reqBody)
	if err != nil {
		return nil, err
	}

	var result map[string]*tokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}
	return result, nil
}

func toEntry(tr *tokenResponse) *tokenEntry {
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	now := time.Now()
	return &tokenEntry{
		accessToken: tr.AccessToken,
		deadline:    now.Add(ttl),
		refreshAt:   now.Add(ttl * 4 / 5),
	}
}

func buildKey(clientID, aud string, scopes []string) string {
	sorted := make([]string, len(scopes))
	copy(sorted, scopes)
	sort.Strings(sorted)
	return clientID + ":" + aud + ":" + strings.Join(sorted, " ")
}

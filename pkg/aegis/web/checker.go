package web

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
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	subjectTypeUser = "user"
	subjectTypeApp  = "app"
	maxResponseBody = 1 << 20 // 1MB
)

type checkRequest struct {
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	Relation    string `json:"relation"`
	ObjectType  string `json:"object_type"`
	ObjectID    string `json:"object_id"`
}

type checkResponse struct {
	Permitted bool   `json:"permitted"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message,omitempty"`
}

// RelationChecker 远程关系鉴权客户端。
type RelationChecker struct {
	keyProvider key.Provider
	endpoint    string
	httpClient  *http.Client

	mu      sync.RWMutex
	issuers map[string]*token.Issuer
}

// NewRelationChecker 创建关系鉴权客户端。
func NewRelationChecker(endpoint string, keyProvider key.Provider) *RelationChecker {
	return &RelationChecker{
		keyProvider: keyProvider,
		endpoint:    strings.TrimSuffix(endpoint, "/"),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		issuers: make(map[string]*token.Issuer),
	}
}

// Check 检查主体是否具备指定关系。
func (c *RelationChecker) Check(ctx context.Context, t tokendef.Token, relation, objectType, objectID string) (bool, error) {
	subjectType := subjectTypeApp
	subjectID := t.GetClientID()

	if uat, ok := t.(*tokendef.UserAccessToken); ok && uat.Identified() {
		subjectType = subjectTypeUser
		subjectID = uat.OpenID()
	}

	cat, err := c.issuer(t.GetAudience()).Issue(ctx)
	if err != nil {
		return false, fmt.Errorf("issue CAT: %w", err)
	}

	req := checkRequest{
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Relation:    relation,
		ObjectType:  objectType,
		ObjectID:    objectID,
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("marshal request: %w", err)
	}

	checkURL := c.endpoint + "/auth/check"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, checkURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", tokendef.TokenTypeBearer+" "+cat)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("send request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("[RelationChecker] close response body: %v", err)
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

	return checkResp.Permitted, nil
}

func (c *RelationChecker) issuer(audience string) *token.Issuer {
	c.mu.RLock()
	iss, ok := c.issuers[audience]
	c.mu.RUnlock()
	if ok {
		return iss
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if iss, ok := c.issuers[audience]; ok {
		return iss
	}

	iss = token.NewIssuer(c.keyProvider, audience)
	c.issuers[audience] = iss
	return iss
}

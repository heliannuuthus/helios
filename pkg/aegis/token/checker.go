package token

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/heliannuuthus/helios/pkg/json"
)

// checkRequest 检查请求（内部使用）
type checkRequest struct {
	SubjectType string `json:"subject_type"` // 主体类型：user / app
	SubjectID   string `json:"subject_id"`   // 主体 ID：OpenID / ClientID
	Relation    string `json:"relation"`     // 关系类型
	ObjectType  string `json:"object_type"`  // 资源类型
	ObjectID    string `json:"object_id"`    // 资源 ID
}

// checkResponse 检查响应（内部使用）
type checkResponse struct {
	Permitted bool   `json:"permitted"`
	Error     string `json:"error,omitempty"`
	Message   string `json:"message,omitempty"`
}

// Checker 关系检查器
// 负责调用 Aegis /auth/check 接口检查关系
type Checker struct {
	issuer     *Issuer
	endpoint   string
	httpClient *http.Client
}

// NewChecker 创建关系检查器
// endpoint: Aegis 服务端点（如 http://auth.example.com）
// keyProvider: 提供签名私钥（用于签发 CAT）
func NewChecker(endpoint string, keyProvider SecretKeyProvider) *Checker {
	return &Checker{
		issuer:   NewIssuer(keyProvider),
		endpoint: strings.TrimSuffix(endpoint, "/"),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Check 检查关系
// vt: 验证后的 Token
// relation: 关系类型
// objectType: 资源类型
// objectID: 资源 ID
//
// 内部根据 Token 判断主体类型：
//   - 如果 User 不为空，则为 user，subjectID = User.Subject
//   - 如果 User 为空，则为 app（M2M），subjectID = ClientID
func (c *Checker) Check(ctx context.Context, vt *VerifiedToken, relation, objectType, objectID string) (bool, error) {
	// 判断主体类型
	subjectType := "user"
	var subjectID string
	if vt.User != nil && vt.User.Subject != "" {
		subjectID = vt.User.Subject
	} else {
		// M2M 场景：没有用户，使用应用身份
		subjectType = "app"
		subjectID = vt.ClientID
	}

	// 签发 CAT（使用 Audience）
	cat, err := c.issuer.Issue(ctx, vt.Audience)
	if err != nil {
		return false, fmt.Errorf("issue CAT: %w", err)
	}

	// 构建请求体
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

	// 构建 HTTP 请求
	checkURL := c.endpoint + "/auth/check"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, checkURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+cat)

	// 发送请求
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("read response: %w", err)
	}

	var checkResp checkResponse
	if err := json.Unmarshal(body, &checkResp); err != nil {
		return false, fmt.Errorf("unmarshal response: %w", err)
	}

	// 检查状态码
	switch resp.StatusCode {
	case http.StatusOK:
		return checkResp.Permitted, nil
	case http.StatusUnauthorized:
		return false, fmt.Errorf("CAT invalid: %s", checkResp.Message)
	default:
		return false, fmt.Errorf("check failed with status %d: %s", resp.StatusCode, checkResp.Message)
	}
}

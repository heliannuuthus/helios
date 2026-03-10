package client

import (
	"net/http"
	"strings"
	"time"
)

const (
	AuthorizationHeader  = "Authorization"
	ChallengeTokenHeader = "X-Challenge-Token"
)

var defaultClient = &http.Client{
	Timeout: 10 * time.Second,
}

// Get 返回 SDK 内部共享的 http.Client。
func Get() *http.Client {
	return defaultClient
}

// Do 使用内部 http.Client 执行请求。
func Do(req *http.Request) (*http.Response, error) {
	return defaultClient.Do(req)
}

// TrimBearer 去除 "Bearer " 前缀，返回 token 本体；无前缀则返回空串。
func TrimBearer(s string) string {
	if len(s) > 7 && strings.EqualFold(s[:7], "Bearer ") {
		return s[7:]
	}
	return ""
}

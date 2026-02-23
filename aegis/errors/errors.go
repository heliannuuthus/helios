// Package errors provides unified error handling for Auth service.
// nolint:revive // This package name is intentional for semantic clarity within the auth module.
package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// AuthError 带 HTTP 状态码的认证错误
type AuthError struct {
	HTTPStatus  int            `json:"-"`
	Code        string         `json:"error"`
	Description string         `json:"error_description,omitempty"`
	Data        map[string]any `json:"data,omitempty"`
}

// Error 实现 error 接口
func (e *AuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// GetHTTPStatus 获取 HTTP 状态码
func (e *AuthError) GetHTTPStatus() int {
	return e.HTTPStatus
}

// GetCode 获取错误码
func (e *AuthError) GetCode() string {
	return e.Code
}

// GetDescription 获取错误描述
func (e *AuthError) GetDescription() string {
	return e.Description
}

// GetData 获取附加数据
func (e *AuthError) GetData() map[string]any {
	return e.Data
}

// ==================== 错误码常量 ====================

const (
	// 400 Bad Request
	CodeInvalidRequest     = "invalid_request"
	CodeInvalidGrant       = "invalid_grant"
	CodeInvalidCredentials = "invalid_credentials"
	CodeClientNotFound     = "client_not_found"
	CodeServiceNotFound    = "service_not_found"

	// 401 Unauthorized
	CodeInvalidToken  = "invalid_token"
	CodeLoginRequired = "login_required"

	// 403 Forbidden
	CodeAccessDenied = "access_denied"

	// 404 Not Found
	CodeNotFound     = "not_found"
	CodeUserNotFound = "user_not_found"

	// 412 Precondition Failed
	CodeFlowNotFound = "flow_not_found"
	CodeFlowExpired  = "flow_expired"
	CodeFlowInvalid  = "flow_invalid"

	// 422 Unprocessable Entity
	CodeChallengeExpired = "challenge_expired"

	// 426 Upgrade Required
	CodeNoConnectionAvailable = "no_connection_available"

	// 428 Precondition Required
	CodeIdentityRequired = "identity_required"

	// 429 Too Many Requests
	CodeRateLimited = "rate_limited"

	// 500 Internal Server Error
	CodeServerError = "server_error"
)

// ==================== 构造函数 ====================

// New 创建一个新的 AuthError
func New(status int, code, description string) *AuthError {
	return &AuthError{
		HTTPStatus:  status,
		Code:        code,
		Description: description,
	}
}

// Newf 创建一个带格式化描述的 AuthError
func Newf(status int, code, format string, args ...any) *AuthError {
	return &AuthError{
		HTTPStatus:  status,
		Code:        code,
		Description: fmt.Sprintf(format, args...),
	}
}

// ==================== 400 Bad Request ====================

func NewInvalidRequest(description string) *AuthError {
	return New(http.StatusBadRequest, CodeInvalidRequest, description)
}

func NewInvalidRequestf(format string, args ...any) *AuthError {
	return Newf(http.StatusBadRequest, CodeInvalidRequest, format, args...)
}

func NewInvalidGrant(description string) *AuthError {
	return New(http.StatusGone, CodeInvalidGrant, description)
}

func NewInvalidCredentials(description string) *AuthError {
	return New(http.StatusUnauthorized, CodeInvalidCredentials, description)
}

func NewInvalidCredentialsf(format string, args ...any) *AuthError {
	return Newf(http.StatusUnauthorized, CodeInvalidCredentials, format, args...)
}

// ==================== 401 Unauthorized ====================

func NewUnauthorized(description string) *AuthError {
	return New(http.StatusUnauthorized, CodeInvalidToken, description)
}

func NewUnauthorizedf(format string, args ...any) *AuthError {
	return Newf(http.StatusUnauthorized, CodeInvalidToken, format, args...)
}

func NewInvalidToken(description string) *AuthError {
	return New(http.StatusUnauthorized, CodeInvalidToken, description)
}

func NewLoginRequired(description string) *AuthError {
	return New(http.StatusUnauthorized, CodeLoginRequired, description)
}

// ==================== 403 Forbidden ====================

func NewAccessDenied(description string) *AuthError {
	return New(http.StatusForbidden, CodeAccessDenied, description)
}

func NewAccessDeniedf(format string, args ...any) *AuthError {
	return Newf(http.StatusForbidden, CodeAccessDenied, format, args...)
}

// ==================== 400 Bad Request (资源不存在视为参数错误) ====================

func NewClientNotFound(description string) *AuthError {
	return New(http.StatusBadRequest, CodeClientNotFound, description)
}

func NewClientNotFoundf(format string, args ...any) *AuthError {
	return Newf(http.StatusBadRequest, CodeClientNotFound, format, args...)
}

func NewServiceNotFound(description string) *AuthError {
	return New(http.StatusBadRequest, CodeServiceNotFound, description)
}

func NewServiceNotFoundf(format string, args ...any) *AuthError {
	return Newf(http.StatusBadRequest, CodeServiceNotFound, format, args...)
}

// ==================== 404 Not Found ====================

func NewNotFound(description string) *AuthError {
	return New(http.StatusNotFound, CodeNotFound, description)
}

func NewNotFoundf(format string, args ...any) *AuthError {
	return Newf(http.StatusNotFound, CodeNotFound, format, args...)
}

func NewUserNotFound(description string) *AuthError {
	return New(http.StatusNotFound, CodeUserNotFound, description)
}

// ==================== Flow 相关错误 ====================

// 412 Precondition Failed — Session/Cookie 丢失，Flow 不存在
func NewFlowNotFound(description string) *AuthError {
	return New(http.StatusPreconditionFailed, CodeFlowNotFound, description)
}

// 408 Request Timeout — Flow 生命周期已过期
func NewFlowExpired(description string) *AuthError {
	return New(http.StatusRequestTimeout, CodeFlowExpired, description)
}

// 409 Conflict — Flow 当前状态不允许此操作
func NewFlowInvalid(description string) *AuthError {
	return New(http.StatusConflict, CodeFlowInvalid, description)
}

// ==================== 422 Unprocessable Entity ====================

// 422 Unprocessable Entity — Challenge 过期（验证码超时）
func NewChallengeExpired(description string) *AuthError {
	return New(http.StatusUnprocessableEntity, CodeChallengeExpired, description)
}

// ==================== 426 Upgrade Required ====================

func NewNoConnectionAvailable(description string) *AuthError {
	if description == "" {
		description = "no login method configured for this application"
	}
	return New(http.StatusUpgradeRequired, CodeNoConnectionAvailable, description)
}

// ==================== 428 Precondition Required ====================

func NewIdentityRequired(missing []string) *AuthError {
	err := New(http.StatusPreconditionRequired, CodeIdentityRequired, "user must bind required identity")
	if len(missing) > 0 {
		err.Data = map[string]any{
			"required": missing,
		}
	}
	return err
}

// ==================== 429 Too Many Requests ====================

// NewTooManyRequests 创建限流错误，retryAfter 为需要等待的秒数
func NewTooManyRequests(retryAfter int) *AuthError {
	err := New(http.StatusTooManyRequests, CodeRateLimited, "rate limit exceeded")
	err.Data = map[string]any{
		"retry_after": retryAfter,
	}
	return err
}

// NewTooManyRequestsWithChallenge 创建限流错误，附带已创建的 Challenge ID
func NewTooManyRequestsWithChallenge(retryAfter int, challengeID string) *AuthError {
	err := NewTooManyRequests(retryAfter)
	err.Data["challenge_id"] = challengeID
	return err
}

// ==================== 500 Internal Server Error ====================

func NewServerError(description string) *AuthError {
	return New(http.StatusInternalServerError, CodeServerError, description)
}

func NewServerErrorf(format string, args ...any) *AuthError {
	return Newf(http.StatusInternalServerError, CodeServerError, format, args...)
}

// Wrap 将普通错误包装为 ServerError
func Wrap(err error) *AuthError {
	if err == nil {
		return nil
	}
	ae := &AuthError{}
	if errors.As(err, &ae) {
		return ae
	}
	return NewServerError(err.Error())
}

// ==================== 辅助函数 ====================

// Is 检查错误是否为指定的错误码
func Is(err error, code string) bool {
	if err == nil {
		return false
	}
	ae := &AuthError{}
	if errors.As(err, &ae) {
		return ae.Code == code
	}
	return false
}

// GetHTTPStatus 从错误获取 HTTP 状态码
func GetHTTPStatus(err error) int {
	ae := &AuthError{}
	if errors.As(err, &ae) {
		return ae.HTTPStatus
	}
	return http.StatusInternalServerError
}

// ToAuthError 将普通错误转换为 AuthError
func ToAuthError(err error) *AuthError {
	if err == nil {
		return nil
	}
	ae := &AuthError{}
	if errors.As(err, &ae) {
		return ae
	}
	return NewServerError(err.Error())
}

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
	CodeInvalidRequest = "invalid_request"
	CodeInvalidScope   = "invalid_scope"
	CodeInvalidGrant   = "invalid_grant"

	// 401 Unauthorized
	CodeUnauthorized     = "unauthorized"
	CodeInvalidToken     = "invalid_token"
	CodeInvalidClient    = "invalid_client"
	CodeExpiredToken     = "expired_token"
	CodeTokenRevoked     = "token_revoked"
	CodeInsufficientAuth = "insufficient_authentication"

	// 403 Forbidden
	CodeAccessDenied   = "access_denied"
	CodeInvalidOrigin  = "invalid_origin"
	CodeOriginMismatch = "origin_mismatch"

	// 404 Not Found
	CodeNotFound        = "not_found"
	CodeUserNotFound    = "user_not_found"
	CodeClientNotFound  = "client_not_found"
	CodeServiceNotFound = "service_not_found"

	// 412 Precondition Failed
	CodeFlowNotFound = "flow_not_found"
	CodeFlowExpired  = "flow_expired"
	CodeFlowInvalid  = "flow_invalid"

	// 422 Unprocessable Entity
	CodeNoConnectionAvailable = "no_connection_available"
	CodeIdentityRequired      = "identity_required"
	CodeInteractionRequired   = "interaction_required"

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

func NewInvalidScope(description string) *AuthError {
	return New(http.StatusBadRequest, CodeInvalidScope, description)
}

func NewInvalidGrant(description string) *AuthError {
	return New(http.StatusBadRequest, CodeInvalidGrant, description)
}

// ==================== 401 Unauthorized ====================

func NewUnauthorized(description string) *AuthError {
	return New(http.StatusUnauthorized, CodeUnauthorized, description)
}

func NewInvalidToken(description string) *AuthError {
	return New(http.StatusUnauthorized, CodeInvalidToken, description)
}

func NewInvalidClient(description string) *AuthError {
	return New(http.StatusUnauthorized, CodeInvalidClient, description)
}

func NewExpiredToken(description string) *AuthError {
	return New(http.StatusUnauthorized, CodeExpiredToken, description)
}

func NewTokenRevoked(description string) *AuthError {
	return New(http.StatusUnauthorized, CodeTokenRevoked, description)
}

// ==================== 403 Forbidden ====================

func NewAccessDenied(description string) *AuthError {
	return New(http.StatusForbidden, CodeAccessDenied, description)
}

func NewAccessDeniedf(format string, args ...any) *AuthError {
	return Newf(http.StatusForbidden, CodeAccessDenied, format, args...)
}

func NewInvalidOrigin(description string) *AuthError {
	return New(http.StatusForbidden, CodeInvalidOrigin, description)
}

func NewInvalidOriginf(format string, args ...any) *AuthError {
	return Newf(http.StatusForbidden, CodeInvalidOrigin, format, args...)
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

func NewUserNotFound(description string) *AuthError {
	return New(http.StatusNotFound, CodeUserNotFound, description)
}

// ==================== 412 Precondition Failed ====================

func NewFlowNotFound(description string) *AuthError {
	return New(http.StatusPreconditionFailed, CodeFlowNotFound, description)
}

func NewFlowExpired(description string) *AuthError {
	return New(http.StatusPreconditionFailed, CodeFlowExpired, description)
}

func NewFlowInvalid(description string) *AuthError {
	return New(http.StatusPreconditionFailed, CodeFlowInvalid, description)
}

// ==================== 422 Unprocessable Entity ====================

func NewNoConnectionAvailable(description string) *AuthError {
	if description == "" {
		description = "no login method configured for this application"
	}
	return New(http.StatusUnprocessableEntity, CodeNoConnectionAvailable, description)
}

func NewIdentityRequired(missing []string) *AuthError {
	err := New(http.StatusUnprocessableEntity, CodeIdentityRequired, "user must bind required identity")
	if len(missing) > 0 {
		err.Data = map[string]any{
			"required": missing,
		}
	}
	return err
}

func NewInteractionRequired(requirement string) *AuthError {
	err := New(http.StatusUnprocessableEntity, CodeInteractionRequired, "human verification required")
	if requirement != "" {
		err.Data = map[string]any{
			"require": requirement,
		}
	}
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

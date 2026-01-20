package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler 认证处理器
type Handler struct {
	service *Service
}

// NewHandler 创建认证处理器
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// Authorize POST /auth/authorize
// @Summary 创建认证会话
// @Description 创建 OAuth2 认证会话，返回 session_id 和可用的 connections（IDPs 配置）
// Session ID 会通过以下方式返回：
//   - Cookie: auth_session（HttpOnly，SPA 和传统 Web 应用都支持）
//   - Response Body: session_id 字段（仅用于前端显示，实际使用时必须通过 Cookie）
//
// Session ID 必须通过 Cookie 传递，后续 login 请求会从 Cookie 读取。
// 如果 SPA 和 API 不在同一域名，需要配置 CORS allow_credentials=true。
//
// 返回的 idps 配置中，type 字段对应 connection（IDP），前端在 login 时作为 connection 传入
// @Tags auth
// @Accept json
// @Produce json
// @Param request body AuthorizeRequest true "授权请求"
// @Success 200 {object} AuthorizeResponse
// @Failure 400 {object} Error
// @Router /auth/authorize [post]
func (h *Handler) Authorize(c *gin.Context) {
	var req AuthorizeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, err.Error()))
		return
	}

	resp, err := h.service.Authorize(c.Request.Context(), &req)
	if err != nil {
		if authErr, ok := err.(*Error); ok {
			h.errorResponse(c, http.StatusBadRequest, authErr)
		} else {
			h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, err.Error()))
		}
		return
	}

	// 设置 session cookie（HttpOnly，必须通过 Cookie 传递）
	// HttpOnly 防止 JavaScript 访问，提高安全性
	// 如果 SPA 和 API 不在同一域名，需要配置 CORS allow_credentials=true
	c.SetCookie("auth_session", resp.SessionID, 600, "/", "", false, true)
	c.JSON(http.StatusOK, resp)
}

// Login POST /auth/login
// @Summary 认证登录
// @Description 使用 connection（IDP）和对应的 data 完成登录，返回授权码。
// Session ID 必须从 Cookie（auth_session）获取，如果没有 Cookie 则视为无效 session。
// SPA 场景使用 HttpOnly Cookie，浏览器会自动发送，更安全。
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "登录请求"
// @Success 200 {object} LoginResponse
// @Failure 400 {object} Error
// @Failure 412 {object} Error "Session 过期"
// @Router /auth/login [post]
func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, err.Error()))
		return
	}

	// 只能从 cookie 获取 session_id
	sessionID, err := c.Cookie("auth_session")
	if err != nil || sessionID == "" {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, "missing session_id (auth_session cookie required)"))
		return
	}

	resp, err := h.service.Login(c.Request.Context(), sessionID, &req)
	if err != nil {
		if authErr, ok := err.(*Error); ok {
			// Session 过期返回 412
			if authErr.Code == ErrInvalidRequest {
				// 检查错误描述是否包含 session expired
				if authErr.Description == "session not found or expired" {
					h.errorResponse(c, http.StatusPreconditionFailed, authErr)
					return
				}
			}
			h.errorResponse(c, http.StatusBadRequest, authErr)
		} else {
			h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, err.Error()))
		}
		return
	}

	// 清除 session cookie（如果存在）
	c.SetCookie("auth_session", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, resp)
}

// Token POST /auth/token
// @Summary 获取 Token
// @Description OAuth2 Token 端点
// @Tags auth
// @Accept x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "授权类型" Enums(authorization_code,refresh_token)
// @Param code formData string false "授权码"
// @Param redirect_uri formData string false "重定向 URI"
// @Param client_id formData string true "客户端 ID"
// @Param code_verifier formData string false "PKCE 验证器"
// @Param refresh_token formData string false "Refresh Token"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} Error
// @Router /auth/token [post]
func (h *Handler) Token(c *gin.Context) {
	var req TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, err.Error()))
		return
	}

	resp, err := h.service.ExchangeToken(c.Request.Context(), &req)
	if err != nil {
		if authErr, ok := err.(*Error); ok {
			h.errorResponse(c, http.StatusBadRequest, authErr)
		} else {
			h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, err.Error()))
		}
		return
	}

	c.JSON(http.StatusOK, resp)
}

// Revoke POST /auth/revoke
// @Summary 撤销 Token
// @Description 撤销 Refresh Token
// @Tags auth
// @Accept x-www-form-urlencoded
// @Produce json
// @Param token formData string true "Token"
// @Success 200
// @Router /auth/revoke [post]
func (h *Handler) Revoke(c *gin.Context) {
	var req RevokeRequest
	if err := c.ShouldBind(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, err.Error()))
		return
	}

	// RFC 7009: 即使 token 无效，也应返回 200
	_ = h.service.RevokeToken(c.Request.Context(), req.Token)
	c.Status(http.StatusOK)
}

// Logout POST /auth/logout
// @Summary 登出
// @Description 撤销用户所有 Token
// @Tags auth
// @Produce json
// @Security Bearer
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} Error
// @Router /auth/logout [post]
func (h *Handler) Logout(c *gin.Context) {
	identity := GetIdentity(c)
	if identity == nil {
		h.errorResponse(c, http.StatusUnauthorized, NewError(ErrInvalidToken, "not authenticated"))
		return
	}

	if err := h.service.RevokeAllTokens(c.Request.Context(), identity.UserID); err != nil {
		h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, "failed to revoke tokens"))
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// UserInfo GET /auth/userinfo
// @Summary 获取用户信息
// @Description 获取当前用户信息
// @Tags auth
// @Produce json
// @Security Bearer
// @Success 200 {object} UserInfoResponse
// @Failure 401 {object} Error
// @Router /auth/userinfo [get]
func (h *Handler) UserInfo(c *gin.Context) {
	identity := GetIdentity(c)
	if identity == nil {
		h.errorResponse(c, http.StatusUnauthorized, NewError(ErrInvalidToken, "not authenticated"))
		return
	}

	resp, err := h.service.GetUserInfo(identity.UserID)
	if err != nil {
		h.errorResponse(c, http.StatusNotFound, NewError(ErrServerError, "user not found"))
		return
	}

	c.JSON(http.StatusOK, resp)
}

// UpdateUserInfo PUT /auth/userinfo
// @Summary 更新用户信息
// @Description 更新当前用户信息
// @Tags auth
// @Accept json
// @Produce json
// @Security Bearer
// @Param request body UpdateUserInfoRequest true "更新请求"
// @Success 200 {object} UserInfoResponse
// @Failure 400 {object} Error
// @Failure 401 {object} Error
// @Router /auth/userinfo [put]
func (h *Handler) UpdateUserInfo(c *gin.Context) {
	identity := GetIdentity(c)
	if identity == nil {
		h.errorResponse(c, http.StatusUnauthorized, NewError(ErrInvalidToken, "not authenticated"))
		return
	}

	var req UpdateUserInfoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, NewError(ErrInvalidRequest, err.Error()))
		return
	}

	resp, err := h.service.UpdateUserInfo(identity.UserID, &req)
	if err != nil {
		h.errorResponse(c, http.StatusInternalServerError, NewError(ErrServerError, err.Error()))
		return
	}

	c.JSON(http.StatusOK, resp)
}

func (h *Handler) errorResponse(c *gin.Context, status int, err *Error) {
	c.JSON(status, err)
}

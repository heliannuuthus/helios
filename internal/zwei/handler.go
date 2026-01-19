package zwei

import (
	"net/http"

	"github.com/heliannuuthus/helios/internal/logger"

	"github.com/gin-gonic/gin"
)

// Handler zwei 认证处理器
type Handler struct {
	service *Service
}

// NewHandler 创建 zwei 认证处理器
func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
	}
}

// Authorize OIDC 风格的授权端点（小程序 code login）
// @Summary 小程序授权登录
// @Description 遵循 OIDC 规范的授权端点，支持小程序 code login
// @Tags zwei
// @Accept json
// @Produce json
// @Param request body AuthorizeRequest true "授权请求"
// @Success 200 {object} TokenResponse
// @Failure 400 {object} OAuth2Error
// @Router /zwei/auth/authorize [post]
func (h *Handler) Authorize(c *gin.Context) {
	var req AuthorizeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Errorf("[Zwei] 请求参数错误: %v", err)
		c.JSON(http.StatusBadRequest, OAuth2Error{
			ErrorCode:        "invalid_request",
			ErrorDescription: err.Error(),
			State:           req.State,
		})
		return
	}

	// 调用 service 处理授权
	tokenResponse, err := h.service.Authorize(c.Request.Context(), &req)
	if err != nil {
		// 如果是 OAuth2Error 类型，直接返回
		if oauthErr, ok := err.(*OAuth2Error); ok {
			logger.Errorf("[Zwei] 授权失败: %s - %s", oauthErr.ErrorCode, oauthErr.ErrorDescription)
			oauthErr.State = req.State
			c.JSON(http.StatusBadRequest, oauthErr)
			return
		}

		// 其他错误
		logger.Errorf("[Zwei] 授权失败: %v", err)
		c.JSON(http.StatusInternalServerError, OAuth2Error{
			ErrorCode:        "server_error",
			ErrorDescription: "服务器内部错误",
			State:           req.State,
		})
		return
	}

	c.JSON(http.StatusOK, tokenResponse)
}

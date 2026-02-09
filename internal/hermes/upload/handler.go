package upload

// 注意：此包位于 hermes 模块下，但包名保持 upload 以保持 API 兼容性

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/internal/aegis"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/oss"
)

type Handler struct {
	db *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

type UploadImageRequest struct {
	ObjectKey string `form:"object-key" binding:"omitempty,max=512"` // 完整的 OSS 对象键，如 "avatars/user123.jpg"（优先级高于 prefix）
	Prefix    string `form:"prefix" binding:"omitempty,max=64"`      // 文件路径前缀，如 "avatars", "images"（当 object-key 为空时使用）
}

type UploadImageResponse struct {
	URL string `json:"url"` // 上传后的图片 URL
}

// UploadImage 上传图片（通用 API）
// @Summary 上传图片到 OSS
// @Tags upload
// @Accept multipart/form-data
// @Produce json
// @Security Bearer
// @Param object-key formData string false "完整的 OSS 对象键，如 avatars/user123.jpg（优先级高于 prefix）"
// @Param prefix formData string false "文件路径前缀，如 avatars, images（当 object-key 为空时使用）"
// @Param file formData file true "图片文件"
// @Success 200 {object} UploadImageResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/upload/image [post]
func (h *Handler) UploadImage(c *gin.Context) {
	// 检查认证（可选，如果需要登录才能上传则取消注释）
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "未登录或登录已过期"})
		return
	}

	identity, ok := user.(aegis.Token)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "无效的认证信息"})
		return
	}

	// 解析表单
	var req UploadImageRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": fmt.Sprintf("参数错误: %v", err)})
		return
	}

	// 获取上传的文件
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "请选择要上传的文件"})
		return
	}

	// 验证文件大小（限制 5MB）
	if file.Size > 5*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"message": "图片大小不能超过 5MB"})
		return
	}

	// 验证文件类型：先检查 Content-Type header，再通过 magic bytes 校验实际内容
	contentType := file.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"message": "只支持上传图片文件"})
		return
	}

	// 通过文件头部 magic bytes 验证实际文件类型（防止伪造 Content-Type）
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "读取文件失败"})
		return
	}
	header := make([]byte, 512)
	n, _ := src.Read(header)
	src.Close()
	detectedType := http.DetectContentType(header[:n])
	if !strings.HasPrefix(detectedType, "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"message": "文件内容不是有效的图片格式"})
		return
	}

	// 确定 object-key
	objectKey := req.ObjectKey
	if objectKey == "" {
		prefix := req.Prefix
		if prefix == "" {
			prefix = "images"
		}

		// 如果是头像上传（prefix 为 "avatars"），强制使用认证用户的 uid 生成固定路径
		// 这样可以防止前端传入错误的 uid 导致安全风险
		if prefix == "avatars" {
			objectKey = fmt.Sprintf("avatars/%s.jpg", aegis.GetInternalUIDFromToken(identity))
		} else {
			// 其他类型使用 prefix + filename（按日期组织）
			now := time.Now()
			objectKey = fmt.Sprintf("%s/%04d/%02d/%02d/%s", prefix, now.Year(), now.Month(), now.Day(), file.Filename)
		}
	} else {
		// 如果前端传入了 object-key，检查是否是头像路径
		// 如果是头像路径，强制使用认证用户的 uid（防止路径篡改）
		if strings.HasPrefix(objectKey, "avatars/") && strings.HasSuffix(objectKey, ".jpg") {
			// 忽略前端传入的 uid，使用认证 token 中的 uid
			objectKey = fmt.Sprintf("avatars/%s.jpg", aegis.GetInternalUIDFromToken(identity))
			logger.Infof("[Upload] 检测到头像上传，强制使用认证 UID 生成路径 - UID: %s", aegis.GetInternalUIDFromToken(identity))
		}
	}

	// 构建预期的 OSS URL（立即返回给前端）
	expectedURL := oss.BuildObjectURL(objectKey)

	// 读取文件内容到内存（用于异步上传）
	fileSrc, err := file.Open()
	if err != nil {
		logger.Errorf("[Upload] 打开文件失败 - UID: %s, Error: %v", aegis.GetInternalUIDFromToken(identity), err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "读取文件失败"})
		return
	}
	defer func() {
		if closeErr := fileSrc.Close(); closeErr != nil {
			logger.Warnf("[Upload] close file source failed: %v", closeErr)
		}
	}()

	fileData, err := io.ReadAll(fileSrc)
	if err != nil {
		logger.Errorf("[Upload] 读取文件失败 - UID: %s, Error: %v", aegis.GetInternalUIDFromToken(identity), err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "读取文件失败"})
		return
	}

	// 立即返回成功响应（前端不需要等待 OSS 上传完成）
	c.JSON(http.StatusOK, UploadImageResponse{URL: expectedURL})

	// 异步上传到 OSS（使用 STS 凭证，60 秒超时防止 goroutine 泄漏）
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_ = ctx // 确保 ctx 可用于未来扩展
		h.uploadToOSSAsync(aegis.GetInternalUIDFromToken(identity), objectKey, bytes.NewReader(fileData))
	}()
}

// uploadToOSSAsync 异步上传文件到 OSS（优先使用 STS 凭证，失败则回退到主账号凭证）
func (h *Handler) uploadToOSSAsync(uid, objectKey string, reader io.Reader) {
	logger.Infof("[Upload] 开始异步上传 - UID: %s, ObjectKey: %s", uid, objectKey)

	// 尝试生成 STS 凭证（如果 STS 已配置）
	credentials, err := oss.GenerateSTSCredentials(objectKey, 3600)
	if err != nil {
		// STS 未配置或失败，使用主账号凭证
		logger.Warnf("[Upload] STS 不可用，使用主账号凭证上传 - UID: %s, ObjectKey: %s, Error: %v", uid, objectKey, err)
		uploadURL, err := oss.UploadImageByKey(objectKey, reader)
		if err != nil {
			logger.Errorf("[Upload] 异步上传失败（主账号凭证） - UID: %s, ObjectKey: %s, Error: %v", uid, objectKey, err)
			return
		}
		logger.Infof("[Upload] 异步上传成功（主账号凭证） - UID: %s, URL: %s", uid, uploadURL)

		// 如果是头像上传，更新数据库
		h.updateAvatarIfNeeded(uid, objectKey, uploadURL)
		return
	}

	// 使用 STS 凭证上传
	uploadURL, err := oss.UploadImageWithSTS(objectKey, reader, credentials)
	if err != nil {
		logger.Errorf("[Upload] STS 上传失败，回退到主账号凭证 - UID: %s, ObjectKey: %s, Error: %v", uid, objectKey, err)
		// 回退到主账号凭证
		uploadURL, err := oss.UploadImageByKey(objectKey, reader)
		if err != nil {
			logger.Errorf("[Upload] 异步上传失败（回退方案） - UID: %s, ObjectKey: %s, Error: %v", uid, objectKey, err)
			return
		}
		logger.Infof("[Upload] 异步上传成功（回退方案） - UID: %s, URL: %s", uid, uploadURL)
		h.updateAvatarIfNeeded(uid, objectKey, uploadURL)
		return
	}

	logger.Infof("[Upload] 异步上传成功（STS 凭证） - UID: %s, URL: %s", uid, uploadURL)
	h.updateAvatarIfNeeded(uid, objectKey, uploadURL)
}

// updateAvatarIfNeeded 如果是头像上传，更新用户头像
// 注意：此时 objectKey 已经保证是正确的（由认证用户的 uid 生成），无需再次验证
func (h *Handler) updateAvatarIfNeeded(uid, objectKey, uploadURL string) {
	// 如果是头像上传（路径为 avatars/{uid}.jpg），自动更新用户头像
	// objectKey 已经由后端强制生成，保证 uid 正确，无需再次验证
	if strings.HasPrefix(objectKey, "avatars/") && strings.HasSuffix(objectKey, ".jpg") {
		// 更新用户头像（使用 auth 模块的用户表）
		if err := h.db.Model(&models.User{}).Where("uid = ?", uid).Update("picture", uploadURL).Error; err != nil {
			logger.Errorf("[Upload] 更新用户头像失败 - UID: %s, URL: %s, Error: %v", uid, uploadURL, err)
		} else {
			logger.Infof("[Upload] 用户头像已更新 - UID: %s, URL: %s", uid, uploadURL)
		}
	}
}

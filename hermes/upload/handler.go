package upload

// 注意：此包位于 hermes 模块下，但包名保持 upload 以保持 API 兼容性

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/aegis"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/r2"
)

type Handler struct {
	db *gorm.DB
}

func NewHandler(db *gorm.DB) *Handler {
	return &Handler{db: db}
}

type UploadImageRequest struct {
	ObjectKey string `form:"object-key" binding:"omitempty,max=512"` // 完整的对象键，如 "avatars/user123.jpg"（优先级高于 prefix）
	Prefix    string `form:"prefix" binding:"omitempty,max=64"`      // 文件路径前缀，如 "avatars", "images"（当 object-key 为空时使用）
}

type UploadImageResponse struct {
	URL string `json:"url"` // 上传后的图片 URL
}

// validateImageFile 验证上传文件的大小和类型
func validateImageFile(c *gin.Context, file *multipart.FileHeader) bool {
	if file.Size > 5*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"message": "图片大小不能超过 5MB"})
		return false
	}

	contentType := file.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"message": "只支持上传图片文件"})
		return false
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "读取文件失败"})
		return false
	}
	defer func() {
		if closeErr := src.Close(); closeErr != nil {
			logger.Warnf("[Upload] close file for magic bytes check failed: %v", closeErr)
		}
	}()

	header := make([]byte, 512)
	n, err := src.Read(header)
	if err != nil && n == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "读取文件头失败"})
		return false
	}
	detectedType := http.DetectContentType(header[:n])
	if !strings.HasPrefix(detectedType, "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"message": "文件内容不是有效的图片格式"})
		return false
	}

	return true
}

// resolveObjectKey 根据请求参数和认证信息确定上传的 object-key
func resolveObjectKey(req UploadImageRequest, identity aegis.Token, filename string) string {
	objectKey := req.ObjectKey
	if objectKey == "" {
		prefix := req.Prefix
		if prefix == "" {
			prefix = "images"
		}
		if prefix == "avatars" {
			return fmt.Sprintf("avatars/%s.jpg", aegis.GetOpenIDFromToken(identity))
		}
		now := time.Now()
		return fmt.Sprintf("%s/%04d/%02d/%02d/%s", prefix, now.Year(), now.Month(), now.Day(), filename)
	}

	if strings.HasPrefix(objectKey, "avatars/") && strings.HasSuffix(objectKey, ".jpg") {
		openid := aegis.GetOpenIDFromToken(identity)
		logger.Infof("[Upload] 检测到头像上传，强制使用认证 OpenID 生成路径 - OpenID: %s", openid)
		return fmt.Sprintf("avatars/%s.jpg", openid)
	}

	return objectKey
}

// UploadImage 上传图片（通用 API）
// @Summary 上传图片到 R2
// @Tags upload
// @Accept multipart/form-data
// @Produce json
// @Security Bearer
// @Param object-key formData string false "完整的对象键，如 avatars/user123.jpg（优先级高于 prefix）"
// @Param prefix formData string false "文件路径前缀，如 avatars, images（当 object-key 为空时使用）"
// @Param file formData file true "图片文件"
// @Success 200 {object} UploadImageResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/upload/image [post]
func (h *Handler) UploadImage(c *gin.Context) {
	// 检查认证
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

	if !validateImageFile(c, file) {
		return
	}

	objectKey := resolveObjectKey(req, identity, file.Filename)
	openid := aegis.GetOpenIDFromToken(identity)

	// 读取文件内容
	fileSrc, err := file.Open()
	if err != nil {
		logger.Errorf("[Upload] 打开文件失败 - OpenID: %s, Error: %v", openid, err)
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
		logger.Errorf("[Upload] 读取文件失败 - OpenID: %s, Error: %v", openid, err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "读取文件失败"})
		return
	}

	// 上传到 R2
	logger.Infof("[Upload] 开始上传 - OpenID: %s, ObjectKey: %s", openid, objectKey)
	uploadURL, err := r2.Upload(objectKey, bytes.NewReader(fileData))
	if err != nil {
		logger.Errorf("[Upload] 上传失败 - OpenID: %s, ObjectKey: %s, Error: %v", openid, objectKey, err)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "上传文件失败"})
		return
	}
	logger.Infof("[Upload] 上传成功 - OpenID: %s, URL: %s", openid, uploadURL)

	// 如果是头像上传，更新数据库
	h.updateAvatarIfNeeded(openid, objectKey, uploadURL)

	c.JSON(http.StatusOK, UploadImageResponse{URL: uploadURL})
}

// updateAvatarIfNeeded 如果是头像上传，更新用户头像
// 注意：此时 objectKey 已经保证是正确的（由认证用户的 openid 生成），无需再次验证
func (h *Handler) updateAvatarIfNeeded(openid, objectKey, uploadURL string) {
	// 如果是头像上传（路径为 avatars/{openid}.jpg），自动更新用户头像
	// objectKey 已经由后端强制生成，保证 openid 正确，无需再次验证
	if strings.HasPrefix(objectKey, "avatars/") && strings.HasSuffix(objectKey, ".jpg") {
		if err := h.db.Model(&models.User{}).Where("openid = ?", openid).Update("picture", uploadURL).Error; err != nil {
			logger.Errorf("[Upload] 更新用户头像失败 - OpenID: %s, URL: %s, Error: %v", openid, uploadURL, err)
		} else {
			logger.Infof("[Upload] 用户头像已更新 - OpenID: %s, URL: %s", openid, uploadURL)
		}
	}
}

package oss

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"

	"github.com/heliannuuthus/helios/pkg/logger"
)

var (
	client     *oss.Client
	bucket     *oss.Bucket
	cfg        Config
	configured bool
)

// Config OSS 客户端配置
type Config struct {
	Endpoint        string // OSS 地域节点，如 oss-cn-hangzhou.aliyuncs.com
	AccessKeyID     string // AccessKey ID
	AccessKeySecret string // AccessKey Secret
	Bucket          string // Bucket 名称
	Domain          string // 自定义域名（可选）
	Region          string // STS 区域（可选，默认从 Endpoint 提取）
	RoleARN         string // RAM 角色 ARN（STS 临时凭证）
	UseInternal     bool   // 是否使用内网端点（生产环境）
}

// resolveEndpoint 根据配置决定使用公网还是内网端点
func resolveEndpoint(c Config) string {
	endpoint := c.Endpoint
	if endpoint == "" {
		return ""
	}

	if !c.UseInternal {
		return endpoint
	}

	// 转换为内网 endpoint：oss-cn-beijing.aliyuncs.com -> oss-cn-beijing-internal.aliyuncs.com
	if strings.Contains(endpoint, "-internal.") {
		return endpoint
	}

	internalEndpoint := strings.Replace(endpoint, ".aliyuncs.com", "-internal.aliyuncs.com", 1)
	logger.Infof("[OSS] 使用内网 endpoint: %s -> %s", endpoint, internalEndpoint)
	return internalEndpoint
}

// Init 初始化 OSS 客户端
func Init(c Config) error {
	cfg = c
	endpoint := resolveEndpoint(c)

	if endpoint == "" || c.AccessKeyID == "" || c.AccessKeySecret == "" || c.Bucket == "" {
		return fmt.Errorf("OSS 配置不完整: endpoint, access-key-id, access-key-secret, bucket 均为必填")
	}

	var err error
	client, err = oss.New(endpoint, c.AccessKeyID, c.AccessKeySecret)
	if err != nil {
		return fmt.Errorf("初始化 OSS 客户端失败: %w", err)
	}

	bucket, err = client.Bucket(c.Bucket)
	if err != nil {
		return fmt.Errorf("获取 OSS Bucket 失败: %w", err)
	}

	configured = true
	logger.Infof("[OSS] 初始化成功 - Endpoint: %s, Bucket: %s, Internal: %v",
		endpoint, c.Bucket, strings.Contains(endpoint, "-internal"))
	return nil
}

// UploadImage 上传图片到 OSS（使用 prefix + filename，按日期组织）
// prefix: 文件路径前缀，如 "avatars", "images" 等
// filename: 文件名（不含路径），如果为空则自动生成
// reader: 文件内容读取器
// 返回: OSS 文件 URL
func UploadImage(prefix, filename string, reader io.Reader) (string, error) {
	if bucket == nil {
		return "", fmt.Errorf("OSS 客户端未初始化")
	}

	// 如果没有提供文件名，生成一个基于时间戳的唯一文件名
	if filename == "" {
		filename = fmt.Sprintf("%d.jpg", time.Now().UnixNano())
	}

	// 确保文件名有扩展名
	if filepath.Ext(filename) == "" {
		filename += ".jpg"
	}

	// 构建完整路径: prefix/yyyy/MM/dd/filename
	now := time.Now()
	objectKey := fmt.Sprintf("%s/%04d/%02d/%02d/%s", prefix, now.Year(), now.Month(), now.Day(), filename)

	return uploadByObjectKey(objectKey, reader)
}

// UploadImageByKey 上传图片到 OSS（使用完整的 objectKey，支持覆盖）
// objectKey: 完整的 OSS 对象键，如 "avatars/user123.jpg"
// reader: 文件内容读取器
// 返回: OSS 文件 URL
func UploadImageByKey(objectKey string, reader io.Reader) (string, error) {
	if bucket == nil {
		return "", fmt.Errorf("OSS 客户端未初始化")
	}

	// 确保 objectKey 不以 / 开头
	if len(objectKey) > 0 && objectKey[0] == '/' {
		objectKey = objectKey[1:]
	}

	return uploadByObjectKey(objectKey, reader)
}

// uploadByObjectKey 内部上传方法
func uploadByObjectKey(objectKey string, reader io.Reader) (string, error) {
	// 上传文件（如果已存在会自动覆盖）
	err := bucket.PutObject(objectKey, reader)
	if err != nil {
		return "", fmt.Errorf("上传文件到 OSS 失败: %w", err)
	}

	return buildObjectURL(objectKey), nil
}

// UploadImageWithSTS 使用 STS 凭证上传图片到 OSS（异步安全）
// objectKey: 完整的 OSS 对象键，如 "avatars/user123.jpg"
// reader: 文件内容读取器
// credentials: STS 临时凭证
// 返回: OSS 文件 URL
func UploadImageWithSTS(objectKey string, reader io.Reader, credentials *STSCredentials) (string, error) {
	if !configured {
		return "", fmt.Errorf("OSS 客户端未初始化")
	}

	// 确保 objectKey 不以 / 开头
	if len(objectKey) > 0 && objectKey[0] == '/' {
		objectKey = objectKey[1:]
	}

	endpoint := resolveEndpoint(cfg)

	// 使用 STS 凭证创建临时客户端
	stsClient, err := oss.New(endpoint, credentials.AccessKeyID, credentials.AccessKeySecret,
		oss.SecurityToken(credentials.SecurityToken))
	if err != nil {
		return "", fmt.Errorf("创建 STS OSS 客户端失败: %w", err)
	}

	stsBucket, err := stsClient.Bucket(cfg.Bucket)
	if err != nil {
		return "", fmt.Errorf("获取 STS Bucket 失败: %w", err)
	}

	// 上传文件
	err = stsBucket.PutObject(objectKey, reader)
	if err != nil {
		return "", fmt.Errorf("使用 STS 凭证上传文件失败: %w", err)
	}

	url := buildObjectURL(objectKey)
	logger.Infof("[OSS STS] 上传成功 - Key: %s, URL: %s", objectKey, url)
	return url, nil
}

// buildObjectURL 构建对象 URL
func buildObjectURL(objectKey string) string {
	d := cfg.Domain
	if d == "" {
		// 如果没有配置自定义域名，使用 OSS 默认域名
		d = fmt.Sprintf("https://%s.%s", cfg.Bucket, cfg.Endpoint)
	} else {
		// 如果配置了自定义域名，确保有协议前缀
		if !strings.HasPrefix(d, "http://") && !strings.HasPrefix(d, "https://") {
			d = "https://" + d
		}
	}

	// 确保 domain 不以 / 结尾
	d = strings.TrimRight(d, "/")

	return fmt.Sprintf("%s/%s", d, objectKey)
}

// BuildObjectURL 构建对象 URL（不实际上传，仅构建 URL）
func BuildObjectURL(objectKey string) string {
	return buildObjectURL(objectKey)
}

// DeleteImage 删除 OSS 中的图片
func DeleteImage(objectKey string) error {
	if bucket == nil {
		return fmt.Errorf("OSS 客户端未初始化")
	}

	err := bucket.DeleteObject(objectKey)
	if err != nil {
		return fmt.Errorf("删除 OSS 文件失败: %w", err)
	}

	logger.Infof("[OSS] 删除成功 - Key: %s", objectKey)
	return nil
}

package r2

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/heliannuuthus/helios/pkg/logger"
)

var (
	client *s3.Client
	bucket string
	domain string
)

// Config R2 客户端配置
type Config struct {
	AccountID       string // Cloudflare Account ID
	AccessKeyID     string // R2 API Token (Access Key ID)
	AccessKeySecret string // R2 API Token (Secret Access Key)
	Bucket          string // R2 Bucket 名称
	Domain          string // 自定义域名（R2 Custom Domain 或 Workers 域名）
}

// Init 初始化 Cloudflare R2 客户端
func Init(cfg Config) error {
	if cfg.AccountID == "" || cfg.AccessKeyID == "" || cfg.AccessKeySecret == "" || cfg.Bucket == "" {
		return fmt.Errorf("R2 配置不完整: account-id, access-key-id, access-key-secret, bucket 均为必填")
	}

	bucket = cfg.Bucket
	domain = cfg.Domain

	// Cloudflare R2 的 S3 兼容端点格式: https://<account-id>.r2.cloudflarestorage.com
	endpoint := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", cfg.AccountID)

	client = s3.New(s3.Options{
		Region:       "auto", // R2 使用 "auto" 作为 region
		Credentials:  credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.AccessKeySecret, ""),
		BaseEndpoint: aws.String(endpoint),
	})

	logger.Infof("[R2] 初始化成功 - AccountID: %s, Bucket: %s", cfg.AccountID, cfg.Bucket)
	return nil
}

// Upload 上传文件到 R2
// objectKey: 完整的对象键，如 "avatars/user123.jpg"
// reader: 文件内容读取器
// 返回: 文件访问 URL
func Upload(objectKey string, reader io.Reader) (string, error) {
	if client == nil {
		return "", fmt.Errorf("R2 客户端未初始化")
	}

	// 确保 objectKey 不以 / 开头
	objectKey = strings.TrimPrefix(objectKey, "/")

	_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
		Body:   reader,
	})
	if err != nil {
		return "", fmt.Errorf("上传文件到 R2 失败: %w", err)
	}

	url := BuildObjectURL(objectKey)
	logger.Infof("[R2] 上传成功 - Key: %s, URL: %s", objectKey, url)
	return url, nil
}

// UploadWithPrefix 按日期目录上传文件到 R2
// prefix: 文件路径前缀，如 "avatars", "images" 等
// filename: 文件名（不含路径），如果为空则自动生成
// reader: 文件内容读取器
// 返回: 文件访问 URL
func UploadWithPrefix(prefix, filename string, reader io.Reader) (string, error) {
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

	return Upload(objectKey, reader)
}

// Delete 删除 R2 中的文件
func Delete(objectKey string) error {
	if client == nil {
		return fmt.Errorf("R2 客户端未初始化")
	}

	objectKey = strings.TrimPrefix(objectKey, "/")

	_, err := client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return fmt.Errorf("删除 R2 文件失败: %w", err)
	}

	logger.Infof("[R2] 删除成功 - Key: %s", objectKey)
	return nil
}

// BuildObjectURL 构建对象的公开访问 URL
// 如果配置了自定义域名（R2 Custom Domain 或 Workers 域名），使用自定义域名
// 否则仅返回 objectKey（需要在 Cloudflare Dashboard 启用 r2.dev 公开访问）
func BuildObjectURL(objectKey string) string {
	objectKey = strings.TrimPrefix(objectKey, "/")

	d := domain
	if d == "" {
		logger.Warnf("[R2] 未配置自定义域名 (r2.domain)，BuildObjectURL 无法生成有效的公开 URL")
		return objectKey
	}

	// 确保有协议前缀
	if !strings.HasPrefix(d, "http://") && !strings.HasPrefix(d, "https://") {
		d = "https://" + d
	}

	// 确保不以 / 结尾
	d = strings.TrimRight(d, "/")

	return fmt.Sprintf("%s/%s", d, objectKey)
}

package storage

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"

	chaosconfig "github.com/heliannuuthus/helios/chaos/config"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Service 存储服务
type Service struct {
	s3Client  *s3.Client
	bucket    string
	publicURL string
}

// NewService 创建存储服务
func NewService() (*Service, error) {
	endpoint := chaosconfig.GetCloudflareR2Endpoint()
	if endpoint == "" {
		return nil, fmt.Errorf("cloudflare R2 endpoint 未配置")
	}

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			chaosconfig.GetCloudflareR2AccessKeyID(),
			chaosconfig.GetCloudflareR2AccessKeySecret(),
			"",
		)),
		config.WithRegion("auto"),
	)
	if err != nil {
		return nil, fmt.Errorf("加载 AWS 配置失败: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})

	return &Service{
		s3Client:  client,
		bucket:    chaosconfig.GetCloudflareR2Bucket(),
		publicURL: chaosconfig.GetCloudflareR2PublicURL(),
	}, nil
}

// Upload 上传文件
// path: 可选，指定上传路径（如 "images/logo.png"），为空则自动生成
func (s *Service) Upload(ctx context.Context, file *multipart.FileHeader, path string) (*UploadResult, error) {
	src, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			logger.Warnf("failed to close uploaded file: %v", err)
		}
	}()

	// 如果指定了路径则使用，否则自动生成
	var storageKey string
	if path != "" {
		storageKey = strings.TrimPrefix(path, "/")
	} else {
		fileID := uuid.New().String()
		ext := filepath.Ext(file.Filename)
		storageKey = fmt.Sprintf("%s/%s%s", time.Now().Format("2006/01/02"), fileID, ext)
	}

	contentType := file.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	_, err = s.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(storageKey),
		Body:        src,
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return nil, fmt.Errorf("上传到 R2 失败: %w", err)
	}

	publicURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(s.publicURL, "/"), storageKey)

	logger.Infof("[Storage] 文件上传成功 - Key: %s", storageKey)
	return &UploadResult{
		Key:         storageKey,
		FileName:    file.Filename,
		FileSize:    file.Size,
		ContentType: contentType,
		PublicURL:   publicURL,
	}, nil
}

// UploadFromReader 从 Reader 上传文件（供内部调用）
// path: 可选，指定上传路径，为空则自动生成
func (s *Service) UploadFromReader(ctx context.Context, reader io.Reader, filename, contentType, path string, size int64) (*UploadResult, error) {
	var storageKey string
	if path != "" {
		storageKey = strings.TrimPrefix(path, "/")
	} else {
		fileID := uuid.New().String()
		ext := filepath.Ext(filename)
		storageKey = fmt.Sprintf("%s/%s%s", time.Now().Format("2006/01/02"), fileID, ext)
	}

	if contentType == "" {
		contentType = "application/octet-stream"
	}

	_, err := s.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(storageKey),
		Body:        reader,
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return nil, fmt.Errorf("上传到 R2 失败: %w", err)
	}

	publicURL := fmt.Sprintf("%s/%s", strings.TrimSuffix(s.publicURL, "/"), storageKey)

	logger.Infof("[Storage] 文件上传成功 - Key: %s", storageKey)
	return &UploadResult{
		Key:         storageKey,
		FileName:    filename,
		FileSize:    size,
		ContentType: contentType,
		PublicURL:   publicURL,
	}, nil
}

package storage

// UploadResult 上传结果（内部使用）
type UploadResult struct {
	Key         string `json:"key"`
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	ContentType string `json:"content_type"`
	PublicURL   string `json:"public_url"`
}

// PresignRequest Presigned URL 请求
type PresignRequest struct {
	FileName    string `json:"file_name" binding:"required,max=256"`
	ContentType string `json:"content_type" binding:"required,max=128"`
	Path        string `json:"path" binding:"omitempty,max=512"`
	Prefix      string `json:"prefix" binding:"omitempty,max=64"`
}

// PresignResponse Presigned URL 响应
type PresignResponse struct {
	UploadURL string `json:"upload_url"`
	Key       string `json:"key"`
	PublicURL string `json:"public_url"`
	ExpiresIn int    `json:"expires_in"`
}

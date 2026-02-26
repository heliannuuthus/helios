package storage

// UploadResult 上传结果（内部使用）
type UploadResult struct {
	Key         string `json:"key"`
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	ContentType string `json:"content_type"`
	PublicURL   string `json:"public_url"`
}

// UploadResponse 上传响应（API 返回）
type UploadResponse struct {
	Key         string `json:"key"`
	FileName    string `json:"file_name"`
	FileSize    int64  `json:"file_size"`
	ContentType string `json:"content_type"`
	PublicURL   string `json:"public_url"`
}

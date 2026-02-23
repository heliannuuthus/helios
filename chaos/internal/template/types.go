package template

// CreateRequest 创建模板请求
type CreateRequest struct {
	TemplateID  string  `json:"template_id" binding:"required"`
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description"`
	Subject     string  `json:"subject" binding:"required"`
	Content     string  `json:"content" binding:"required"`
	Variables   *string `json:"variables"`
	ServiceID   *string `json:"service_id"`
}

// UpdateRequest 更新模板请求
type UpdateRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Subject     *string `json:"subject"`
	Content     *string `json:"content"`
	Variables   *string `json:"variables"`
	IsEnabled   *bool   `json:"is_enabled"`
}

// RenderRequest 渲染模板请求
type RenderRequest struct {
	TemplateID string         `json:"template_id" binding:"required"`
	Data       map[string]any `json:"data"`
}

// RenderResponse 渲染模板响应
type RenderResponse struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

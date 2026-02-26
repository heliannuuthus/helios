package mail

// SendRequest 发送邮件请求
type SendRequest struct {
	To         string         `json:"to" binding:"required,email"`
	Subject    string         `json:"subject"`
	TemplateID string         `json:"template_id" binding:"required"`
	Data       map[string]any `json:"data"`
}

package telegram

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	defaultAPIURL  = "https://api.telegram.org"
	defaultTimeout = 30 * time.Second
)

// Client Telegram Bot 客户端
type Client struct {
	token      string
	apiURL     string
	httpClient *http.Client
}

// Option 客户端配置选项
type Option func(*Client)

// WithAPIURL 设置自定义 API URL（用于代理）
func WithAPIURL(url string) Option {
	return func(c *Client) {
		c.apiURL = url
	}
}

// WithHTTPClient 设置自定义 HTTP 客户端
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithTimeout 设置请求超时时间
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// NewClient 创建 Telegram Bot 客户端
func NewClient(token string, opts ...Option) *Client {
	c := &Client{
		token:  token,
		apiURL: defaultAPIURL,
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// buildURL 构建 API 请求 URL
func (c *Client) buildURL(method string) string {
	return fmt.Sprintf("%s/bot%s/%s", c.apiURL, c.token, method)
}

// doRequest 执行 HTTP 请求
func (c *Client) doRequest(ctx context.Context, method, apiMethod string, body io.Reader, contentType string) (*Response, error) {
	url := c.buildURL(apiMethod)

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 Telegram API 失败: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Errorf("[Telegram] 关闭响应体失败: %v", err)
		}
	}()

	var result Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if !result.OK {
		return &result, fmt.Errorf("telegram API 错误: %s (code: %d)", result.Description, result.ErrorCode)
	}

	return &result, nil
}

// postJSON 发送 JSON 请求
func (c *Client) postJSON(ctx context.Context, method string, payload any) (*Response, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	return c.doRequest(ctx, http.MethodPost, method, bytes.NewReader(data), "application/json")
}

// postMultipart 发送 multipart 请求（用于文件上传）
func (c *Client) postMultipart(ctx context.Context, method string, fields map[string]string, files map[string]FileUpload) (*Response, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// 添加普通字段
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			return nil, fmt.Errorf("写入字段 %s 失败: %w", key, err)
		}
	}

	// 添加文件
	for key, file := range files {
		part, err := writer.CreateFormFile(key, file.Filename)
		if err != nil {
			return nil, fmt.Errorf("创建文件字段 %s 失败: %w", key, err)
		}
		if _, err := io.Copy(part, file.Reader); err != nil {
			return nil, fmt.Errorf("写入文件 %s 失败: %w", key, err)
		}
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("关闭 multipart writer 失败: %w", err)
	}

	return c.doRequest(ctx, http.MethodPost, method, &buf, writer.FormDataContentType())
}

// GetMe 获取 Bot 信息，可用于验证 token 是否有效
func (c *Client) GetMe(ctx context.Context) (*User, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "getMe", nil, "")
	if err != nil {
		return nil, err
	}

	var user User
	if err := json.Unmarshal(resp.Result, &user); err != nil {
		return nil, fmt.Errorf("解析用户信息失败: %w", err)
	}

	return &user, nil
}

// SendMessage 发送文本消息
func (c *Client) SendMessage(ctx context.Context, req *SendMessageRequest) (*Message, error) {
	resp, err := c.postJSON(ctx, "sendMessage", req)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(resp.Result, &msg); err != nil {
		return nil, fmt.Errorf("解析消息失败: %w", err)
	}

	logger.Debugf("[Telegram] 发送消息成功 - ChatID: %v, MessageID: %d", req.ChatID, msg.MessageID)
	return &msg, nil
}

// SendPhoto 发送图片
func (c *Client) SendPhoto(ctx context.Context, req *SendPhotoRequest) (*Message, error) {
	// 如果是 URL 或 file_id，使用 JSON 请求
	if req.Photo != "" {
		resp, err := c.postJSON(ctx, "sendPhoto", req)
		if err != nil {
			return nil, err
		}

		var msg Message
		if err := json.Unmarshal(resp.Result, &msg); err != nil {
			return nil, fmt.Errorf("解析消息失败: %w", err)
		}

		return &msg, nil
	}

	// 如果是文件上传，使用 multipart
	if req.PhotoFile == nil {
		return nil, fmt.Errorf("photo 或 photo_file 必须提供其一")
	}

	fields := map[string]string{
		"chat_id": fmt.Sprintf("%v", req.ChatID),
	}
	if req.Caption != "" {
		fields["caption"] = req.Caption
	}
	if req.ParseMode != "" {
		fields["parse_mode"] = req.ParseMode
	}

	files := map[string]FileUpload{
		"photo": *req.PhotoFile,
	}

	resp, err := c.postMultipart(ctx, "sendPhoto", fields, files)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(resp.Result, &msg); err != nil {
		return nil, fmt.Errorf("解析消息失败: %w", err)
	}

	return &msg, nil
}

// SendDocument 发送文档
func (c *Client) SendDocument(ctx context.Context, req *SendDocumentRequest) (*Message, error) {
	// 如果是 URL 或 file_id，使用 JSON 请求
	if req.Document != "" {
		resp, err := c.postJSON(ctx, "sendDocument", req)
		if err != nil {
			return nil, err
		}

		var msg Message
		if err := json.Unmarshal(resp.Result, &msg); err != nil {
			return nil, fmt.Errorf("解析消息失败: %w", err)
		}

		return &msg, nil
	}

	// 如果是文件上传，使用 multipart
	if req.DocumentFile == nil {
		return nil, fmt.Errorf("document 或 document_file 必须提供其一")
	}

	fields := map[string]string{
		"chat_id": fmt.Sprintf("%v", req.ChatID),
	}
	if req.Caption != "" {
		fields["caption"] = req.Caption
	}
	if req.ParseMode != "" {
		fields["parse_mode"] = req.ParseMode
	}

	files := map[string]FileUpload{
		"document": *req.DocumentFile,
	}

	resp, err := c.postMultipart(ctx, "sendDocument", fields, files)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(resp.Result, &msg); err != nil {
		return nil, fmt.Errorf("解析消息失败: %w", err)
	}

	return &msg, nil
}

// EditMessageText 编辑消息文本
func (c *Client) EditMessageText(ctx context.Context, req *EditMessageTextRequest) (*Message, error) {
	resp, err := c.postJSON(ctx, "editMessageText", req)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(resp.Result, &msg); err != nil {
		return nil, fmt.Errorf("解析消息失败: %w", err)
	}

	return &msg, nil
}

// DeleteMessage 删除消息
func (c *Client) DeleteMessage(ctx context.Context, chatID ChatID, messageID int64) error {
	req := map[string]any{
		"chat_id":    chatID,
		"message_id": messageID,
	}

	_, err := c.postJSON(ctx, "deleteMessage", req)
	return err
}

// SendChatAction 发送聊天动作（如 typing、upload_photo 等）
func (c *Client) SendChatAction(ctx context.Context, chatID ChatID, action ChatAction) error {
	req := map[string]any{
		"chat_id": chatID,
		"action":  action,
	}

	_, err := c.postJSON(ctx, "sendChatAction", req)
	return err
}

// GetChat 获取聊天信息
func (c *Client) GetChat(ctx context.Context, chatID ChatID) (*Chat, error) {
	req := map[string]any{
		"chat_id": chatID,
	}

	resp, err := c.postJSON(ctx, "getChat", req)
	if err != nil {
		return nil, err
	}

	var chat Chat
	if err := json.Unmarshal(resp.Result, &chat); err != nil {
		return nil, fmt.Errorf("解析聊天信息失败: %w", err)
	}

	return &chat, nil
}

// SetWebhook 设置 Webhook
func (c *Client) SetWebhook(ctx context.Context, req *SetWebhookRequest) error {
	_, err := c.postJSON(ctx, "setWebhook", req)
	return err
}

// DeleteWebhook 删除 Webhook
func (c *Client) DeleteWebhook(ctx context.Context, dropPendingUpdates bool) error {
	req := map[string]any{
		"drop_pending_updates": dropPendingUpdates,
	}

	_, err := c.postJSON(ctx, "deleteWebhook", req)
	return err
}

// GetWebhookInfo 获取 Webhook 信息
func (c *Client) GetWebhookInfo(ctx context.Context) (*WebhookInfo, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "getWebhookInfo", nil, "")
	if err != nil {
		return nil, err
	}

	var info WebhookInfo
	if err := json.Unmarshal(resp.Result, &info); err != nil {
		return nil, fmt.Errorf("解析 Webhook 信息失败: %w", err)
	}

	return &info, nil
}

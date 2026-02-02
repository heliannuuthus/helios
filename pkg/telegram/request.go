package telegram

// SendMessageRequest 发送消息请求
type SendMessageRequest struct {
	ChatID                   ChatID `json:"chat_id"`
	Text                     string `json:"text"`
	MessageThreadID          int64  `json:"message_thread_id,omitempty"`
	ParseMode                string `json:"parse_mode,omitempty"`
	DisableWebPagePreview    bool   `json:"disable_web_page_preview,omitempty"`
	DisableNotification      bool   `json:"disable_notification,omitempty"`
	ProtectContent           bool   `json:"protect_content,omitempty"`
	ReplyToMessageID         int64  `json:"reply_to_message_id,omitempty"`
	AllowSendingWithoutReply bool   `json:"allow_sending_without_reply,omitempty"`
	ReplyMarkup              any    `json:"reply_markup,omitempty"` // InlineKeyboard, ReplyKeyboard, ReplyKeyboardRemove
}

// SendPhotoRequest 发送图片请求
type SendPhotoRequest struct {
	ChatID                   ChatID      `json:"chat_id"`
	Photo                    string      `json:"photo,omitempty"` // file_id 或 URL
	PhotoFile                *FileUpload `json:"-"`               // 文件上传（二选一）
	MessageThreadID          int64       `json:"message_thread_id,omitempty"`
	Caption                  string      `json:"caption,omitempty"`
	ParseMode                string      `json:"parse_mode,omitempty"`
	HasSpoiler               bool        `json:"has_spoiler,omitempty"`
	DisableNotification      bool        `json:"disable_notification,omitempty"`
	ProtectContent           bool        `json:"protect_content,omitempty"`
	ReplyToMessageID         int64       `json:"reply_to_message_id,omitempty"`
	AllowSendingWithoutReply bool        `json:"allow_sending_without_reply,omitempty"`
	ReplyMarkup              any         `json:"reply_markup,omitempty"`
}

// SendDocumentRequest 发送文档请求
type SendDocumentRequest struct {
	ChatID                      ChatID      `json:"chat_id"`
	Document                    string      `json:"document,omitempty"` // file_id 或 URL
	DocumentFile                *FileUpload `json:"-"`                  // 文件上传（二选一）
	MessageThreadID             int64       `json:"message_thread_id,omitempty"`
	Thumbnail                   string      `json:"thumbnail,omitempty"`
	Caption                     string      `json:"caption,omitempty"`
	ParseMode                   string      `json:"parse_mode,omitempty"`
	DisableContentTypeDetection bool        `json:"disable_content_type_detection,omitempty"`
	DisableNotification         bool        `json:"disable_notification,omitempty"`
	ProtectContent              bool        `json:"protect_content,omitempty"`
	ReplyToMessageID            int64       `json:"reply_to_message_id,omitempty"`
	AllowSendingWithoutReply    bool        `json:"allow_sending_without_reply,omitempty"`
	ReplyMarkup                 any         `json:"reply_markup,omitempty"`
}

// EditMessageTextRequest 编辑消息文本请求
type EditMessageTextRequest struct {
	ChatID                ChatID `json:"chat_id,omitempty"`
	MessageID             int64  `json:"message_id,omitempty"`
	InlineMessageID       string `json:"inline_message_id,omitempty"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview,omitempty"`
	ReplyMarkup           any    `json:"reply_markup,omitempty"`
}

// SetWebhookRequest 设置 Webhook 请求
type SetWebhookRequest struct {
	URL                string   `json:"url"`
	Certificate        string   `json:"certificate,omitempty"`
	IPAddress          string   `json:"ip_address,omitempty"`
	MaxConnections     int      `json:"max_connections,omitempty"`
	AllowedUpdates     []string `json:"allowed_updates,omitempty"`
	DropPendingUpdates bool     `json:"drop_pending_updates,omitempty"`
	SecretToken        string   `json:"secret_token,omitempty"`
}

// AnswerCallbackQueryRequest 回复回调查询请求
type AnswerCallbackQueryRequest struct {
	CallbackQueryID string `json:"callback_query_id"`
	Text            string `json:"text,omitempty"`
	ShowAlert       bool   `json:"show_alert,omitempty"`
	URL             string `json:"url,omitempty"`
	CacheTime       int    `json:"cache_time,omitempty"`
}

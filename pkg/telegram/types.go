package telegram

import (
	"github.com/go-json-experiment/json/jsontext"
	"io"
)

// ChatID 可以是 int64（chat_id）或 string（@username）
type ChatID any

// ChatAction 聊天动作类型
type ChatAction string

const (
	ActionTyping          ChatAction = "typing"
	ActionUploadPhoto     ChatAction = "upload_photo"
	ActionRecordVideo     ChatAction = "record_video"
	ActionUploadVideo     ChatAction = "upload_video"
	ActionRecordVoice     ChatAction = "record_voice"
	ActionUploadVoice     ChatAction = "upload_voice"
	ActionUploadDocument  ChatAction = "upload_document"
	ActionChooseSticker   ChatAction = "choose_sticker"
	ActionFindLocation    ChatAction = "find_location"
	ActionRecordVideoNote ChatAction = "record_video_note"
	ActionUploadVideoNote ChatAction = "upload_video_note"
)

// ParseMode 消息解析模式
type ParseMode string

const (
	ParseModeMarkdown   ParseMode = "Markdown"
	ParseModeMarkdownV2 ParseMode = "MarkdownV2"
	ParseModeHTML       ParseMode = "HTML"
)

// Response Telegram API 通用响应
type Response struct {
	OK          bool            `json:"ok"`
	Result      jsontext.Value `json:"result,omitempty"`
	Description string          `json:"description,omitempty"`
	ErrorCode   int             `json:"error_code,omitempty"`
}

// User Telegram 用户
type User struct {
	ID                      int64  `json:"id"`
	IsBot                   bool   `json:"is_bot"`
	FirstName               string `json:"first_name"`
	LastName                string `json:"last_name,omitempty"`
	Username                string `json:"username,omitempty"`
	LanguageCode            string `json:"language_code,omitempty"`
	IsPremium               bool   `json:"is_premium,omitempty"`
	CanJoinGroups           bool   `json:"can_join_groups,omitempty"`
	CanReadAllGroupMessages bool   `json:"can_read_all_group_messages,omitempty"`
	SupportsInlineQueries   bool   `json:"supports_inline_queries,omitempty"`
}

// Chat Telegram 聊天
type Chat struct {
	ID                    int64  `json:"id"`
	Type                  string `json:"type"` // private, group, supergroup, channel
	Title                 string `json:"title,omitempty"`
	Username              string `json:"username,omitempty"`
	FirstName             string `json:"first_name,omitempty"`
	LastName              string `json:"last_name,omitempty"`
	Description           string `json:"description,omitempty"`
	InviteLink            string `json:"invite_link,omitempty"`
	SlowModeDelay         int    `json:"slow_mode_delay,omitempty"`
	MessageAutoDeleteTime int    `json:"message_auto_delete_time,omitempty"`
}

// Message Telegram 消息
type Message struct {
	MessageID       int64           `json:"message_id"`
	MessageThreadID int64           `json:"message_thread_id,omitempty"`
	From            *User           `json:"from,omitempty"`
	Chat            Chat            `json:"chat"`
	Date            int64           `json:"date"`
	EditDate        int64           `json:"edit_date,omitempty"`
	Text            string          `json:"text,omitempty"`
	Caption         string          `json:"caption,omitempty"`
	Photo           []PhotoSize     `json:"photo,omitempty"`
	Document        *Document       `json:"document,omitempty"`
	ReplyToMessage  *Message        `json:"reply_to_message,omitempty"`
	ReplyMarkup     *InlineKeyboard `json:"reply_markup,omitempty"`
}

// PhotoSize 图片尺寸信息
type PhotoSize struct {
	FileID       string `json:"file_id"`
	FileUniqueID string `json:"file_unique_id"`
	Width        int    `json:"width"`
	Height       int    `json:"height"`
	FileSize     int64  `json:"file_size,omitempty"`
}

// Document 文档信息
type Document struct {
	FileID       string     `json:"file_id"`
	FileUniqueID string     `json:"file_unique_id"`
	Thumbnail    *PhotoSize `json:"thumbnail,omitempty"`
	FileName     string     `json:"file_name,omitempty"`
	MimeType     string     `json:"mime_type,omitempty"`
	FileSize     int64      `json:"file_size,omitempty"`
}

// FileUpload 文件上传
type FileUpload struct {
	Filename string
	Reader   io.Reader
}

// InlineKeyboard 内联键盘
type InlineKeyboard struct {
	InlineKeyboard [][]InlineKeyboardButton `json:"inline_keyboard"`
}

// InlineKeyboardButton 内联键盘按钮
type InlineKeyboardButton struct {
	Text                         string `json:"text"`
	URL                          string `json:"url,omitempty"`
	CallbackData                 string `json:"callback_data,omitempty"`
	SwitchInlineQuery            string `json:"switch_inline_query,omitempty"`
	SwitchInlineQueryCurrentChat string `json:"switch_inline_query_current_chat,omitempty"`
}

// ReplyKeyboard 回复键盘
type ReplyKeyboard struct {
	Keyboard              [][]KeyboardButton `json:"keyboard"`
	IsPersistent          bool               `json:"is_persistent,omitempty"`
	ResizeKeyboard        bool               `json:"resize_keyboard,omitempty"`
	OneTimeKeyboard       bool               `json:"one_time_keyboard,omitempty"`
	InputFieldPlaceholder string             `json:"input_field_placeholder,omitempty"`
	Selective             bool               `json:"selective,omitempty"`
}

// KeyboardButton 键盘按钮
type KeyboardButton struct {
	Text            string `json:"text"`
	RequestContact  bool   `json:"request_contact,omitempty"`
	RequestLocation bool   `json:"request_location,omitempty"`
}

// ReplyKeyboardRemove 移除回复键盘
type ReplyKeyboardRemove struct {
	RemoveKeyboard bool `json:"remove_keyboard"`
	Selective      bool `json:"selective,omitempty"`
}

// WebhookInfo Webhook 信息
type WebhookInfo struct {
	URL                          string   `json:"url"`
	HasCustomCertificate         bool     `json:"has_custom_certificate"`
	PendingUpdateCount           int      `json:"pending_update_count"`
	IPAddress                    string   `json:"ip_address,omitempty"`
	LastErrorDate                int64    `json:"last_error_date,omitempty"`
	LastErrorMessage             string   `json:"last_error_message,omitempty"`
	LastSynchronizationErrorDate int64    `json:"last_synchronization_error_date,omitempty"`
	MaxConnections               int      `json:"max_connections,omitempty"`
	AllowedUpdates               []string `json:"allowed_updates,omitempty"`
}

// Update Webhook 更新
type Update struct {
	UpdateID      int64     `json:"update_id"`
	Message       *Message  `json:"message,omitempty"`
	EditedMessage *Message  `json:"edited_message,omitempty"`
	ChannelPost   *Message  `json:"channel_post,omitempty"`
	CallbackQuery *Callback `json:"callback_query,omitempty"`
}

// Callback 回调查询
type Callback struct {
	ID              string   `json:"id"`
	From            User     `json:"from"`
	Message         *Message `json:"message,omitempty"`
	InlineMessageID string   `json:"inline_message_id,omitempty"`
	ChatInstance    string   `json:"chat_instance"`
	Data            string   `json:"data,omitempty"`
}

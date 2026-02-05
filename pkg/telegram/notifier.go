package telegram

import (
	"context"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/pkg/logger"
)

// Notifier 通知发送器，封装常用的消息发送场景
type Notifier struct {
	client    *Client
	defaultTo ChatID
}

// NewNotifier 创建通知发送器
// defaultTo: 默认发送目标（chat_id 或 @username）
func NewNotifier(client *Client, defaultTo ChatID) *Notifier {
	return &Notifier{
		client:    client,
		defaultTo: defaultTo,
	}
}

// NotifyOption 通知选项
type NotifyOption func(*SendMessageRequest)

// WithChatID 指定发送目标
func WithChatID(chatID ChatID) NotifyOption {
	return func(req *SendMessageRequest) {
		req.ChatID = chatID
	}
}

// WithParseMode 设置解析模式
func WithParseMode(mode ParseMode) NotifyOption {
	return func(req *SendMessageRequest) {
		req.ParseMode = string(mode)
	}
}

// WithMarkdown 使用 Markdown 格式
func WithMarkdown() NotifyOption {
	return func(req *SendMessageRequest) {
		req.ParseMode = string(ParseModeMarkdown)
	}
}

// WithMarkdownV2 使用 MarkdownV2 格式
func WithMarkdownV2() NotifyOption {
	return func(req *SendMessageRequest) {
		req.ParseMode = string(ParseModeMarkdownV2)
	}
}

// WithHTML 使用 HTML 格式
func WithHTML() NotifyOption {
	return func(req *SendMessageRequest) {
		req.ParseMode = string(ParseModeHTML)
	}
}

// WithSilent 静默发送（不触发通知）
func WithSilent() NotifyOption {
	return func(req *SendMessageRequest) {
		req.DisableNotification = true
	}
}

// WithReplyTo 回复指定消息
func WithReplyTo(messageID int64) NotifyOption {
	return func(req *SendMessageRequest) {
		req.ReplyToMessageID = messageID
	}
}

// WithInlineKeyboard 添加内联键盘
func WithInlineKeyboard(keyboard *InlineKeyboard) NotifyOption {
	return func(req *SendMessageRequest) {
		req.ReplyMarkup = keyboard
	}
}

// WithDisablePreview 禁用链接预览
func WithDisablePreview() NotifyOption {
	return func(req *SendMessageRequest) {
		req.DisableWebPagePreview = true
	}
}

// Notify 发送通知消息
func (n *Notifier) Notify(ctx context.Context, text string, opts ...NotifyOption) (*Message, error) {
	req := &SendMessageRequest{
		ChatID: n.defaultTo,
		Text:   text,
	}

	for _, opt := range opts {
		opt(req)
	}

	return n.client.SendMessage(ctx, req)
}

// NotifyWithTimeout 带超时的发送通知
func (n *Notifier) NotifyWithTimeout(text string, timeout time.Duration, opts ...NotifyOption) (*Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return n.Notify(ctx, text, opts...)
}

// NotifyAsync 异步发送通知（不阻塞，错误只记录日志）
func (n *Notifier) NotifyAsync(text string, opts ...NotifyOption) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if _, err := n.Notify(ctx, text, opts...); err != nil {
			logger.Errorf("[Telegram] 异步发送通知失败: %v", err)
		}
	}()
}

// NotifyHTML 发送 HTML 格式消息
func (n *Notifier) NotifyHTML(ctx context.Context, text string, opts ...NotifyOption) (*Message, error) {
	opts = append([]NotifyOption{WithHTML()}, opts...)
	return n.Notify(ctx, text, opts...)
}

// NotifyMarkdown 发送 Markdown 格式消息
func (n *Notifier) NotifyMarkdown(ctx context.Context, text string, opts ...NotifyOption) (*Message, error) {
	opts = append([]NotifyOption{WithMarkdown()}, opts...)
	return n.Notify(ctx, text, opts...)
}

// Client 获取底层客户端（用于更复杂的操作）
func (n *Notifier) Client() *Client {
	return n.client
}

// ---- 便捷构建方法 ----

// NewInlineKeyboard 创建内联键盘
func NewInlineKeyboard(rows ...[]InlineKeyboardButton) *InlineKeyboard {
	return &InlineKeyboard{
		InlineKeyboard: rows,
	}
}

// NewInlineKeyboardRow 创建一行按钮
func NewInlineKeyboardRow(buttons ...InlineKeyboardButton) []InlineKeyboardButton {
	return buttons
}

// NewURLButton 创建 URL 按钮
func NewURLButton(text, url string) InlineKeyboardButton {
	return InlineKeyboardButton{
		Text: text,
		URL:  url,
	}
}

// NewCallbackButton 创建回调按钮
func NewCallbackButton(text, callbackData string) InlineKeyboardButton {
	return InlineKeyboardButton{
		Text:         text,
		CallbackData: callbackData,
	}
}

// ---- 格式化工具 ----

// EscapeMarkdownV2 转义 MarkdownV2 特殊字符
func EscapeMarkdownV2(text string) string {
	chars := []rune{'_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!'}
	result := text
	for _, c := range chars {
		result = escapeChar(result, c)
	}
	return result
}

func escapeChar(s string, c rune) string {
	var result []rune
	for _, r := range s {
		if r == c {
			result = append(result, '\\')
		}
		result = append(result, r)
	}
	return string(result)
}

// Bold 加粗文本（HTML）
func Bold(text string) string {
	return fmt.Sprintf("<b>%s</b>", text)
}

// Italic 斜体文本（HTML）
func Italic(text string) string {
	return fmt.Sprintf("<i>%s</i>", text)
}

// Code 代码文本（HTML）
func Code(text string) string {
	return fmt.Sprintf("<code>%s</code>", text)
}

// Pre 预格式化文本块（HTML）
func Pre(text string) string {
	return fmt.Sprintf("<pre>%s</pre>", text)
}

// PreWithLang 带语言的预格式化文本块（HTML）
func PreWithLang(text, lang string) string {
	return fmt.Sprintf("<pre><code class=\"language-%s\">%s</code></pre>", lang, text)
}

// Link 链接（HTML）
func Link(text, url string) string {
	return fmt.Sprintf("<a href=\"%s\">%s</a>", url, text)
}

// Mention 提及用户（HTML）
func Mention(text string, userID int64) string {
	return fmt.Sprintf("<a href=\"tg://user?id=%d\">%s</a>", userID, text)
}

// Spoiler 剧透文本（HTML）
func Spoiler(text string) string {
	return fmt.Sprintf("<tg-spoiler>%s</tg-spoiler>", text)
}

// Strikethrough 删除线文本（HTML）
func Strikethrough(text string) string {
	return fmt.Sprintf("<s>%s</s>", text)
}

// Underline 下划线文本（HTML）
func Underline(text string) string {
	return fmt.Sprintf("<u>%s</u>", text)
}

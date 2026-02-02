package mail

import (
	"io"
)

// ContentType 邮件内容类型
type ContentType string

const (
	ContentTypePlain ContentType = "text/plain"
	ContentTypeHTML  ContentType = "text/html"
)

// Priority 邮件优先级
type Priority int

const (
	PriorityLow    Priority = 5
	PriorityNormal Priority = 3
	PriorityHigh   Priority = 1
)

// Encryption 加密方式
type Encryption string

const (
	EncryptionNone     Encryption = "none"
	EncryptionSSL      Encryption = "ssl"
	EncryptionSTARTTLS Encryption = "starttls"
)

// Attachment 邮件附件
type Attachment struct {
	Filename    string    // 文件名
	ContentType string    // MIME 类型，如 "application/pdf"
	Reader      io.Reader // 文件内容
	Inline      bool      // 是否内嵌（用于内嵌图片等）
	ContentID   string    // 内嵌时的 Content-ID（用于 HTML 引用）
}

// Address 邮件地址
type Address struct {
	Name    string // 显示名称
	Address string // 邮件地址
}

// String 返回格式化的邮件地址
func (a Address) String() string {
	if a.Name == "" {
		return a.Address
	}
	return a.Name + " <" + a.Address + ">"
}

// Message 邮件消息
type Message struct {
	From        Address           // 发件人
	To          []Address         // 收件人
	Cc          []Address         // 抄送
	Bcc         []Address         // 密送
	ReplyTo     *Address          // 回复地址
	Subject     string            // 主题
	Body        string            // 正文内容
	ContentType ContentType       // 内容类型
	Priority    Priority          // 优先级
	Headers     map[string]string // 自定义头
	Attachments []Attachment      // 附件
}

// NewMessage 创建新邮件消息
func NewMessage() *Message {
	return &Message{
		ContentType: ContentTypePlain,
		Priority:    PriorityNormal,
		Headers:     make(map[string]string),
	}
}

// SetFrom 设置发件人
func (m *Message) SetFrom(address string, name ...string) *Message {
	m.From = Address{Address: address}
	if len(name) > 0 {
		m.From.Name = name[0]
	}
	return m
}

// AddTo 添加收件人
func (m *Message) AddTo(address string, name ...string) *Message {
	addr := Address{Address: address}
	if len(name) > 0 {
		addr.Name = name[0]
	}
	m.To = append(m.To, addr)
	return m
}

// AddCc 添加抄送
func (m *Message) AddCc(address string, name ...string) *Message {
	addr := Address{Address: address}
	if len(name) > 0 {
		addr.Name = name[0]
	}
	m.Cc = append(m.Cc, addr)
	return m
}

// AddBcc 添加密送
func (m *Message) AddBcc(address string, name ...string) *Message {
	addr := Address{Address: address}
	if len(name) > 0 {
		addr.Name = name[0]
	}
	m.Bcc = append(m.Bcc, addr)
	return m
}

// SetReplyTo 设置回复地址
func (m *Message) SetReplyTo(address string, name ...string) *Message {
	addr := Address{Address: address}
	if len(name) > 0 {
		addr.Name = name[0]
	}
	m.ReplyTo = &addr
	return m
}

// SetSubject 设置主题
func (m *Message) SetSubject(subject string) *Message {
	m.Subject = subject
	return m
}

// SetBody 设置正文
func (m *Message) SetBody(body string) *Message {
	m.Body = body
	return m
}

// SetHTML 设置 HTML 正文
func (m *Message) SetHTML(html string) *Message {
	m.Body = html
	m.ContentType = ContentTypeHTML
	return m
}

// SetPlainText 设置纯文本正文
func (m *Message) SetPlainText(text string) *Message {
	m.Body = text
	m.ContentType = ContentTypePlain
	return m
}

// SetPriority 设置优先级
func (m *Message) SetPriority(priority Priority) *Message {
	m.Priority = priority
	return m
}

// SetHeader 设置自定义头
func (m *Message) SetHeader(key, value string) *Message {
	m.Headers[key] = value
	return m
}

// AddAttachment 添加附件
func (m *Message) AddAttachment(attachment Attachment) *Message {
	m.Attachments = append(m.Attachments, attachment)
	return m
}

// AddFileAttachment 添加文件附件
func (m *Message) AddFileAttachment(filename string, reader io.Reader, contentType string) *Message {
	m.Attachments = append(m.Attachments, Attachment{
		Filename:    filename,
		ContentType: contentType,
		Reader:      reader,
		Inline:      false,
	})
	return m
}

// AddInlineAttachment 添加内嵌附件（如图片）
func (m *Message) AddInlineAttachment(filename, contentID string, reader io.Reader, contentType string) *Message {
	m.Attachments = append(m.Attachments, Attachment{
		Filename:    filename,
		ContentType: contentType,
		Reader:      reader,
		Inline:      true,
		ContentID:   contentID,
	})
	return m
}

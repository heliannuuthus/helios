package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

const (
	defaultPort       = 587
	defaultSSLPort    = 465
	defaultTimeout    = 30 * time.Second
	defaultEncryption = EncryptionSTARTTLS
)

// Client SMTP 邮件客户端
type Client struct {
	host       string
	port       int
	username   string
	password   string
	encryption Encryption
	timeout    time.Duration
	tlsConfig  *tls.Config
	localName  string // HELO/EHLO 使用的本地主机名
}

// Option 客户端配置选项
type Option func(*Client)

// WithPort 设置 SMTP 端口
func WithPort(port int) Option {
	return func(c *Client) {
		c.port = port
	}
}

// WithEncryption 设置加密方式
func WithEncryption(encryption Encryption) Option {
	return func(c *Client) {
		c.encryption = encryption
	}
}

// WithTimeout 设置连接超时
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.timeout = timeout
	}
}

// WithTLSConfig 设置 TLS 配置
func WithTLSConfig(config *tls.Config) Option {
	return func(c *Client) {
		c.tlsConfig = config
	}
}

// WithLocalName 设置 HELO/EHLO 本地主机名
func WithLocalName(name string) Option {
	return func(c *Client) {
		c.localName = name
	}
}

// WithSSL 使用 SSL 加密（端口 465）
func WithSSL() Option {
	return func(c *Client) {
		c.encryption = EncryptionSSL
		if c.port == defaultPort {
			c.port = defaultSSLPort
		}
	}
}

// WithSTARTTLS 使用 STARTTLS 加密（端口 587）
func WithSTARTTLS() Option {
	return func(c *Client) {
		c.encryption = EncryptionSTARTTLS
		if c.port == defaultSSLPort {
			c.port = defaultPort
		}
	}
}

// NewClient 创建 SMTP 客户端
//
// host: SMTP 服务器地址
// username: 认证用户名（通常是邮箱地址）
// password: 认证密码或授权码
func NewClient(host, username, password string, opts ...Option) *Client {
	c := &Client{
		host:       host,
		port:       defaultPort,
		username:   username,
		password:   password,
		encryption: defaultEncryption,
		timeout:    defaultTimeout,
		localName:  "localhost",
	}

	for _, opt := range opts {
		opt(c)
	}

	// 如果没有自定义 TLS 配置，创建默认配置
	if c.tlsConfig == nil {
		c.tlsConfig = &tls.Config{
			ServerName: c.host,
			MinVersion: tls.VersionTLS12,
		}
	}

	return c
}

// addr 返回服务器地址
func (c *Client) addr() string {
	return fmt.Sprintf("%s:%d", c.host, c.port)
}

// dial 建立连接
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	if c.encryption == EncryptionSSL {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    c.tlsConfig,
		}
		return tlsDialer.DialContext(ctx, "tcp", c.addr())
	}

	return dialer.DialContext(ctx, "tcp", c.addr())
}

// Send 发送邮件
func (c *Client) Send(ctx context.Context, msg *Message) error {
	if err := c.validateMessage(msg); err != nil {
		return fmt.Errorf("validate message failed: %w", err)
	}

	client, cleanup, err := c.createSMTPClient(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := c.setupConnection(client); err != nil {
		return err
	}

	if err := c.sendEnvelope(client, msg); err != nil {
		return err
	}

	if err := c.sendContent(client, msg); err != nil {
		return err
	}

	return client.Quit()
}

// createSMTPClient 创建 SMTP 客户端并返回清理函数
func (c *Client) createSMTPClient(ctx context.Context) (*smtp.Client, func(), error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("dial failed: %w", err)
	}

	client, err := smtp.NewClient(conn, c.host)
	if err != nil {
		_ = conn.Close() //nolint:errcheck
		return nil, nil, fmt.Errorf("create smtp client failed: %w", err)
	}

	cleanup := func() {
		_ = client.Close() //nolint:errcheck
		_ = conn.Close()   //nolint:errcheck
	}

	return client, cleanup, nil
}

// setupConnection 设置连接（HELLO、STARTTLS、AUTH）
func (c *Client) setupConnection(client *smtp.Client) error {
	if err := client.Hello(c.localName); err != nil {
		return fmt.Errorf("hello failed: %w", err)
	}

	if c.encryption == EncryptionSTARTTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(c.tlsConfig); err != nil {
				return fmt.Errorf("starttls failed: %w", err)
			}
		}
	}

	if c.username != "" && c.password != "" {
		auth := smtp.PlainAuth("", c.username, c.password, c.host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth failed: %w", err)
		}
	}

	return nil
}

// sendEnvelope 发送信封（发件人、收件人）
func (c *Client) sendEnvelope(client *smtp.Client, msg *Message) error {
	from := msg.From.Address
	if from == "" {
		from = c.username
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("mail from failed: %w", err)
	}

	for _, rcpt := range c.collectRecipients(msg) {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("rcpt to %s failed: %w", rcpt, err)
		}
	}

	return nil
}

// sendContent 发送邮件内容
func (c *Client) sendContent(client *smtp.Client, msg *Message) error {
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("data command failed: %w", err)
	}

	content, err := c.buildMessage(msg)
	if err != nil {
		return fmt.Errorf("build message failed: %w", err)
	}

	if _, err := w.Write(content); err != nil {
		return fmt.Errorf("write message failed: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("close data writer failed: %w", err)
	}

	return nil
}

// SendSimple 发送简单邮件（便捷方法）
func (c *Client) SendSimple(ctx context.Context, to, subject, body string) error {
	msg := NewMessage().
		AddTo(to).
		SetSubject(subject).
		SetBody(body)
	return c.Send(ctx, msg)
}

// SendHTML 发送 HTML 邮件（便捷方法）
func (c *Client) SendHTML(ctx context.Context, to, subject, html string) error {
	msg := NewMessage().
		AddTo(to).
		SetSubject(subject).
		SetHTML(html)
	return c.Send(ctx, msg)
}

// validateMessage 验证邮件消息
func (c *Client) validateMessage(msg *Message) error {
	if len(msg.To) == 0 {
		return fmt.Errorf("no recipients")
	}
	if msg.Subject == "" {
		return fmt.Errorf("empty subject")
	}
	return nil
}

// collectRecipients 收集所有收件人
func (c *Client) collectRecipients(msg *Message) []string {
	recipients := make([]string, 0, len(msg.To)+len(msg.Cc)+len(msg.Bcc))
	for _, addr := range msg.To {
		recipients = append(recipients, addr.Address)
	}
	for _, addr := range msg.Cc {
		recipients = append(recipients, addr.Address)
	}
	for _, addr := range msg.Bcc {
		recipients = append(recipients, addr.Address)
	}
	return recipients
}

// buildMessage 构建邮件内容
func (c *Client) buildMessage(msg *Message) ([]byte, error) {
	var buf bytes.Buffer

	// 写入邮件头
	c.writeHeader(&buf, msg)

	// 根据是否有附件决定内容格式
	if len(msg.Attachments) > 0 {
		if err := c.writeMultipartBody(&buf, msg); err != nil {
			return nil, err
		}
	} else {
		c.writeSimpleBody(&buf, msg)
	}

	return buf.Bytes(), nil
}

// writeHeader 写入邮件头
func (c *Client) writeHeader(buf *bytes.Buffer, msg *Message) {
	// From
	from := msg.From
	if from.Address == "" {
		from.Address = c.username
	}
	fmt.Fprintf(buf, "From: %s\r\n", c.encodeAddress(from))

	// To
	toAddrs := make([]string, 0, len(msg.To))
	for _, addr := range msg.To {
		toAddrs = append(toAddrs, c.encodeAddress(addr))
	}
	fmt.Fprintf(buf, "To: %s\r\n", strings.Join(toAddrs, ", "))

	// Cc
	if len(msg.Cc) > 0 {
		ccAddrs := make([]string, 0, len(msg.Cc))
		for _, addr := range msg.Cc {
			ccAddrs = append(ccAddrs, c.encodeAddress(addr))
		}
		fmt.Fprintf(buf, "Cc: %s\r\n", strings.Join(ccAddrs, ", "))
	}

	// Reply-To
	if msg.ReplyTo != nil {
		fmt.Fprintf(buf, "Reply-To: %s\r\n", c.encodeAddress(*msg.ReplyTo))
	}

	// Subject
	fmt.Fprintf(buf, "Subject: %s\r\n", c.encodeSubject(msg.Subject))

	// Date
	fmt.Fprintf(buf, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))

	// Message-ID
	fmt.Fprintf(buf, "Message-ID: <%d.%s@%s>\r\n",
		time.Now().UnixNano(), c.username, c.host)

	// MIME-Version
	buf.WriteString("MIME-Version: 1.0\r\n")

	// Priority
	if msg.Priority != PriorityNormal {
		fmt.Fprintf(buf, "X-Priority: %d\r\n", msg.Priority)
	}

	// Custom headers
	for key, value := range msg.Headers {
		fmt.Fprintf(buf, "%s: %s\r\n", key, value)
	}
}

// writeSimpleBody 写入简单邮件正文
func (c *Client) writeSimpleBody(buf *bytes.Buffer, msg *Message) {
	fmt.Fprintf(buf, "Content-Type: %s; charset=UTF-8\r\n", msg.ContentType)
	buf.WriteString("Content-Transfer-Encoding: base64\r\n")
	buf.WriteString("\r\n")

	// 使用 base64 编码，更兼容各邮件客户端
	encoded := base64.StdEncoding.EncodeToString([]byte(msg.Body))
	// 每 76 个字符换行（RFC 2045）
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteString("\r\n")
	}
}

// writeMultipartBody 写入带附件的邮件正文
func (c *Client) writeMultipartBody(buf *bytes.Buffer, msg *Message) error {
	hasInline := c.hasInlineAttachments(msg)
	boundary := c.generateBoundary("mixed")
	fmt.Fprintf(buf, "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", boundary)

	// 写入正文部分
	fmt.Fprintf(buf, "--%s\r\n", boundary)
	if err := c.writeBodyPart(buf, msg, hasInline); err != nil {
		return err
	}

	// 写入普通附件
	if err := c.writeNormalAttachments(buf, boundary, msg); err != nil {
		return err
	}

	fmt.Fprintf(buf, "--%s--\r\n", boundary)
	return nil
}

// hasInlineAttachments 检查是否有内嵌附件
func (c *Client) hasInlineAttachments(msg *Message) bool {
	for _, att := range msg.Attachments {
		if att.Inline {
			return true
		}
	}
	return false
}

// writeBodyPart 写入邮件正文部分
func (c *Client) writeBodyPart(buf *bytes.Buffer, msg *Message, hasInline bool) error {
	if hasInline && msg.ContentType == ContentTypeHTML {
		return c.writeRelatedBody(buf, msg)
	}
	fmt.Fprintf(buf, "Content-Type: %s; charset=UTF-8\r\n", msg.ContentType)
	buf.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	c.writeBase64Body(buf, msg.Body)
	buf.WriteString("\r\n")
	return nil
}

// writeRelatedBody 写入 HTML 正文和内嵌图片（multipart/related）
func (c *Client) writeRelatedBody(buf *bytes.Buffer, msg *Message) error {
	relatedBoundary := c.generateBoundary("related")
	fmt.Fprintf(buf, "Content-Type: multipart/related; boundary=\"%s\"\r\n\r\n", relatedBoundary)

	// HTML 正文
	fmt.Fprintf(buf, "--%s\r\n", relatedBoundary)
	fmt.Fprintf(buf, "Content-Type: %s; charset=UTF-8\r\n", msg.ContentType)
	buf.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	c.writeBase64Body(buf, msg.Body)
	buf.WriteString("\r\n")

	// 内嵌附件
	for _, att := range msg.Attachments {
		if !att.Inline {
			continue
		}
		if err := c.writeAttachment(buf, relatedBoundary, att); err != nil {
			return err
		}
	}

	fmt.Fprintf(buf, "--%s--\r\n", relatedBoundary)
	return nil
}

// writeNormalAttachments 写入普通附件
func (c *Client) writeNormalAttachments(buf *bytes.Buffer, boundary string, msg *Message) error {
	for _, att := range msg.Attachments {
		if att.Inline {
			continue
		}
		if err := c.writeAttachment(buf, boundary, att); err != nil {
			return err
		}
	}
	return nil
}

// writeAttachment 写入附件
func (c *Client) writeAttachment(buf *bytes.Buffer, boundary string, att Attachment) error {
	fmt.Fprintf(buf, "--%s\r\n", boundary)

	contentType := att.ContentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	encodedFilename := mime.QEncoding.Encode("UTF-8", att.Filename)

	if att.Inline {
		fmt.Fprintf(buf, "Content-Type: %s; name=\"%s\"\r\n", contentType, encodedFilename)
		buf.WriteString("Content-Transfer-Encoding: base64\r\n")
		fmt.Fprintf(buf, "Content-Disposition: inline; filename=\"%s\"\r\n", encodedFilename)
		if att.ContentID != "" {
			fmt.Fprintf(buf, "Content-ID: <%s>\r\n", att.ContentID)
		}
	} else {
		fmt.Fprintf(buf, "Content-Type: %s; name=\"%s\"\r\n", contentType, encodedFilename)
		buf.WriteString("Content-Transfer-Encoding: base64\r\n")
		fmt.Fprintf(buf, "Content-Disposition: attachment; filename=\"%s\"\r\n", encodedFilename)
	}
	buf.WriteString("\r\n")

	// 读取附件内容并 base64 编码
	data, err := io.ReadAll(att.Reader)
	if err != nil {
		return fmt.Errorf("read attachment %s failed: %w", att.Filename, err)
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	// 每 76 个字符换行
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteString("\r\n")
	}

	return nil
}

// encodeAddress 编码邮件地址
func (c *Client) encodeAddress(addr Address) string {
	if addr.Name == "" {
		return addr.Address
	}
	encodedName := mime.QEncoding.Encode("UTF-8", addr.Name)
	return fmt.Sprintf("%s <%s>", encodedName, addr.Address)
}

// encodeSubject 编码邮件主题
func (c *Client) encodeSubject(subject string) string {
	return mime.QEncoding.Encode("UTF-8", subject)
}

// generateBoundary 生成 MIME 边界
func (c *Client) generateBoundary(prefix string) string {
	return fmt.Sprintf("=_%s_%d_=", prefix, time.Now().UnixNano())
}

// writeBase64Body 写入 base64 编码的正文
func (c *Client) writeBase64Body(buf *bytes.Buffer, body string) {
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	// 每 76 个字符换行（RFC 2045）
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteString("\r\n")
	}
}

// Verify 验证 SMTP 连接和认证
func (c *Client) Verify(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	defer func() { _ = conn.Close() }() //nolint:errcheck

	client, err := smtp.NewClient(conn, c.host)
	if err != nil {
		return fmt.Errorf("create smtp client failed: %w", err)
	}
	defer func() { _ = client.Close() }() //nolint:errcheck

	if err := client.Hello(c.localName); err != nil {
		return fmt.Errorf("hello failed: %w", err)
	}

	if c.encryption == EncryptionSTARTTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(c.tlsConfig); err != nil {
				return fmt.Errorf("starttls failed: %w", err)
			}
		}
	}

	if c.username != "" && c.password != "" {
		auth := smtp.PlainAuth("", c.username, c.password, c.host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth failed: %w", err)
		}
	}

	return client.Quit()
}

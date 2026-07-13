package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"github.com/knadh/smtppool/v2"

	"github.com/heliannuuthus/pkg/logger"
)

const (
	defaultPort        = 587
	defaultSSLPort     = 465
	defaultTimeout     = 30 * time.Second
	defaultMaxConns    = 5
	defaultIdleTimeout = 30 * time.Second
	defaultPoolWait    = 5 * time.Second
)

// Client SMTP 连接池客户端
type Client struct {
	pool     *smtppool.Pool
	host     string
	port     int
	username string
	password string
	useSSL   bool
}

// ClientConfig 客户端配置
type ClientConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	UseSSL      bool
	MaxConns    int
	IdleTimeout time.Duration
	PoolWait    time.Duration
}

// NewClient 创建 SMTP 连接池客户端
func NewClient(cfg *ClientConfig) (*Client, error) {
	if cfg == nil {
		return nil, fmt.Errorf("mail client config is required")
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, fmt.Errorf("smtp host is required")
	}
	if strings.TrimSpace(cfg.Username) == "" {
		return nil, fmt.Errorf("smtp username is required")
	}
	if strings.TrimSpace(cfg.Password) == "" {
		return nil, fmt.Errorf("smtp password is required")
	}
	port := cfg.Port
	if port == 0 {
		if cfg.UseSSL {
			port = defaultSSLPort
		} else {
			port = defaultPort
		}
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid smtp port: %d", port)
	}

	maxConns := cfg.MaxConns
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}

	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}

	poolWait := cfg.PoolWait
	if poolWait <= 0 {
		poolWait = defaultPoolWait
	}

	ssl := smtppool.SSLSTARTTLS
	if cfg.UseSSL {
		ssl = smtppool.SSLTLS
	}

	pool, err := smtppool.New(smtppool.Opt{
		Host:            cfg.Host,
		Port:            port,
		Auth:            smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host),
		MaxConns:        maxConns,
		IdleTimeout:     idleTimeout,
		PoolWaitTimeout: poolWait,
		SSL:             ssl,
	})
	if err != nil {
		return nil, fmt.Errorf("create smtp pool: %w", err)
	}

	return &Client{
		pool:     pool,
		host:     cfg.Host,
		port:     port,
		username: cfg.Username,
		password: cfg.Password,
		useSSL:   cfg.UseSSL,
	}, nil
}

// Send 发送邮件
func (c *Client) Send(_ context.Context, msg *Message) error {
	if len(msg.To) == 0 {
		return fmt.Errorf("no recipients")
	}
	if msg.Subject == "" {
		return fmt.Errorf("empty subject")
	}

	e := c.toPoolEmail(msg)
	return c.pool.Send(e)
}

// Verify 建立一次 SMTP/TLS 连接并完成认证，确保凭据不会到首次发信时才暴露问题。
func (c *Client) Verify(ctx context.Context) error {
	address := net.JoinHostPort(c.host, fmt.Sprintf("%d", c.port))
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.host}
	var smtpClient *smtp.Client
	if c.useSSL {
		conn, err := (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, "tcp", address)
		if err != nil {
			return fmt.Errorf("connect smtp tls: %w", err)
		}
		client, err := smtp.NewClient(conn, c.host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("create smtp client: %w", err)
		}
		smtpClient = client
	} else {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil {
			return fmt.Errorf("connect smtp: %w", err)
		}
		client, err := smtp.NewClient(conn, c.host)
		if err != nil {
			_ = conn.Close()
			return fmt.Errorf("create smtp client: %w", err)
		}
		if ok, _ := client.Extension("STARTTLS"); !ok {
			_ = client.Close()
			return fmt.Errorf("smtp server does not support STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			_ = client.Close()
			return fmt.Errorf("start smtp tls: %w", err)
		}
		smtpClient = client
	}
	defer smtpClient.Close()
	if err := smtpClient.Auth(smtp.PlainAuth("", c.username, c.password, c.host)); err != nil {
		return fmt.Errorf("authenticate smtp: %w", err)
	}
	logger.Debugf("[Mail] SMTP 连接验证成功: %s:%d", c.host, c.port)
	return nil
}

// Close 关闭连接池
func (c *Client) Close() {
	if c.pool != nil {
		c.pool.Close()
	}
}

// toPoolEmail 将 Message 转换为 smtppool.Email
func (c *Client) toPoolEmail(msg *Message) smtppool.Email {
	from := msg.From.Address
	if from == "" {
		from = c.username
	}

	to := make([]string, 0, len(msg.To))
	for _, addr := range msg.To {
		to = append(to, addr.String())
	}

	cc := make([]string, 0, len(msg.Cc))
	for _, addr := range msg.Cc {
		cc = append(cc, addr.String())
	}

	bcc := make([]string, 0, len(msg.Bcc))
	for _, addr := range msg.Bcc {
		bcc = append(bcc, addr.String())
	}

	e := smtppool.Email{
		From:    from,
		To:      to,
		Cc:      cc,
		Bcc:     bcc,
		Subject: msg.Subject,
	}

	if msg.ContentType == ContentTypeHTML {
		e.HTML = []byte(msg.Body)
	} else {
		e.Text = []byte(msg.Body)
	}

	for _, att := range msg.Attachments {
		if a := convertAttachment(att); a != nil {
			e.Attachments = append(e.Attachments, *a)
		}
	}

	if len(msg.Headers) > 0 {
		if e.Headers == nil {
			e.Headers = textproto.MIMEHeader{}
		}
		for k, v := range msg.Headers {
			e.Headers.Set(k, v)
		}
	}

	return e
}

func convertAttachment(att Attachment) *smtppool.Attachment {
	content, err := io.ReadAll(att.Reader)
	if err != nil {
		logger.Warnf("[Mail] 读取附件 %s 失败: %v", att.Filename, err)
		return nil
	}

	ct := att.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}

	a := smtppool.Attachment{
		Filename: att.Filename,
		Content:  content,
		Header:   textproto.MIMEHeader{},
	}
	a.Header.Set("Content-Type", ct)
	a.Header.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, att.Filename))
	a.Header.Set("Content-Transfer-Encoding", "base64")

	if att.Inline {
		a.HTMLRelated = true
		a.Header.Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, att.Filename))
		if att.ContentID != "" {
			a.Header.Set("Content-ID", fmt.Sprintf("<%s>", att.ContentID))
		}
	}

	return &a
}

package mail

import (
	"context"
	"fmt"
	"io"
	"net/smtp"
	"net/textproto"
	"time"

	"github.com/knadh/smtppool/v2"

	"github.com/heliannuuthus/helios/pkg/logger"
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
	port := cfg.Port
	if port == 0 {
		if cfg.UseSSL {
			port = defaultSSLPort
		} else {
			port = defaultPort
		}
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

// Verify 验证 SMTP 连接池可用性（池在创建时已建立首个连接，此处为空操作）
func (c *Client) Verify(_ context.Context) error {
	logger.Debugf("[Mail] SMTP 连接池验证: %s:%d", c.host, c.port)
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

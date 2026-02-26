package mail

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/mail/templates"
)

// Sender 邮件发送器
type Sender struct {
	client         *Client
	templateEngine *templates.Engine
	from           string
}

// SenderConfig 发送器配置
type SenderConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	UseSSL   bool

	MaxConns    int
	IdleTimeout int // 秒

	BrandName   string
	LogoURL     string
	FooterLinks []templates.FooterLink
}

// NewSender 创建邮件发送器
func NewSender(cfg *SenderConfig) (*Sender, error) {
	client, err := NewClient(&ClientConfig{
		Host:     cfg.Host,
		Port:     cfg.Port,
		Username: cfg.Username,
		Password: cfg.Password,
		UseSSL:   cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("create mail client: %w", err)
	}

	brandName := cfg.BrandName
	if brandName == "" {
		brandName = "Aegis"
	}

	engine, err := templates.NewEngine(&templates.EngineConfig{
		BrandName:   brandName,
		LogoURL:     cfg.LogoURL,
		FooterLinks: cfg.FooterLinks,
	})
	if err != nil {
		logger.Errorf("[Mail] 创建模板引擎失败: %v", err)
		engine = nil
	}

	return &Sender{
		client:         client,
		templateEngine: engine,
		from:           cfg.Username,
	}, nil
}

// ==================== 基础发送方法 ====================

// Send 发送邮件
func (s *Sender) Send(ctx context.Context, to, subject, body string) error {
	msg := NewMessage().
		SetFrom(s.from).
		AddTo(to).
		SetSubject(subject).
		SetHTML(body)

	if err := s.client.Send(ctx, msg); err != nil {
		logger.Errorf("[Mail] 发送邮件失败 - To: %s, Subject: %s, Error: %v", to, subject, err)
		return fmt.Errorf("send email failed: %w", err)
	}

	logger.Infof("[Mail] 发送邮件成功 - To: %s, Subject: %s", to, subject)
	return nil
}

// ==================== 实现 challenge.EmailSender 接口 ====================

// SendCode 发送验证码邮件
func (s *Sender) SendCode(ctx context.Context, email, code string) error {
	return s.SendCodeWithScene(ctx, email, code, templates.SceneOTPLogin, "")
}

// SendCodeWithScene 根据场景发送验证码邮件
func (s *Sender) SendCodeWithScene(ctx context.Context, email, code string, scene templates.Scene, greeting string) error {
	if s.templateEngine == nil {
		subject := "您的验证码"
		body := fmt.Sprintf("您的验证码是：%s，5 分钟内有效。", code)
		return s.Send(ctx, email, subject, body)
	}

	subject, html, err := s.templateEngine.RenderOTPScene(scene, code, greeting)
	if err != nil {
		logger.Errorf("[Mail] 渲染 OTP 模板失败: %v", err)
		return fmt.Errorf("render otp template failed: %w", err)
	}

	if err := s.send(ctx, email, subject, html); err != nil {
		logger.Errorf("[Mail] 发送验证码失败 - To: %s, Scene: %s, Error: %v", email, scene, err)
		return err
	}

	logger.Infof("[Mail] 发送验证码成功 - To: %s, Scene: %s", email, scene)
	return nil
}

// ==================== 操作邮件 ====================

// SendAction 发送操作邮件（带按钮）
func (s *Sender) SendAction(ctx context.Context, email string, scene templates.Scene, actionURL, greeting string) error {
	if s.templateEngine == nil {
		return fmt.Errorf("template engine not initialized")
	}

	subject, html, err := s.templateEngine.RenderActionScene(scene, actionURL, greeting)
	if err != nil {
		logger.Errorf("[Mail] 渲染 Action 模板失败: %v", err)
		return fmt.Errorf("render action template failed: %w", err)
	}

	if err := s.send(ctx, email, subject, html); err != nil {
		logger.Errorf("[Mail] 发送操作邮件失败 - To: %s, Scene: %s, Error: %v", email, scene, err)
		return err
	}

	logger.Infof("[Mail] 发送操作邮件成功 - To: %s, Scene: %s", email, scene)
	return nil
}

// ==================== 通知邮件 ====================

// SendNotification 发送通知邮件
func (s *Sender) SendNotification(ctx context.Context, email string, scene templates.Scene, details []templates.DetailItem, actionURL, greeting string) error {
	if s.templateEngine == nil {
		return fmt.Errorf("template engine not initialized")
	}

	subject, html, err := s.templateEngine.RenderNotificationScene(scene, details, actionURL, greeting)
	if err != nil {
		logger.Errorf("[Mail] 渲染 Notification 模板失败: %v", err)
		return fmt.Errorf("render notification template failed: %w", err)
	}

	if err := s.send(ctx, email, subject, html); err != nil {
		logger.Errorf("[Mail] 发送通知邮件失败 - To: %s, Scene: %s, Error: %v", email, scene, err)
		return err
	}

	logger.Infof("[Mail] 发送通知邮件成功 - To: %s, Scene: %s", email, scene)
	return nil
}

// ==================== 便捷方法 ====================

// SendLoginAlert 发送登录提醒
func (s *Sender) SendLoginAlert(ctx context.Context, email string, details []templates.DetailItem, securityURL string) error {
	return s.SendNotification(ctx, email, templates.SceneNotifyLoginAlert, details, securityURL, "")
}

// SendPasswordChanged 发送密码已更改通知
func (s *Sender) SendPasswordChanged(ctx context.Context, email string) error {
	return s.SendNotification(ctx, email, templates.SceneNotifyPasswordChanged, nil, "", "")
}

// SendVerifyEmailLink 发送邮箱验证链接
func (s *Sender) SendVerifyEmailLink(ctx context.Context, email, verifyURL string) error {
	return s.SendAction(ctx, email, templates.SceneActionVerifyEmail, verifyURL, "")
}

// SendResetPasswordLink 发送重置密码链接
func (s *Sender) SendResetPasswordLink(ctx context.Context, email, resetURL string) error {
	return s.SendAction(ctx, email, templates.SceneActionResetPassword, resetURL, "")
}

// ==================== 扩展方法 ====================

// Verify 验证 SMTP 连接
func (s *Sender) Verify(ctx context.Context) error {
	return s.client.Verify(ctx)
}

// Close 关闭连接池
func (s *Sender) Close() {
	s.client.Close()
}

// GetTemplateEngine 获取模板引擎
func (s *Sender) GetTemplateEngine() *templates.Engine {
	return s.templateEngine
}

// SetBrandName 设置品牌名称
func (s *Sender) SetBrandName(name string) {
	if s.templateEngine != nil {
		s.templateEngine.SetBrandName(name)
	}
}

// SetLogoURL 设置 Logo URL
func (s *Sender) SetLogoURL(url string) {
	if s.templateEngine != nil {
		s.templateEngine.SetLogoURL(url)
	}
}

// send 内部发送方法
func (s *Sender) send(ctx context.Context, to, subject, html string) error {
	msg := NewMessage().
		SetFrom(s.from).
		AddTo(to).
		SetSubject(subject).
		SetHTML(html)

	if err := s.client.Send(ctx, msg); err != nil {
		return fmt.Errorf("send email failed: %w", err)
	}
	return nil
}

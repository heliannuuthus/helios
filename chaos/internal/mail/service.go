package mail

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/chaos/config"
	"github.com/heliannuuthus/helios/chaos/internal/template"
	"github.com/heliannuuthus/helios/pkg/logger"
	pkgmail "github.com/heliannuuthus/helios/pkg/mail"
)

// Service 邮件服务
type Service struct {
	client          *pkgmail.Client
	templateService *template.Service
	from            string
	fromName        string
}

// NewService 创建邮件服务
func NewService(templateService *template.Service) (*Service, error) {
	client, err := pkgmail.NewClient(&pkgmail.ClientConfig{
		Host:     config.GetSMTPHost(),
		Port:     config.GetSMTPPort(),
		Username: config.GetSMTPUsername(),
		Password: config.GetSMTPPassword(),
		UseSSL:   config.GetSMTPPort() == 465,
	})
	if err != nil {
		return nil, fmt.Errorf("创建邮件客户端失败: %w", err)
	}

	return &Service{
		client:          client,
		templateService: templateService,
		from:            config.GetSMTPFrom(),
		fromName:        config.GetSMTPFromName(),
	}, nil
}

// Send 发送邮件
func (s *Service) Send(ctx context.Context, req *SendRequest) error {
	subject, body, err := s.templateService.Render(ctx, req.TemplateID, req.Data)
	if err != nil {
		return fmt.Errorf("渲染模板失败: %w", err)
	}

	if req.Subject != "" {
		subject = req.Subject
	}

	from := s.from
	if s.fromName != "" {
		from = fmt.Sprintf("%s <%s>", s.fromName, s.from)
	}

	msg := pkgmail.NewMessage().
		SetFrom(from).
		AddTo(req.To).
		SetSubject(subject).
		SetHTML(body)

	if err := s.client.Send(ctx, msg); err != nil {
		logger.Errorf("[Mail] 发送邮件失败 - To: %s, Subject: %s, Error: %v", req.To, subject, err)
		return fmt.Errorf("发送邮件失败: %w", err)
	}

	logger.Infof("[Mail] 发送邮件成功 - To: %s, Subject: %s", req.To, subject)
	return nil
}

// SendRaw 发送原始邮件（不使用模板）
func (s *Service) SendRaw(ctx context.Context, to, subject, body string) error {
	from := s.from
	if s.fromName != "" {
		from = fmt.Sprintf("%s <%s>", s.fromName, s.from)
	}

	msg := pkgmail.NewMessage().
		SetFrom(from).
		AddTo(to).
		SetSubject(subject).
		SetHTML(body)

	if err := s.client.Send(ctx, msg); err != nil {
		logger.Errorf("[Mail] 发送原始邮件失败 - To: %s, Subject: %s, Error: %v", to, subject, err)
		return fmt.Errorf("发送邮件失败: %w", err)
	}

	logger.Infof("[Mail] 发送原始邮件成功 - To: %s, Subject: %s", to, subject)
	return nil
}

// Verify 验证 SMTP 连接
func (s *Service) Verify(ctx context.Context) error {
	return s.client.Verify(ctx)
}

// Close 关闭连接
func (s *Service) Close() {
	s.client.Close()
}

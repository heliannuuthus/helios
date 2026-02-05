package templates

import (
	"bytes"
	"fmt"
	"html/template"
	"sync"
	"time"
)

// Scene 邮件场景类型
type Scene string

// 预定义场景
const (
	// OTP 验证码场景
	SceneOTPLogin          Scene = "otp_login"
	SceneOTPRegister       Scene = "otp_register"
	SceneOTPResetPassword  Scene = "otp_reset_password"
	SceneOTPBindEmail      Scene = "otp_bind_email"
	SceneOTPChangeEmail    Scene = "otp_change_email"
	SceneOTPMFA            Scene = "otp_mfa"
	SceneOTPVerifyIdentity Scene = "otp_verify_identity"
	SceneOTPDeleteAccount  Scene = "otp_delete_account"

	// Action 操作场景
	SceneActionVerifyEmail   Scene = "action_verify_email"
	SceneActionResetPassword Scene = "action_reset_password"
	SceneActionInvitation    Scene = "action_invitation"
	SceneActionConfirmChange Scene = "action_confirm_change"
	SceneActionWelcome       Scene = "action_welcome"

	// Notification 通知场景
	SceneNotifyLoginAlert         Scene = "notify_login_alert"
	SceneNotifyPasswordChanged    Scene = "notify_password_changed"
	SceneNotifySecurityAlert      Scene = "notify_security_alert"
	SceneNotifyAccountDeactivated Scene = "notify_account_deactivated"
	SceneNotifyEmailChanged       Scene = "notify_email_changed"
)

// Engine 邮件模板引擎
type Engine struct {
	baseTemplate    *template.Template
	contentTemplate *template.Template
	brandName       string
	logoURL         string
	footerLinks     []FooterLink
	mu              sync.RWMutex
}

// EngineConfig 引擎配置
type EngineConfig struct {
	BrandName   string       // 品牌名称
	LogoURL     string       // Logo URL（可选）
	FooterLinks []FooterLink // 页脚链接（可选）
}

// NewEngine 创建模板引擎
func NewEngine(cfg *EngineConfig) (*Engine, error) {
	e := &Engine{
		brandName:   cfg.BrandName,
		logoURL:     cfg.LogoURL,
		footerLinks: cfg.FooterLinks,
	}

	// 解析基础布局模板
	baseTmpl, err := template.New("base").Parse(BaseLayout)
	if err != nil {
		return nil, fmt.Errorf("parse base template failed: %w", err)
	}
	e.baseTemplate = baseTmpl

	// 解析内容模板
	contentTmpl := template.New("content")
	if _, err := contentTmpl.New("otp").Parse(OTPContent); err != nil {
		return nil, fmt.Errorf("parse otp template failed: %w", err)
	}
	if _, err := contentTmpl.New("action").Parse(ActionContent); err != nil {
		return nil, fmt.Errorf("parse action template failed: %w", err)
	}
	if _, err := contentTmpl.New("notification").Parse(NotificationContent); err != nil {
		return nil, fmt.Errorf("parse notification template failed: %w", err)
	}
	e.contentTemplate = contentTmpl

	return e, nil
}

// SetBrandName 设置品牌名称
func (e *Engine) SetBrandName(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.brandName = name
}

// SetLogoURL 设置 Logo URL
func (e *Engine) SetLogoURL(url string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logoURL = url
}

// SetFooterLinks 设置页脚链接
func (e *Engine) SetFooterLinks(links []FooterLink) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.footerLinks = links
}

// RenderOTP 渲染 OTP 验证码邮件
func (e *Engine) RenderOTP(data *OTPData) (string, string, error) {
	// 渲染内容
	content, err := e.renderContent("otp", data)
	if err != nil {
		return "", "", err
	}

	// 渲染完整邮件
	subject := data.Title
	preHeader := fmt.Sprintf("您的验证码是 %s，%d 分钟内有效", data.Code, data.ExpiresInMinutes)

	html, err := e.renderFull(subject, preHeader, content)
	if err != nil {
		return "", "", err
	}

	return subject, html, nil
}

// RenderOTPScene 根据场景渲染 OTP 邮件
func (e *Engine) RenderOTPScene(scene Scene, code string, greeting string) (string, string, error) {
	var data *OTPData

	switch scene {
	case SceneOTPLogin:
		data = OTPSceneLogin()
	case SceneOTPRegister:
		data = OTPSceneRegister()
	case SceneOTPResetPassword:
		data = OTPSceneResetPassword()
	case SceneOTPBindEmail:
		data = OTPSceneBindEmail()
	case SceneOTPChangeEmail:
		data = OTPSceneChangeEmail()
	case SceneOTPMFA:
		data = OTPSceneMFA()
	case SceneOTPVerifyIdentity:
		data = OTPSceneVerifyIdentity()
	case SceneOTPDeleteAccount:
		data = OTPSceneDeleteAccount()
	default:
		data = OTPSceneLogin() // 默认使用登录场景
	}

	data.Code = code
	if greeting != "" {
		data.Greeting = greeting
	}

	return e.RenderOTP(data)
}

// RenderAction 渲染操作按钮邮件
func (e *Engine) RenderAction(data *ActionData) (string, string, error) {
	content, err := e.renderContent("action", data)
	if err != nil {
		return "", "", err
	}

	subject := data.Title
	preHeader := data.Description

	html, err := e.renderFull(subject, preHeader, content)
	if err != nil {
		return "", "", err
	}

	return subject, html, nil
}

// RenderActionScene 根据场景渲染操作邮件
func (e *Engine) RenderActionScene(scene Scene, actionURL string, greeting string) (string, string, error) {
	var data *ActionData

	switch scene {
	case SceneActionVerifyEmail:
		data = ActionSceneVerifyEmail()
	case SceneActionResetPassword:
		data = ActionSceneResetPassword()
	case SceneActionInvitation:
		data = ActionSceneInvitation()
	case SceneActionConfirmChange:
		data = ActionSceneConfirmChange()
	case SceneActionWelcome:
		data = ActionSceneWelcome()
	default:
		data = ActionSceneVerifyEmail()
	}

	data.ActionURL = actionURL
	if greeting != "" {
		data.Greeting = greeting
	}

	return e.RenderAction(data)
}

// RenderNotification 渲染通知邮件
func (e *Engine) RenderNotification(data *NotificationData) (string, string, error) {
	content, err := e.renderContent("notification", data)
	if err != nil {
		return "", "", err
	}

	subject := data.Title
	preHeader := ""
	if data.InfoBox != nil {
		preHeader = data.InfoBox.Text
	}

	html, err := e.renderFull(subject, preHeader, content)
	if err != nil {
		return "", "", err
	}

	return subject, html, nil
}

// RenderNotificationScene 根据场景渲染通知邮件
func (e *Engine) RenderNotificationScene(scene Scene, details []DetailItem, actionURL string, greeting string) (string, string, error) {
	var data *NotificationData

	switch scene {
	case SceneNotifyLoginAlert:
		data = NotifySceneLoginAlert()
	case SceneNotifyPasswordChanged:
		data = NotifyScenePasswordChanged()
	case SceneNotifySecurityAlert:
		data = NotifySceneSecurityAlert()
	case SceneNotifyAccountDeactivated:
		data = NotifySceneAccountDeactivated()
	case SceneNotifyEmailChanged:
		data = NotifySceneEmailChanged()
	default:
		data = NotifySceneLoginAlert()
	}

	if len(details) > 0 {
		data.Details = details
	}
	if actionURL != "" {
		data.ActionURL = actionURL
	}
	if greeting != "" {
		data.Greeting = greeting
	}

	return e.RenderNotification(data)
}

// renderContent 渲染内容模板
func (e *Engine) renderContent(name string, data any) (string, error) {
	var buf bytes.Buffer
	if err := e.contentTemplate.ExecuteTemplate(&buf, name, data); err != nil {
		return "", fmt.Errorf("execute content template %s failed: %w", name, err)
	}
	return buf.String(), nil
}

// renderFull 渲染完整邮件
func (e *Engine) renderFull(subject, preHeader, content string) (string, error) {
	e.mu.RLock()
	baseData := BaseData{
		Subject:     subject,
		PreHeader:   preHeader,
		BrandName:   e.brandName,
		LogoURL:     e.logoURL,
		Content:     template.HTML(content), // 使用 template.HTML 避免转义
		FooterLinks: e.footerLinks,
		Year:        time.Now().Year(),
	}
	e.mu.RUnlock()

	var buf bytes.Buffer
	if err := e.baseTemplate.Execute(&buf, baseData); err != nil {
		return "", fmt.Errorf("execute base template failed: %w", err)
	}

	return buf.String(), nil
}

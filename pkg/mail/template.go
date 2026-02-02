package mail

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"sync"
)

// TemplateEngine 邮件模板引擎
type TemplateEngine struct {
	client    *Client
	templates map[string]*template.Template
	mu        sync.RWMutex
	funcMap   template.FuncMap
}

// NewTemplateEngine 创建模板引擎
func NewTemplateEngine(client *Client) *TemplateEngine {
	return &TemplateEngine{
		client:    client,
		templates: make(map[string]*template.Template),
		funcMap:   make(template.FuncMap),
	}
}

// AddFunc 添加模板函数
func (e *TemplateEngine) AddFunc(name string, fn any) *TemplateEngine {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.funcMap[name] = fn
	return e
}

// AddFuncMap 添加模板函数集
func (e *TemplateEngine) AddFuncMap(funcMap template.FuncMap) *TemplateEngine {
	e.mu.Lock()
	defer e.mu.Unlock()
	for name, fn := range funcMap {
		e.funcMap[name] = fn
	}
	return e
}

// Register 注册模板
func (e *TemplateEngine) Register(name, content string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	tmpl, err := template.New(name).Funcs(e.funcMap).Parse(content)
	if err != nil {
		return fmt.Errorf("parse template %s failed: %w", name, err)
	}

	e.templates[name] = tmpl
	return nil
}

// RegisterFile 从文件注册模板
func (e *TemplateEngine) RegisterFile(name, filepath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	tmpl, err := template.New(name).Funcs(e.funcMap).ParseFiles(filepath)
	if err != nil {
		return fmt.Errorf("parse template file %s failed: %w", filepath, err)
	}

	e.templates[name] = tmpl
	return nil
}

// Render 渲染模板
func (e *TemplateEngine) Render(name string, data any) (string, error) {
	e.mu.RLock()
	tmpl, ok := e.templates[name]
	e.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("template %s not found", name)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute template %s failed: %w", name, err)
	}

	return buf.String(), nil
}

// SendTemplate 使用模板发送邮件
func (e *TemplateEngine) SendTemplate(ctx context.Context, templateName string, data any, msg *Message) error {
	body, err := e.Render(templateName, data)
	if err != nil {
		return err
	}

	msg.Body = body
	if msg.ContentType == "" {
		msg.ContentType = ContentTypeHTML
	}

	return e.client.Send(ctx, msg)
}

// SendTemplateSimple 使用模板发送简单邮件
func (e *TemplateEngine) SendTemplateSimple(ctx context.Context, templateName string, data any, to, subject string) error {
	msg := NewMessage().
		AddTo(to).
		SetSubject(subject)

	return e.SendTemplate(ctx, templateName, data, msg)
}

// 预定义邮件模板

// OTPTemplate 验证码邮件模板
const OTPTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            background: #f9fafb;
            border-radius: 8px;
            padding: 32px;
        }
        .code {
            font-size: 32px;
            font-weight: bold;
            letter-spacing: 4px;
            color: #1a73e8;
            background: #e8f0fe;
            padding: 16px 24px;
            border-radius: 8px;
            display: inline-block;
            margin: 20px 0;
        }
        .footer {
            margin-top: 24px;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>{{.Title}}</h2>
        <p>您好，</p>
        <p>您的验证码是：</p>
        <div class="code">{{.Code}}</div>
        <p>验证码有效期为 <strong>{{.ExpiresInMinutes}}</strong> 分钟，请尽快使用。</p>
        <p>如果这不是您的操作，请忽略此邮件。</p>
        <div class="footer">
            <p>此邮件由系统自动发送，请勿回复。</p>
            {{if .AppName}}<p>— {{.AppName}}</p>{{end}}
        </div>
    </div>
</body>
</html>`

// OTPTemplateData 验证码模板数据
type OTPTemplateData struct {
	Title            string // 邮件标题，如 "登录验证码"
	Code             string // 验证码
	ExpiresInMinutes int    // 过期时间（分钟）
	AppName          string // 应用名称（可选）
}

// WelcomeTemplate 欢迎邮件模板
const WelcomeTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 12px;
            padding: 40px;
            color: white;
        }
        h1 {
            margin-bottom: 24px;
        }
        .btn {
            display: inline-block;
            background: white;
            color: #667eea;
            padding: 12px 32px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
            margin: 20px 0;
        }
        .footer {
            margin-top: 32px;
            font-size: 14px;
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>欢迎加入 {{.AppName}}！</h1>
        <p>Hi {{.Username}}，</p>
        <p>感谢您注册 {{.AppName}}。我们很高兴能为您服务！</p>
        {{if .ActionURL}}
        <a href="{{.ActionURL}}" class="btn">{{.ActionText}}</a>
        {{end}}
        <div class="footer">
            <p>如有任何问题，请随时联系我们。</p>
            <p>— {{.AppName}} 团队</p>
        </div>
    </div>
</body>
</html>`

// WelcomeTemplateData 欢迎邮件模板数据
type WelcomeTemplateData struct {
	AppName    string // 应用名称
	Username   string // 用户名
	ActionURL  string // 按钮链接（可选）
	ActionText string // 按钮文字（可选）
}

// NotificationTemplate 通知邮件模板
const NotificationTemplate = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .container {
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 24px;
        }
        .header {
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 16px;
            margin-bottom: 16px;
        }
        .content {
            padding: 16px 0;
        }
        .footer {
            border-top: 1px solid #e5e7eb;
            padding-top: 16px;
            margin-top: 16px;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <strong>{{.Title}}</strong>
        </div>
        <div class="content">
            {{.Content}}
        </div>
        <div class="footer">
            {{if .AppName}}<p>— {{.AppName}}</p>{{end}}
            <p>此邮件由系统自动发送。</p>
        </div>
    </div>
</body>
</html>`

// NotificationTemplateData 通知邮件模板数据
type NotificationTemplateData struct {
	Title   string        // 通知标题
	Content template.HTML // 通知内容（支持 HTML）
	AppName string        // 应用名称（可选）
}

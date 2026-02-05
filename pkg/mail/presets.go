package mail

// 常用邮件服务商预设配置

// NewQQExmailClient 创建腾讯企业邮箱客户端
//
// username: 邮箱地址
// password: 授权码（不是登录密码）
func NewQQExmailClient(username, password string, opts ...Option) *Client {
	defaultOpts := []Option{
		WithPort(465),
		WithSSL(),
	}
	return NewClient("smtp.exmail.qq.com", username, password, append(defaultOpts, opts...)...)
}

// NewQQMailClient 创建 QQ 邮箱客户端
//
// username: 邮箱地址
// password: 授权码（不是登录密码）
func NewQQMailClient(username, password string, opts ...Option) *Client {
	defaultOpts := []Option{
		WithPort(465),
		WithSSL(),
	}
	return NewClient("smtp.qq.com", username, password, append(defaultOpts, opts...)...)
}

// New163MailClient 创建网易 163 邮箱客户端
//
// username: 邮箱地址
// password: 授权码
func New163MailClient(username, password string, opts ...Option) *Client {
	defaultOpts := []Option{
		WithPort(465),
		WithSSL(),
	}
	return NewClient("smtp.163.com", username, password, append(defaultOpts, opts...)...)
}

// NewGmailClient 创建 Gmail 客户端
//
// username: 邮箱地址
// password: 应用专用密码（App Password）
func NewGmailClient(username, password string, opts ...Option) *Client {
	defaultOpts := []Option{
		WithPort(587),
		WithSTARTTLS(),
	}
	return NewClient("smtp.gmail.com", username, password, append(defaultOpts, opts...)...)
}

// NewOutlookClient 创建 Outlook/Hotmail 客户端
//
// username: 邮箱地址
// password: 密码或应用密码
func NewOutlookClient(username, password string, opts ...Option) *Client {
	defaultOpts := []Option{
		WithPort(587),
		WithSTARTTLS(),
	}
	return NewClient("smtp.office365.com", username, password, append(defaultOpts, opts...)...)
}

// NewAliyunMailClient 创建阿里云企业邮箱客户端
//
// username: 邮箱地址
// password: 邮箱密码
func NewAliyunMailClient(username, password string, opts ...Option) *Client {
	defaultOpts := []Option{
		WithPort(465),
		WithSSL(),
	}
	return NewClient("smtp.mxhichina.com", username, password, append(defaultOpts, opts...)...)
}

// NewSendGridClient 创建 SendGrid 客户端
//
// apiKey: SendGrid API Key
func NewSendGridClient(apiKey string, opts ...Option) *Client {
	defaultOpts := []Option{
		WithPort(587),
		WithSTARTTLS(),
	}
	return NewClient("smtp.sendgrid.net", "apikey", apiKey, append(defaultOpts, opts...)...)
}

// NewMailgunClient 创建 Mailgun 客户端
//
// domain: Mailgun 域名
// apiKey: Mailgun SMTP 密码
func NewMailgunClient(domain, username, password string, opts ...Option) *Client {
	defaultOpts := []Option{
		WithPort(587),
		WithSTARTTLS(),
	}
	return NewClient("smtp.mailgun.org", username, password, append(defaultOpts, opts...)...)
}

// NewAWSESClient 创建 AWS SES 客户端
//
// region: AWS 区域，如 "us-east-1"
// accessKeyID: SMTP 用户名
// secretAccessKey: SMTP 密码
func NewAWSESClient(region, accessKeyID, secretAccessKey string, opts ...Option) *Client {
	host := "email-smtp." + region + ".amazonaws.com"
	defaultOpts := []Option{
		WithPort(587),
		WithSTARTTLS(),
	}
	return NewClient(host, accessKeyID, secretAccessKey, append(defaultOpts, opts...)...)
}

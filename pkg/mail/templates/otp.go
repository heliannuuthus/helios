package templates

// OTPContent OTP 验证码内容模板
// 极简风格：统一字色、清晰层级、无多余装饰
const OTPContent = `<p style="font-size: 20px; font-weight: 600; color: #202124; margin: 0 0 24px 0;">{{.Title}}</p>

{{if .Greeting}}<p style="font-size: 15px; color: #202124; margin: 0 0 16px 0;">{{.Greeting}}</p>{{end}}

<p style="font-size: 15px; color: #202124; margin: 0 0 32px 0;">{{.Description}}</p>

<p style="font-size: 32px; font-weight: 500; font-family: 'Google Sans', -apple-system, BlinkMacSystemFont, sans-serif; letter-spacing: 6px; color: #202124; margin: 0 0 32px 0;">{{.Code}}</p>

<p style="font-size: 13px; color: #5f6368; margin: 0 0 16px 0;">此验证码将在 {{.ExpiresInMinutes}} 分钟后失效。</p>

<p style="font-size: 13px; color: #5f6368; margin: 0;">如果您没有请求此验证码，请忽略这封邮件。请勿将验证码分享给任何人。</p>`

// OTPData OTP 模板数据
type OTPData struct {
	Title            string // 标题，如 "登录验证码"、"注册验证码"
	Greeting         string // 问候语（可选），如 "您好，张三"
	Description      string // 描述，如 "您正在登录账户，请使用以下验证码完成验证："
	Code             string // 验证码
	ExpiresInMinutes int    // 过期时间（分钟）
}

// OTP 场景预设

// OTPSceneLogin 登录验证码场景
func OTPSceneLogin() *OTPData {
	return &OTPData{
		Title:            "登录验证码",
		Description:      "您正在登录账户，请使用以下验证码完成身份验证：",
		ExpiresInMinutes: 5,
	}
}

// OTPSceneRegister 注册验证码场景
func OTPSceneRegister() *OTPData {
	return &OTPData{
		Title:            "注册验证码",
		Description:      "您正在注册新账户，请使用以下验证码完成邮箱验证：",
		ExpiresInMinutes: 10,
	}
}

// OTPSceneResetPassword 重置密码验证码场景
func OTPSceneResetPassword() *OTPData {
	return &OTPData{
		Title:            "重置密码验证码",
		Description:      "您正在重置账户密码，请使用以下验证码完成验证：",
		ExpiresInMinutes: 10,
	}
}

// OTPSceneBindEmail 绑定邮箱验证码场景
func OTPSceneBindEmail() *OTPData {
	return &OTPData{
		Title:            "绑定邮箱验证码",
		Description:      "您正在绑定新的邮箱地址，请使用以下验证码完成验证：",
		ExpiresInMinutes: 10,
	}
}

// OTPSceneChangeEmail 更换邮箱验证码场景
func OTPSceneChangeEmail() *OTPData {
	return &OTPData{
		Title:            "更换邮箱验证码",
		Description:      "您正在更换账户的邮箱地址，请使用以下验证码确认本次操作：",
		ExpiresInMinutes: 10,
	}
}

// OTPSceneMFA MFA 二次验证场景
func OTPSceneMFA() *OTPData {
	return &OTPData{
		Title:            "安全验证码",
		Description:      "为了保护您的账户安全，请使用以下验证码完成二次验证：",
		ExpiresInMinutes: 5,
	}
}

// OTPSceneVerifyIdentity 身份验证场景
func OTPSceneVerifyIdentity() *OTPData {
	return &OTPData{
		Title:            "身份验证码",
		Description:      "您正在进行敏感操作，请使用以下验证码确认您的身份：",
		ExpiresInMinutes: 5,
	}
}

// OTPSceneDeleteAccount 删除账户验证码场景
func OTPSceneDeleteAccount() *OTPData {
	return &OTPData{
		Title:            "账户注销验证码",
		Description:      "您正在申请注销账户，此操作不可逆。请使用以下验证码确认操作：",
		ExpiresInMinutes: 5,
	}
}

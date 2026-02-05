package templates

// OTPContent OTP 验证码内容模板
// 配色方案：主色 #2563eb (蓝色)，背景渐变更柔和
const OTPContent = `<h2 style="font-size: 24px; font-weight: 700; color: #111827; margin: 0 0 12px 0; letter-spacing: -0.3px;">{{.Title}}</h2>

{{if .Greeting}}
<p style="font-size: 16px; color: #374151; margin: 0 0 24px 0;">{{.Greeting}}</p>
{{end}}

<p style="font-size: 16px; color: #4b5563; margin: 0 0 32px 0; line-height: 1.7;">{{.Description}}</p>

<div style="text-align: center; margin: 40px 0;">
    <div style="display: inline-block; background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); border-radius: 16px; padding: 28px 56px; box-shadow: 0 10px 25px -5px rgba(37, 99, 235, 0.4);">
        <p style="font-size: 40px; font-weight: 800; font-family: 'SF Mono', Monaco, 'Cascadia Code', Consolas, 'Courier New', monospace; letter-spacing: 12px; color: #ffffff; margin: 0; text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">{{.Code}}</p>
    </div>
</div>

<div style="text-align: center; margin: 32px 0;">
    <span style="display: inline-block; background-color: #fef3c7; border-radius: 8px; padding: 12px 24px; font-size: 14px; color: #92400e; font-weight: 500;">
        ⏱ 验证码将在 <strong style="color: #78350f;">{{.ExpiresInMinutes}} 分钟</strong>后失效
    </span>
</div>

<div style="background-color: #f3f4f6; border-radius: 12px; padding: 20px 24px; margin-top: 40px;">
    <p style="font-size: 14px; font-weight: 600; color: #374151; margin: 0 0 8px 0;">🔒 安全提示</p>
    <p style="font-size: 14px; color: #6b7280; margin: 0; line-height: 1.7;">
        请勿将此验证码分享给任何人，包括客服人员。如果这不是您的操作，请忽略此邮件。
    </p>
</div>`

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

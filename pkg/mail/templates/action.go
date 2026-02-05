package templates

// ActionContent 操作按钮内容模板
// 配色方案：主色 #2563eb (蓝色)
const ActionContent = `<h2 style="font-size: 24px; font-weight: 700; color: #111827; margin: 0 0 12px 0; letter-spacing: -0.3px;">{{.Title}}</h2>

{{if .Greeting}}
<p style="font-size: 16px; color: #374151; margin: 0 0 24px 0;">{{.Greeting}}</p>
{{end}}

<p style="font-size: 16px; color: #4b5563; margin: 0 0 32px 0; line-height: 1.7;">{{.Description}}</p>

<div style="text-align: center; margin: 40px 0;">
    <a href="{{.ActionURL}}" target="_blank" style="display: inline-block; background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); color: #ffffff; text-decoration: none; font-size: 16px; font-weight: 600; padding: 16px 48px; border-radius: 10px; box-shadow: 0 10px 25px -5px rgba(37, 99, 235, 0.4); letter-spacing: 0.3px;">
        {{.ActionText}}
    </a>
</div>

{{if gt .ExpiresInMinutes 0}}
<div style="text-align: center; margin: 24px 0 32px 0;">
    <span style="font-size: 14px; color: #6b7280;">
        此链接将在 {{.ExpiresInMinutes}} 分钟后失效
    </span>
</div>
{{end}}

<div style="background-color: #f3f4f6; border-radius: 12px; padding: 20px 24px; margin-top: 40px;">
    <p style="font-size: 14px; font-weight: 600; color: #374151; margin: 0 0 12px 0;">按钮无法点击？</p>
    <p style="font-size: 14px; color: #6b7280; margin: 0 0 12px 0; line-height: 1.6;">请复制以下链接到浏览器地址栏打开：</p>
    <p style="font-size: 13px; color: #2563eb; word-break: break-all; line-height: 1.6; margin: 0; font-family: 'SF Mono', Monaco, Consolas, monospace;">{{.ActionURL}}</p>
</div>

{{if .Warning}}
<div style="margin-top: 24px; padding: 16px 20px; background-color: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 0 8px 8px 0;">
    <p style="font-size: 14px; color: #92400e; margin: 0; line-height: 1.6;">{{.Warning}}</p>
</div>
{{end}}`

// ActionData 操作按钮模板数据
type ActionData struct {
	Title            string // 标题
	Greeting         string // 问候语（可选）
	Description      string // 描述
	ActionURL        string // 操作链接
	ActionText       string // 按钮文字
	ExpiresInMinutes int    // 过期时间（分钟），0 表示不显示
	Warning          string // 警告信息（可选）
}

// 操作场景预设

// ActionSceneVerifyEmail 验证邮箱场景
func ActionSceneVerifyEmail() *ActionData {
	return &ActionData{
		Title:            "验证您的邮箱",
		Description:      "感谢您的注册！请点击下方按钮验证您的邮箱地址，以完成账户激活：",
		ActionText:       "验证邮箱",
		ExpiresInMinutes: 60,
	}
}

// ActionSceneResetPassword 重置密码场景
func ActionSceneResetPassword() *ActionData {
	return &ActionData{
		Title:            "重置您的密码",
		Description:      "我们收到了重置您账户密码的请求。请点击下方按钮设置新密码：",
		ActionText:       "重置密码",
		ExpiresInMinutes: 30,
		Warning:          "如果这不是您的操作，请忽略此邮件。您的密码不会被更改。",
	}
}

// ActionSceneInvitation 邀请加入场景
func ActionSceneInvitation() *ActionData {
	return &ActionData{
		Title:            "您收到了一份邀请",
		ActionText:       "接受邀请",
		ExpiresInMinutes: 0,
	}
}

// ActionSceneConfirmChange 确认更改场景
func ActionSceneConfirmChange() *ActionData {
	return &ActionData{
		Title:            "确认账户更改",
		Description:      "您正在更改账户信息，请点击下方按钮确认此操作：",
		ActionText:       "确认更改",
		ExpiresInMinutes: 30,
		Warning:          "如果这不是您的操作，请立即联系客服并更改您的密码。",
	}
}

// ActionSceneWelcome 欢迎场景
func ActionSceneWelcome() *ActionData {
	return &ActionData{
		Title:            "欢迎加入！",
		Description:      "感谢您的注册！点击下方按钮开始探索：",
		ActionText:       "开始使用",
		ExpiresInMinutes: 0,
	}
}

package templates

// ActionContent 操作按钮内容模板
// 极简风格：单一主色按钮、统一字色
const ActionContent = `<p style="font-size: 20px; font-weight: 600; color: #202124; margin: 0 0 24px 0;">{{.Title}}</p>

{{if .Greeting}}<p style="font-size: 15px; color: #202124; margin: 0 0 16px 0;">{{.Greeting}}</p>{{end}}

<p style="font-size: 15px; color: #202124; margin: 0 0 24px 0;">{{.Description}}</p>

<p style="margin: 0 0 24px 0;">
    <a href="{{.ActionURL}}" target="_blank" style="display: inline-block; background-color: #1a73e8; color: #ffffff; text-decoration: none; font-size: 14px; font-weight: 500; padding: 12px 24px; border-radius: 4px;">{{.ActionText}}</a>
</p>

{{if gt .ExpiresInMinutes 0}}<p style="font-size: 13px; color: #5f6368; margin: 0 0 16px 0;">此链接将在 {{.ExpiresInMinutes}} 分钟后失效。</p>{{end}}

<p style="font-size: 13px; color: #5f6368; margin: 0 0 16px 0;">如果按钮无法点击，请复制以下链接到浏览器：<br><span style="word-break: break-all;">{{.ActionURL}}</span></p>

{{if .Warning}}<p style="font-size: 13px; color: #5f6368; margin: 0;">{{.Warning}}</p>{{end}}`

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

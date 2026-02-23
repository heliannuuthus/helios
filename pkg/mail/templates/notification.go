package templates

// NotificationContent 通知内容模板
// 极简风格：统一字色、简洁表格、无彩色装饰
const NotificationContent = `<p style="font-size: 20px; font-weight: 600; color: #202124; margin: 0 0 24px 0;">{{.Title}}</p>

{{if .Greeting}}<p style="font-size: 15px; color: #202124; margin: 0 0 16px 0;">{{.Greeting}}</p>{{end}}

<div style="font-size: 15px; color: #202124; line-height: 1.7; margin-bottom: 24px;">{{.Content}}</div>

{{if .InfoBox}}<p style="font-size: 13px; color: #5f6368; margin: 0 0 24px 0;">{{if .InfoBox.Title}}<strong>{{.InfoBox.Title}}</strong> {{end}}{{.InfoBox.Text}}</p>{{end}}

{{if .Details}}
<table style="width: 100%; border-collapse: collapse; margin: 0 0 24px 0;">
    {{range .Details}}
    <tr>
        <td style="padding: 6px 0; font-size: 13px; color: #5f6368; width: 80px; vertical-align: top;">{{.Label}}</td>
        <td style="padding: 6px 0; font-size: 13px; color: #202124; vertical-align: top;">{{.Value}}</td>
    </tr>
    {{end}}
</table>
{{end}}

{{if .ActionURL}}
<p style="margin: 0;">
    <a href="{{.ActionURL}}" target="_blank" style="display: inline-block; background-color: #1a73e8; color: #ffffff; text-decoration: none; font-size: 14px; font-weight: 500; padding: 12px 24px; border-radius: 4px;">{{.ActionText}}</a>
</p>
{{end}}`

// InfoBox 信息框
type InfoBox struct {
	Type  string // info, warning, error, success
	Title string // 标题（可选）
	Text  string // 内容
}

// DetailItem 详情项
type DetailItem struct {
	Label string // 标签
	Value string // 值
}

// NotificationData 通知模板数据
type NotificationData struct {
	Title        string       // 标题
	Greeting     string       // 问候语（可选）
	Content      string       // 主要内容（HTML）
	InfoBox      *InfoBox     // 信息框（可选）
	DetailsTitle string       // 详情标题（可选）
	Details      []DetailItem // 详情列表（可选）
	ActionURL    string       // 操作链接（可选）
	ActionText   string       // 按钮文字（可选）
}

// 通知场景预设

// NotifySceneLoginAlert 登录提醒场景
func NotifySceneLoginAlert() *NotificationData {
	return &NotificationData{
		Title:        "新设备登录提醒",
		Content:      "<p style=\"margin: 0;\">您的账户刚刚在新设备上登录。如果这是您本人的操作，请忽略此邮件。</p>",
		DetailsTitle: "登录详情",
		InfoBox: &InfoBox{
			Type: "warning",
			Text: "如果这不是您的操作，请立即修改密码并检查账户安全设置。",
		},
		ActionText: "检查账户安全",
	}
}

// NotifyScenePasswordChanged 密码已更改场景
func NotifyScenePasswordChanged() *NotificationData {
	return &NotificationData{
		Title:   "密码已更改",
		Content: "<p style=\"margin: 0 0 12px 0;\">您的账户密码已成功更改。</p><p style=\"margin: 0; color: #6b7280;\">如果这不是您的操作，请立即联系客服。</p>",
		InfoBox: &InfoBox{
			Type:  "success",
			Title: "✓ 操作成功",
			Text:  "您的密码已更新。下次登录时请使用新密码。",
		},
	}
}

// NotifySceneSecurityAlert 安全警告场景
func NotifySceneSecurityAlert() *NotificationData {
	return &NotificationData{
		Title:   "账户安全警告",
		Content: "<p style=\"margin: 0;\">我们检测到您的账户存在异常活动，请确认以下操作是否由您本人发起。</p>",
		InfoBox: &InfoBox{
			Type:  "error",
			Title: "⚠ 安全警告",
			Text:  "如果您不认识以下活动，请立即更改密码并启用双因素认证。",
		},
		ActionText: "保护我的账户",
	}
}

// NotifySceneAccountDeactivated 账户已停用场景
func NotifySceneAccountDeactivated() *NotificationData {
	return &NotificationData{
		Title:   "账户已停用",
		Content: "<p style=\"margin: 0;\">您的账户已被停用。如有疑问，请联系客服了解详情。</p>",
		InfoBox: &InfoBox{
			Type: "warning",
			Text: "在账户停用期间，您将无法登录或使用相关服务。",
		},
	}
}

// NotifySceneEmailChanged 邮箱已更改场景
func NotifySceneEmailChanged() *NotificationData {
	return &NotificationData{
		Title:   "邮箱地址已更改",
		Content: "<p style=\"margin: 0;\">您的账户邮箱地址已更改。此邮件发送至您的旧邮箱地址作为安全通知。</p>",
		InfoBox: &InfoBox{
			Type:  "warning",
			Title: "重要提示",
			Text:  "如果这不是您的操作，您的账户可能已被入侵。请立即联系客服。",
		},
		ActionText: "联系客服",
	}
}

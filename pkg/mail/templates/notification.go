package templates

// NotificationContent 通知内容模板
// 配色方案：使用语义化颜色（蓝色信息、黄色警告、红色错误、绿色成功）
const NotificationContent = `<h2 style="font-size: 24px; font-weight: 700; color: #111827; margin: 0 0 12px 0; letter-spacing: -0.3px;">{{.Title}}</h2>

{{if .Greeting}}
<p style="font-size: 16px; color: #374151; margin: 0 0 24px 0;">{{.Greeting}}</p>
{{end}}

<div style="font-size: 16px; color: #4b5563; line-height: 1.7;">
    {{.Content}}
</div>

{{if .InfoBox}}
<div style="background-color: {{if eq .InfoBox.Type "warning"}}#fef3c7{{else if eq .InfoBox.Type "error"}}#fee2e2{{else if eq .InfoBox.Type "success"}}#d1fae5{{else}}#dbeafe{{end}}; border-left: 4px solid {{if eq .InfoBox.Type "warning"}}#f59e0b{{else if eq .InfoBox.Type "error"}}#ef4444{{else if eq .InfoBox.Type "success"}}#10b981{{else}}#2563eb{{end}}; border-radius: 0 12px 12px 0; padding: 20px 24px; margin: 28px 0;">
    {{if .InfoBox.Title}}
    <p style="font-size: 15px; font-weight: 600; color: {{if eq .InfoBox.Type "warning"}}#92400e{{else if eq .InfoBox.Type "error"}}#991b1b{{else if eq .InfoBox.Type "success"}}#065f46{{else}}#1e40af{{end}}; margin: 0 0 8px 0;">{{.InfoBox.Title}}</p>
    {{end}}
    <p style="font-size: 14px; color: {{if eq .InfoBox.Type "warning"}}#a16207{{else if eq .InfoBox.Type "error"}}#b91c1c{{else if eq .InfoBox.Type "success"}}#047857{{else}}#1d4ed8{{end}}; margin: 0; line-height: 1.6;">{{.InfoBox.Text}}</p>
</div>
{{end}}

{{if .Details}}
<div style="background-color: #f9fafb; border-radius: 12px; padding: 24px; margin: 28px 0; border: 1px solid #e5e7eb;">
    {{if .DetailsTitle}}
    <p style="font-size: 15px; font-weight: 600; color: #111827; margin: 0 0 16px 0;">{{.DetailsTitle}}</p>
    {{end}}
    <table style="width: 100%; border-collapse: collapse;">
        {{range .Details}}
        <tr>
            <td style="padding: 12px 0; font-size: 14px; color: #6b7280; width: 120px; vertical-align: top; border-bottom: 1px solid #e5e7eb;">{{.Label}}</td>
            <td style="padding: 12px 0; font-size: 14px; color: #111827; vertical-align: top; border-bottom: 1px solid #e5e7eb; font-weight: 500;">{{.Value}}</td>
        </tr>
        {{end}}
    </table>
</div>
{{end}}

{{if .ActionURL}}
<div style="margin-top: 36px; text-align: center;">
    <a href="{{.ActionURL}}" target="_blank" style="display: inline-block; background-color: #111827; color: #ffffff; text-decoration: none; font-size: 15px; font-weight: 600; padding: 14px 36px; border-radius: 10px; box-shadow: 0 4px 14px -3px rgba(0, 0, 0, 0.3);">
        {{.ActionText}}
    </a>
</div>
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

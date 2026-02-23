package templates

// BaseLayout 基础布局模板
// 极简风格，参考 Google/X 设计语言
// 特点：大量留白、统一字色、无多余装饰
const BaseLayout = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="x-apple-disable-message-reformatting">
    <title>{{.Subject}}</title>
    <!--[if mso]>
    <style type="text/css">
        table {border-collapse:collapse;border-spacing:0;margin:0;}
        div, td {padding:0;}
        div {margin:0 !important;}
    </style>
    <noscript>
        <xml>
            <o:OfficeDocumentSettings>
                <o:PixelsPerInch>96</o:PixelsPerInch>
            </o:OfficeDocumentSettings>
        </xml>
    </noscript>
    <![endif]-->
</head>
<body style="margin: 0; padding: 0; width: 100%; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'PingFang SC', 'Microsoft YaHei', sans-serif; font-size: 15px; line-height: 1.7; color: #202124; background-color: #ffffff; -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%;">
    <div style="display: none; max-height: 0; overflow: hidden; mso-hide: all;">{{.PreHeader}}</div>
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #ffffff;">
        <tr>
            <td style="padding: 40px 20px;">
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="480" style="max-width: 480px; margin: 0 auto;">
                    <tr>
                        <td style="padding-bottom: 32px;">
                            {{if .LogoURL}}
                            <img src="{{.LogoURL}}" alt="{{.BrandName}}" style="height: 24px;">
                            {{else}}
                            <span style="font-size: 16px; font-weight: 600; color: #202124;">{{.BrandName}}</span>
                            {{end}}
                        </td>
                    </tr>
                    <tr>
                        <td>{{.Content}}</td>
                    </tr>
                    <tr>
                        <td style="padding-top: 40px;">
                            <p style="font-size: 12px; color: #5f6368; margin: 0; line-height: 1.8;">
                                此邮件由 <a href="mailto:aegis@heliannuuthus.com" style="color: #5f6368;">aegis@heliannuuthus.com</a> 发送，请勿直接回复。{{if .FooterLinks}}<br>{{range .FooterLinks}}<a href="{{.URL}}" style="color: #5f6368; text-decoration: underline;">{{.Text}}</a>&nbsp;&nbsp;{{end}}{{end}}
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`

// FooterLink 页脚链接
type FooterLink struct {
	Text string
	URL  string
}

// BaseData 基础模板数据
type BaseData struct {
	Subject     string       // 邮件主题
	PreHeader   string       // 预览文本
	BrandName   string       // 品牌名称
	LogoURL     string       // Logo URL（可选）
	Content     interface{}  // 主体内容（使用 template.HTML 避免转义）
	FooterLinks []FooterLink // 页脚链接（可选）
	Year        int          // 年份
}

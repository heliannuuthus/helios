package templates

// BaseLayout 基础布局模板
// 使用内联样式，兼容所有邮件客户端（Gmail、Outlook、QQ邮箱等）
// 配色方案：深灰主色 + 蓝色强调色，专业简洁
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
<body style="margin: 0; padding: 0; width: 100%; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'PingFang SC', 'Microsoft YaHei', sans-serif; font-size: 16px; line-height: 1.6; color: #374151; background-color: #f3f4f6; -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%;">
    <!-- Preheader Text -->
    <div style="display: none; max-height: 0; overflow: hidden; mso-hide: all;">
        {{.PreHeader}}
    </div>

    <!-- Email Wrapper -->
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color: #f3f4f6;">
        <tr>
            <td style="padding: 48px 24px;">
                <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); overflow: hidden;">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 32px 40px; text-align: center; background-color: #ffffff; border-bottom: 1px solid #e5e7eb;">
                            {{if .LogoURL}}
                            <img src="{{.LogoURL}}" alt="{{.BrandName}}" style="max-height: 48px; max-width: 180px;">
                            {{else}}
                            <h1 style="font-size: 28px; font-weight: 700; color: #111827; margin: 0; letter-spacing: -0.5px;">{{.BrandName}}</h1>
                            {{end}}
                        </td>
                    </tr>

                    <!-- Content -->
                    <tr>
                        <td style="padding: 48px 40px;">
                            {{.Content}}
                        </td>
                    </tr>

                    <!-- Footer -->
                    <tr>
                        <td style="padding: 32px 40px; background-color: #f9fafb; border-top: 1px solid #e5e7eb; text-align: center;">
                            <p style="font-size: 14px; color: #6b7280; margin: 0 0 8px 0; line-height: 1.6;">
                                此邮件由系统自动发送，请勿直接回复
                            </p>
                            <p style="font-size: 14px; color: #9ca3af; margin: 0; line-height: 1.6;">
                                如有疑问，请联系客服支持
                            </p>
                            {{if .FooterLinks}}
                            <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                                {{range .FooterLinks}}
                                <a href="{{.URL}}" style="color: #6b7280; text-decoration: none; margin: 0 16px; font-size: 13px;">{{.Text}}</a>
                                {{end}}
                            </div>
                            {{end}}
                            <p style="font-size: 13px; color: #9ca3af; margin: 24px 0 0 0;">
                                © {{.Year}} {{.BrandName}}
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

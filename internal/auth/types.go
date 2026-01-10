package auth

// Identity 用户身份信息（JWE 内层加密内容）
type Identity struct {
	OpenID   string `json:"sub"`
	Nickname string `json:"nickname,omitempty"`
	Avatar   string `json:"picture,omitempty"`
}

// GetOpenID 返回系统生成的 openid
func (u *Identity) GetOpenID() string {
	return u.OpenID
}

// TokenPair token 对
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// JWK 密钥结构
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x,omitempty"`
	D   string `json:"d,omitempty"`
	K   string `json:"k,omitempty"`
}

// WxCode2SessionResponse 微信 code2session 响应
type WxCode2SessionResponse struct {
	OpenID     string `json:"openid"`
	SessionKey string `json:"session_key"`
	UnionID    string `json:"unionid,omitempty"`
	ErrCode    int    `json:"errcode,omitempty"`
	ErrMsg     string `json:"errmsg,omitempty"`
}

// IdP 常量
const (
	IDPWechatMP      = "wechat:mp"      // 微信小程序
	IDPWechatUnionID = "wechat:unionid" // 微信 UnionID
	IDPWechatOA      = "wechat:oa"      // 微信公众号
	IDPDouyinMP      = "douyin:mp"      // 抖音小程序
	IDPDouyinUnionID = "douyin:unionid" // 抖音 UnionID
	IDPAlipayMP      = "alipay:mp"      // 支付宝小程序
	IDPAppleSignIn   = "apple:signin"   // Apple 登录
)

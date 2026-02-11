# SFA（Single-Factor Authentication）设计文档

> 更新日期：2026-02-11

---

## 1. 概述

SFA 是 Helios 认证系统中的基础验证单元，用于完成一次单因素身份验证。原名 Challenge，重新定义为 SFA 以准确表达其语义：**每次 SFA 只验证一个认证因子**。

### 核心定位

- **SFA 是验证能力**，不是业务逻辑
- **SFA 是 MFA 的组成部分**——MFA = 主认证（SFA）+ 追加验证（SFA），两个不同类别的因子组合
- **SFA 是 Delegate 登录的基础**——Delegate 路径 = 独立完成一次 SFA → 签发 SFA Token → 作为 Login 的 proof

### 与 Challenge 的关系

SFA 取代原有 Challenge 的概念。Challenge 这个名字描述的是"挑战-响应"的交互模式，但实际上它的本质就是单因素认证。重命名为 SFA 后：

| 原名 | 新名 | 含义 |
|------|------|------|
| Challenge | SFA | 一次单因素认证 |
| ChallengeToken | SFA Token | 单因素认证通过后的凭证 |
| ChallengeType | Type | 业务场景（由业务 Service 定义） |
| — | Channel Type | 验证方式（由系统定义） |
| — | Channel | 验证目标（由前端/用户提供） |

---

## 2. 三层模型

SFA 请求由三个维度描述：

### 2.1 Type（业务场景）

**由业务 Service 定义**，描述"为什么要做这个验证"。

| Type | 含义 | 用途 |
|------|------|------|
| login | 登录验证 | delegate 登录场景 |
| forget_password | 忘记密码 | 密码重置前的身份确认 |
| bind_phone | 绑定手机号 | 个人中心绑定操作 |
| bind_email | 绑定邮箱 | 个人中心绑定操作 |
| ... | 业务自定义 | 按需扩展 |

Type 的作用：

- **限流策略**：`forget_password` 每小时最多 5 次，`login` 每分钟最多 3 次
- **消息模板**：`forget_password` 发"重置密码验证码"，`login` 发"登录验证码"
- **审计日志**：记录这次验证的业务目的
- **策略控制**：某些 channel_type 只允许在特定 type 下使用

**注意：Type 只适用于验证类 SFA（见 2.2），交换类 SFA 不需要 Type。**

### 2.2 Channel Type（验证方式）

**由系统定义**，描述"通过什么方式验证"。按交互模式分为两大类：

#### 验证类（业务可定义 Type）

用户需要主动提交 proof 完成验证，支持 Type 场景配置。

| Channel Type | 交互模式 | 因子类别 | Create 做什么 | Verify 做什么 |
|-------------|---------|---------|--------------|--------------|
| email_otp | 发送-验证 | Possession | 发邮件验证码 | 比对验证码 |
| sms_otp | 发送-验证 | Possession | 发短信验证码 | 比对验证码 |
| totp | 输入-验证 | Possession | 无（等用户输入） | 比对动态码 |
| webauthn | 挑战-签名 | Inherence + Possession | 生成 challenge options | 验签 |
| captcha | 即时验证 | 非认证因子 | 无 | 调第三方 API |

#### 交换类（系统固定能力，不需要 Type）

平台侧的固定能力，用 code 换取用户信息，一步完成，无需 Verify 阶段。

| Channel Type | 平台 | 换取什么 | Create 做什么 |
|-------------|------|---------|--------------|
| wechat-mp | 微信小程序 | 手机号 | code → 微信 API → 手机号 → 签发 SFA Token |
| alipay-mp | 支付宝小程序 | 手机号 | code → 支付宝 API → 手机号 → 签发 SFA Token |

交换类不需要 Type 的原因：
- 交换是一次性的、即时完成的，无"发码 → 等待 → 输码"过程
- 没有消息模板可选（不是系统发出的）
- 触发由前端用户授权决定，不受业务编排控制

### 2.3 Channel（验证目标）

**由前端/用户提供**，是验证的具体操作数。

| Channel Type | Channel 含义 | 示例 |
|-------------|-------------|------|
| email_otp | 目标邮箱 | `a@b.com` |
| sms_otp | 目标手机号 | `+8613800138000` |
| totp | 用户标识 | `user_123` |
| webauthn | 用户标识（可空） | `user_123` 或空（discoverable） |
| captcha | 空或 site_key | — |
| wechat-mp | 微信 code | `<wx_code>` |
| alipay-mp | 支付宝 code | `<alipay_code>` |

---

## 3. 数据结构

### 3.1 CreateRequest

```go
type CreateRequest struct {
    Type        string `json:"type,omitempty"`         // 业务场景（验证类必填，交换类忽略）
    ChannelType string `json:"channel_type"`           // 验证方式
    Channel     string `json:"channel"`                // 验证目标
}
```

### 3.2 CreateResponse

```go
type CreateResponse struct {
    SFAID     string                 `json:"sfa_id"`               // SFA 会话 ID
    Type      string                 `json:"type,omitempty"`       // 业务场景
    ExpiresIn int                    `json:"expires_in,omitempty"` // 过期秒数
    Data      map[string]any         `json:"data,omitempty"`       // 附加数据（masked_email / site_key / webauthn options）
    Required  *ConnectionConfig      `json:"required,omitempty"`   // 前置条件（captcha）
    Token     string                 `json:"token,omitempty"`      // 交换类直接返回 SFA Token
}
```

### 3.3 VerifyRequest

```go
type VerifyRequest struct {
    ChannelType string `json:"channel_type"` // 本次提交的验证方式
    Proof       any    `json:"proof"`        // 验证证明
}
```

### 3.4 VerifyResponse

```go
type VerifyResponse struct {
    Verified bool           `json:"verified"`
    Token    string         `json:"token,omitempty"` // SFA Token（验证通过后签发）
    Data     map[string]any `json:"data,omitempty"`  // 附加数据
}
```

---

## 4. 交互流程

### 4.1 验证类：Email OTP（有 captcha 前置）

```
前端                                          后端
 │                                             │
 │  POST /auth/sfa                             │
 │  { type: "login",                           │
 │    channel_type: "email_otp",               │
 │    channel: "a@b.com" }                     │
 │ ──────────────────────────────────────────> │
 │                                             │  RequiresCaptcha = true
 │                                             │  创建 SFA 会话，标记 pending_captcha
 │                                             │
 │  { sfa_id: "xxx",                           │
 │    required: {                              │
 │      connection: "captcha",                 │
 │      strategy: ["turnstile"],               │
 │      identifier: "0x4AAA..." }}             │
 │ <────────────────────────────────────────── │
 │                                             │
 │  PUT /auth/sfa?sfa_id=xxx                   │
 │  { channel_type: "captcha",                 │
 │    proof: "turnstile_token" }               │
 │ ──────────────────────────────────────────> │
 │                                             │  验证 captcha ✓ → 发邮件验证码
 │                                             │
 │  { sfa_id: "xxx",                           │
 │    data: { next: "email_otp" }}             │
 │ <────────────────────────────────────────── │
 │                                             │
 │  PUT /auth/sfa?sfa_id=xxx                   │
 │  { channel_type: "email_otp",               │
 │    proof: "382910" }                        │
 │ ──────────────────────────────────────────> │
 │                                             │  验证 ✓ → 签发 SFA Token
 │                                             │
 │  { verified: true,                          │
 │    token: "v4.public.xxx" }                 │
 │ <────────────────────────────────────────── │
```

### 4.2 验证类：TOTP（无前置）

```
前端                                          后端
 │                                             │
 │  POST /auth/sfa                             │
 │  { type: "login",                           │
 │    channel_type: "totp",                    │
 │    channel: "user_123" }                    │
 │ ──────────────────────────────────────────> │
 │                                             │
 │  { sfa_id: "yyy",                           │
 │    expires_in: 300 }                        │
 │ <────────────────────────────────────────── │
 │                                             │
 │  PUT /auth/sfa?sfa_id=yyy                   │
 │  { channel_type: "totp",                    │
 │    proof: "123456" }                        │
 │ ──────────────────────────────────────────> │
 │                                             │
 │  { verified: true,                          │
 │    token: "v4.public.xxx" }                 │
 │ <────────────────────────────────────────── │
```

### 4.3 交换类：微信小程序换手机号

```
前端                                          后端
 │                                             │
 │  POST /auth/sfa                             │
 │  { channel_type: "wechat-mp",               │
 │    channel: "<wx_phone_code>" }             │
 │ ──────────────────────────────────────────> │
 │                                             │  code → 微信 API → 手机号
 │                                             │  签发 SFA Token
 │                                             │
 │  { sfa_id: "zzz",                           │
 │    token: "v4.public.xxx" }                 │
 │ <────────────────────────────────────────── │
```

交换类一步完成，Create 即返回 Token，无需 Verify。

---

## 5. SFA Token 与 Delegate 登录

SFA 验证通过后签发 SFA Token（PASETO v4），可作为 Login 接口的 proof 使用。

### 5.1 Delegate 登录流程

```
1. 前端发起 SFA（如 email_otp）
2. 完成验证，拿到 SFA Token
3. POST /auth/login {
     connection: "user",
     proof: "<sfa_token>"
   }
4. 后端校验：
   - SFA Token 有效
   - SFA Token 的 channel_type 在 user.delegate 列表中
   - 登录成功
```

### 5.2 SFA Token 内容

```
claims:
  sub:          验证的 channel（邮箱/手机号/user_id）
  channel_type: 使用的验证方式
  type:         业务场景（验证类有值，交换类无值）
  iss:          签发者
  exp:          过期时间（短期）
  iat:          签发时间
```

---

## 6. 认证因子分类

| 因子类别 | 含义 | 对应的 Channel Type |
|---------|------|-------------------|
| Knowledge（你知道的） | 记忆中的秘密 | password（在 IDP strategy 中，不走 SFA） |
| Possession（你拥有的） | 实体或虚拟设备 | email_otp, sms_otp, totp, wechat-mp, alipay-mp |
| Inherence（你本身的） | 生物特征 | webauthn（含设备持有 + 生物特征） |

- **单独使用任何一个 channel_type = SFA（单因素认证）**
- **主认证（Knowledge）+ 追加 SFA（Possession/Inherence）= MFA（多因素认证）**
- **SFA 用于 delegate 登录 = 单因素替代路径**
- **SFA 用于 MFA 加固 = 多因素的第二因子**

验证能力本身不区分是 SFA 场景还是 MFA 场景，由编排层决定。

---

## 7. 设计决策

### 7.1 为什么 Type 只适用于验证类

交换类（wechat-mp、alipay-mp）是平台侧的固定能力，一次性即时完成。没有限流模板、消息模板的需求，Type 字段对它没有意义。

### 7.2 为什么 Channel Type 不区分 SFA/MFA

同一个 `totp` 验证，不管是用来做 delegate 登录还是做 MFA 加固，验证动作完全一样。区分场景是编排层的事，不是 Provider 的事。

### 7.3 为什么不用 email/sms 等散装字段

三层模型（type + channel_type + channel）统一了请求结构。不需要为每种验证方式单独加字段，新增 channel_type 只需注册 Provider，请求结构不变。

### 7.4 为什么保留 captcha 前置机制

captcha 不是认证因子，而是防自动化攻击的手段。SFA 创建时如果 channel_type 需要 captcha 前置，标记 pending_captcha，等 captcha 通过后再触发副作用（发码）。这个机制与原 Challenge 设计一致。

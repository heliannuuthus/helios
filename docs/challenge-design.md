# Challenge 服务设计文档

> 更新日期：2026-02-10

---

## 1. 概述

Challenge 是独立于 AuthFlow 的验证流程，用于完成需要异步交互的身份验证（如邮件验证码、TOTP、人机验证等）。Challenge 验证通过后签发短期 ChallengeToken，可作为 Login 接口的 proof 使用。

### 核心设计原则

- **单一 Challenge ID 贯穿整个验证流程**：创建后返回 challenge_id，后续所有操作围绕该 ID
- **前端显式声明验证类型**：每次提交 proof 时通过 connection 字段明确"我在验什么"
- **依赖 Registry 而非自持 Provider**：challenge.Service 通过 authenticator.Registry 按需获取验证能力，不重复持有
- **无状态分发**：所有验证能力通过 Registry.Get + 类型断言获取，Service 只做编排

---

## 2. 架构

```
challenge.Service
    |
    |-- registry (*authenticator.Registry)    // 按需获取验证能力
    |   |-- Get("captcha") → *VChanAuthenticator → .Verifier() → captcha.Verifier
    |   \-- Get("email_otp") → *MFAAuthenticator → .Provider() → mfa.Provider
    |
    \-- cache (*cache.Manager)                // Challenge 生命周期管理
```

challenge.Service 只有两个字段：`cache` 和 `registry`。不持有任何具体的 Provider 或 Verifier 实例。

---

## 3. 数据结构

### 3.1 CreateRequest

```go
type CreateRequest struct {
    Type   ChallengeType  // captcha / email_otp / totp / sms_otp / tg_otp
    UserID string         // TOTP 时必填
    Email  string         // email_otp 时必填
    Phone  string         // sms_otp 时必填
}
```

### 3.2 CreateResponse

```go
type CreateResponse struct {
    ChallengeID string            // 始终返回
    Type        string            // challenge 类型（有 Required 时不返回）
    ExpiresIn   int               // 过期秒数（有 Required 时不返回）
    Data        map[string]any    // 附加数据（site_key / masked_email 等）
    Required    *ConnectionConfig // 需要先完成的前置验证（含 connection / strategy / identifier）
}
```

### 3.3 VerifyRequest

```go
type VerifyRequest struct {
    Connection string  // 本次验证的类型（captcha / email_otp / totp ...）
    Proof      any     // 验证证明
}
```

### 3.4 VerifyResponse

```go
type VerifyResponse struct {
    Verified       bool
    ChallengeID    string         // 前置验证通过后返回
    ChallengeToken string         // 最终验证通过后签发的凭证
    Data           map[string]any // 附加数据（next 等）
}
```

---

## 4. 交互流程

### 4.1 Email OTP（有 captcha 前置）

最完整的流程，包含三次交互：

```
前端                                          后端
 │                                             │
 │  POST /auth/challenge                       │
 │  { type: "email_otp",                      │
 │    email: "a@b.com" }                      │
 │ ──────────────────────────────────────────> │
 │                                             │  RequiresCaptcha = true
 │                                             │  创建 challenge, 标记 pending_captcha
 │                                             │  邮件不发送
 │                                             │
 │  { challenge_id: "xxx",                     │
 │    required: {                              │
 │      connection: "captcha",                 │
 │      strategy: ["turnstile"],               │
 │      identifier: "0x4AAA..." }}             │
 │ <────────────────────────────────────────── │
 │                                             │
 │  (用户完成 Turnstile)                        │
 │                                             │
 │  PUT /auth/challenge?challenge_id=xxx       │
 │  { connection: "captcha",                   │
 │    proof: "turnstile_token" }               │
 │ ──────────────────────────────────────────> │
 │                                             │  验证 captcha ✓
 │                                             │  清除 pending_captcha
 │                                             │  触发 sendOTP → 邮件发出
 │                                             │
 │  { challenge_id: "xxx",                     │
 │    data: { next: "email_otp" }}             │
 │ <────────────────────────────────────────── │
 │                                             │
 │  (用户输入验证码)                             │
 │                                             │
 │  PUT /auth/challenge?challenge_id=xxx       │
 │  { connection: "email_otp",                 │
 │    proof: "382910" }                        │
 │ ──────────────────────────────────────────> │
 │                                             │  EmailOTPProvider.Verify ✓
 │                                             │  签发 ChallengeToken
 │                                             │  删除 challenge
 │                                             │
 │  { verified: true,                          │
 │    challenge_token: "v4.public.xxx" }       │
 │ <────────────────────────────────────────── │
```

### 4.2 TOTP（无 captcha 前置）

两次交互：

```
前端                                          后端
 │                                             │
 │  POST /auth/challenge                       │
 │  { type: "totp", user_id: "uid" }          │
 │ ──────────────────────────────────────────> │
 │                                             │  RequiresCaptcha = false
 │                                             │  直接创建 challenge
 │                                             │
 │  { challenge_id: "yyy",                     │
 │    type: "totp",                            │
 │    expires_in: 300 }                        │
 │ <────────────────────────────────────────── │
 │                                             │
 │  (用户输入 Authenticator App 动态码)          │
 │                                             │
 │  PUT /auth/challenge?challenge_id=yyy       │
 │  { connection: "totp",                      │
 │    proof: "123456" }                        │
 │ ──────────────────────────────────────────> │
 │                                             │  TOTPProvider.Verify ✓
 │                                             │
 │  { verified: true,                          │
 │    challenge_token: "v4.public.xxx" }       │
 │ <────────────────────────────────────────── │
```

### 4.3 Captcha（独立 challenge）

两次交互：

```
前端                                          后端
 │                                             │
 │  POST /auth/challenge                       │
 │  { type: "captcha" }                        │
 │ ──────────────────────────────────────────> │
 │                                             │
 │  { challenge_id: "zzz",                     │
 │    type: "captcha",                         │
 │    data: { site_key: "0x4AAA..." }}         │
 │ <────────────────────────────────────────── │
 │                                             │
 │  PUT /auth/challenge?challenge_id=zzz       │
 │  { connection: "captcha",                   │
 │    proof: "turnstile_token" }               │
 │ ──────────────────────────────────────────> │
 │                                             │
 │  { verified: true }                         │
 │ <────────────────────────────────────────── │
```

---

## 5. Connection 配置模型

Challenge 返回的 `required` 字段复用 `ConnectionConfig` 结构，与 `/auth/connections` 接口返回的格式完全一致：

```json
{
  "connection": "captcha",
  "identifier": "0x4AAAAAAAxxxxxx",
  "strategy": ["turnstile"]
}
```

前端拿到后可以直接用 `strategy` 判断渲染哪种 captcha 组件，无需额外查询。

---

## 6. Verify 分发逻辑

Verify 接口通过请求体中的 `connection` 字段显式分发：

```
PUT /auth/challenge?challenge_id=xxx
Body: { "connection": "captcha|email_otp|totp|...", "proof": "..." }

switch req.Connection {
case "captcha":
    → 如果 challenge.Type == captcha → 直接走 handleChallengeVerify（验证 captcha challenge）
    → 如果 pending_captcha == true  → 验证前置 captcha，通过后触发副作用（如发送邮件）
    → 否则 → 报错：challenge 不需要 captcha 验证

case challenge.Type:
    → 如果 pending_captcha == true  → 报错：请先完成 captcha 前置验证
    → 否则 → 委托给对应的 mfa.Provider 验证

default:
    → 报错：connection 与 challenge 不匹配
}
```

### 合法性校验矩阵

| Challenge 状态 | connection = "captcha" | connection = challenge.Type | 其他 connection |
|---------------|------------------------|----------------------------|----------------|
| pending_captcha | 验证 captcha → 触发副作用 | 拒绝（前置未完成） | 拒绝 |
| 正常 (captcha type) | 验证 captcha challenge | N/A (相同) | 拒绝 |
| 正常 (Delegated type) | 拒绝（无需 captcha） | 验证 MFA proof | 拒绝 |

---

## 7. ChallengeToken 与 Delegate 登录

Challenge 验证通过后签发 ChallengeToken（PASETO v4），可作为 Login 接口的 proof 使用。

### 7.1 认证因子分类

身份验证因子分三个类别：

| 类别 | 含义 | 示例 |
|------|------|------|
| 你**知道的**（Knowledge） | 记忆中的秘密 | 密码、PIN、安全问题 |
| 你**拥有的**（Possession） | 实体或虚拟设备 | 手机（短信/TOTP）、硬件密钥、邮箱 |
| 你**本身的**（Inherence） | 生物特征 | 指纹、面容、虹膜 |

- **单因素认证（SFA）**：只需一种因子（如只要密码）
- **多因素认证（MFA）**：需要两种或以上**不同类别**的因子组合（如密码 + TOTP）

> 密码 + 安全问题都属于"知道的"，不算 MFA。

### 7.2 在本系统中的对应关系

| 系统概念 | 认证因子角色 | 说明 |
|---------|------------|------|
| IDP（github/google/user） | 第一因子 | 证明"你是谁" |
| captcha（Required） | **不是认证因子** | 人机验证，防自动化攻击 |
| email_otp / totp / webauthn（Delegated） | 可作为第二因子或独立因子 | 取决于配置方式 |

### 7.3 Delegate 语义

`ConnectionConfig.Delegate` 的语义是**"可以替代该 IDP 主认证的独立验证方式"**，而不是"主认证之后的附加 MFA"。

#### 语义演进

早期理解：`delegate` = 主认证之后必须完成的 MFA 列表（附加验证）。

```
密码登录 → 验证通过 → 还需完成 totp 或 email_otp → 才算登录成功
```

当前理解：`delegate` = IDP 把登录能力委托给的独立认证方式（替代路径）。

```
用户可以选择：
  路径 A：直接密码登录
  路径 B：完成 email_otp challenge → 用 ChallengeToken 作为 proof 登录
  路径 C：完成 totp challenge → 用 ChallengeToken 作为 proof 登录
```

#### 为什么不叫 MFA

- MFA 的含义是"主认证**之后**的附加验证"——先验密码，再验 TOTP
- Delegate 的含义是"可以**替代**主认证的独立路径"——email_otp 验通了就等于登录了
- 两者的关系不同：MFA 是串行补充，Delegate 是并行替代

如果未来需要真正的 MFA（强制"密码 + TOTP"两步验证），应该用独立的配置字段（如 `mfa_required`），不应该复用 `delegate`。

### 7.4 Delegate 配置与流程

```json
{
  "connection": "user",
  "strategy": ["password", "passkey"],
  "delegate": ["email_otp", "totp"],
  "require": ["captcha"]
}
```

| 字段 | 关系 | 语义 |
|------|------|------|
| `strategy` | OR | 同一 connection 下的主认证方式，proof 直接提交给 IDP |
| `delegate` | OR | 可替代主认证的独立验证方式，proof 是 ChallengeToken |
| `require` | AND | 前置条件，必须全部通过 |

Strategy 和 Delegate 是**同级替代关系**——用户可以选择密码登录，也可以选择邮件验证码登录。

### 7.5 Delegate 登录流程

```
1. 前端发起 challenge（如 email_otp）
2. 完成 challenge 验证，拿到 challenge_token
3. POST /auth/login {
     connection: "user",
     proof: "<challenge_token>"
   }
4. 后端校验：
   - challenge_token 有效
   - challenge_token 的类型在 user.delegate 列表中
   - 登录成功
```

Delegate 的核心含义：IDP 把登录能力委托给了这些 connection，它们的 ChallengeToken 就是合法的登录凭证。

---

## 8. Challenge 状态机

```
                    POST /auth/challenge
                           |
              +------------+------------+
              |                         |
      RequiresCaptcha             不需要 captcha
              |                         |
    创建 challenge               创建 challenge
    pending_captcha=true         执行副作用（sendOTP）
    返回 required                返回 challenge 信息
              |                         |
    PUT /auth/challenge                 |
    { connection: "captcha" }           |
    验证 captcha ✓                      |
    清除 pending                        |
    执行副作用                           |
    返回 { next }                       |
              |                         |
              +------------+------------+
                           |
                PUT /auth/challenge
                { connection: challenge.Type }
                验证实际 proof ✓
                签发 ChallengeToken
                删除 challenge
                           |
                      { verified }
```

---

## 9. 设计决策

### 9.1 为什么 challenge.Service 依赖 Registry 而非直接持有 Provider

- **单一数据源**：所有 Authenticator 在 Registry 注册一次，challenge 按需获取，避免重复构造和实例不一致
- **配置一致性**：Registry 注册时检查了配置开关（如 `mfa.email-otp.enabled`），challenge 自动继承，不会出现"Registry 没注册但 challenge 能用"的情况
- **关注点分离**：challenge.Service 只做流程编排，验证能力由 Registry 中的 Provider 提供

### 9.2 为什么用 pending_captcha 状态机而非两次 POST

- **单一 Challenge ID**：前端拿到 ID 后所有操作围绕它，不需要重传 email、type 等参数
- **状态在服务端**：challenge 记录了 email、type 等信息，防止参数篡改
- **幂等性**：同一个 challenge ID 不会因为重复请求产生多次发邮件

### 9.3 为什么 Required 复用 ConnectionConfig 而非独立结构

- 与 `/auth/connections` 接口返回的结构一致，前端处理逻辑统一
- 包含 `strategy` 字段，前端知道该用哪种 captcha 组件（turnstile / recaptcha / hcaptcha）
- 多余字段有 `omitzero` 标签，JSON 输出干净

### 9.4 为什么 Verify 需要前端指定 connection

- **语义清晰**：前端明确知道自己在验什么，后端也能做合法性校验
- **防止误用**：pending 状态下提交 email_otp proof 会被拒绝，正常状态下提交 captcha 也会被拒绝
- **可扩展**：未来如果一个 challenge 有多个前置条件（如 captcha + SMS），connection 字段可以区分

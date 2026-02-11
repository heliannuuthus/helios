# Challenge API 接口文档

> 基于三层模型重构后的 Challenge 接口

---

## 概览

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/auth/challenge` | 创建 Challenge |
| PUT | `/auth/challenge?challenge_id={id}` | 验证 Challenge |

---

## 设计原则

1. **Challenge 与 AuthFlow 完全独立**：Challenge 是独立的验证服务，不依赖 AuthFlow 会话
2. **分层职责**：service 层负责验证逻辑，handler 层负责签发 ChallengeToken
3. **captcha 不是 channel_type**：captcha 仅作为前置条件，不能独立创建 Challenge
4. **client_id/audience 合法性校验**：Create 时校验应用存在、服务存在、且应用有权访问该服务

---

## 1. POST /auth/challenge — 创建 Challenge

### Request Body

```json
{
  "client_id": "app_abc123",
  "audience": "svc_xyz789",
  "type": "login",
  "channel_type": "email_otp",
  "channel": "user@example.com"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `client_id` | string | **必填** | 发起验证的应用 ID。需为已注册的合法应用。 |
| `audience` | string | **必填** | 目标服务 ID。需为合法服务，且与 client_id 存在关联关系。 |
| `type` | string | 验证类必填，交换类忽略 | 业务场景。用于限流策略和消息模板选择。 |
| `channel_type` | string | **必填** | 验证方式。可选值见下表。 |
| `channel` | string | **必填** | 验证目标。具体含义取决于 `channel_type`。 |

### channel_type 可选值

| channel_type | 分类 | channel 含义 | type 是否必填 | 说明 |
|-------------|------|-------------|-------------|------|
| `email_otp` | 验证类 | 邮箱地址 | 是 | 邮箱 OTP |
| `totp` | 验证类 | 用户标识（user_id） | 是 | TOTP 动态口令 |
| `webauthn` | 验证类 | 用户标识（可空，discoverable login 场景） | 是 | WebAuthn/Passkey |
| `wechat-mp` | 交换类 | 微信 code | 否 | 微信小程序换手机号 |
| `alipay-mp` | 交换类 | 支付宝 code | 否 | 支付宝小程序换手机号 |

> `captcha` 不作为独立的 `channel_type`，仅作为 `email_otp` 等验证类的前置条件自动触发。
>
> `sms_otp`、`tg_otp` 暂未支持，后续扩展。

### type 可选值（由业务 Service 定义）

| type | 含义 | 用途 |
|------|------|------|
| `login` | 登录验证 | delegate 登录场景 |
| `forget_password` | 忘记密码 | 密码重置前的身份确认 |
| `bind_phone` | 绑定手机号 | 个人中心绑定操作 |
| `bind_email` | 绑定邮箱 | 个人中心绑定操作 |
| 业务自定义 | ... | 按需扩展 |

### 错误校验

服务端在创建 Challenge 前执行以下校验：

1. `client_id` 对应的应用必须存在
2. `audience` 对应的服务必须存在
3. 该应用必须有权访问该服务（存在 Application-Service 关联关系）

校验失败返回 `400 invalid_request`。

### Response — 需要 captcha 前置

当 `channel_type` 为 `email_otp` 且系统配置了 captcha 时，返回 `required` 字段，提示前端先完成人机验证。

```json
{
  "challenge_id": "abc123def456",
  "required": {
    "connection": "captcha",
    "identifier": "0x4AAAAAAAxxxxxx",
    "strategy": ["turnstile"]
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `challenge_id` | string | Challenge 会话 ID |
| `required` | object \| null | 前置条件配置（captcha）。有值时表示需要先通过 PUT 提交 captcha proof。 |
| `required.connection` | string | 前置条件类型标识（`captcha`） |
| `required.identifier` | string | 公开标识（Turnstile site_key） |
| `required.strategy` | string[] | 策略（`turnstile`） |

### Response — 无前置条件

captcha 不需要或已配置跳过时，直接返回 Challenge 信息。

```json
{
  "challenge_id": "abc123def456",
  "channel_type": "email_otp",
  "expires_in": 300,
  "data": {
    "masked_email": "u***@example.com"
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `challenge_id` | string | Challenge 会话 ID |
| `channel_type` | string | 验证方式 |
| `expires_in` | int | 过期时间（秒） |
| `data` | object \| null | 附加数据。不同 channel_type 返回不同内容。 |
| `token` | string \| null | 交换类直接返回 ChallengeToken（验证类为空，由 handler 签发） |

### Response — 交换类（直接返回 Token）

```json
{
  "challenge_id": "xyz789",
  "token": "v4.public.xxxx..."
}
```

交换类一步完成，不需要 Verify。

### data 字段说明

| channel_type | data 内容 |
|-------------|----------|
| `email_otp` | `{ "masked_email": "u***@example.com" }` |
| 其他 | 空或 channel_type 特定数据 |

### 错误响应

| HTTP 状态 | error | 说明 |
|-----------|-------|------|
| 400 | `invalid_request` | 参数错误 / client_id 无效 / audience 无效 / 无访问权限 |
| 500 | `server_error` | 服务端错误（provider 未配置等） |

---

## 2. PUT /auth/challenge?challenge_id={id} — 验证 Challenge

### Query Parameters

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `challenge_id` | string | **必填** | 来自 POST 创建时返回的 challenge_id |

### Request Body

```json
{
  "channel_type": "captcha",
  "proof": "turnstile_token_string"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `channel_type` | string | **必填** | 本次提交的验证方式 |
| `proof` | any | **必填** | 验证证明。通常是 string（OTP code / captcha token），WebAuthn 场景可能是 JSON object。 |

### 验证流程说明

PUT 接口支持两种场景：

**场景 A：提交 captcha 前置验证**

当 POST 返回 `required` 时，先通过 PUT 提交 captcha：

```json
{
  "channel_type": "captcha",
  "proof": "turnstile_token"
}
```

Response（captcha 通过后触发副作用，如发邮件）：

```json
{
  "challenge_id": "abc123def456",
  "data": {
    "next": "email_otp"
  }
}
```

| 字段 | 说明 |
|------|------|
| `challenge_id` | 同一个 Challenge 会话 |
| `data.next` | 下一步需要提交的 channel_type |

**场景 B：提交实际验证**

captcha 通过后（或不需要 captcha 时），提交实际的 proof：

```json
{
  "channel_type": "email_otp",
  "proof": "382910"
}
```

Response（验证成功，handler 签发 ChallengeToken）：

```json
{
  "verified": true,
  "challenge_token": "v4.public.xxxx..."
}
```

Response（验证失败）：

```json
{
  "verified": false
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `verified` | bool | 是否验证成功 |
| `challenge_id` | string \| null | 前置验证通过后返回（场景 A） |
| `challenge_token` | string \| null | 验证成功后由 handler 签发的 ChallengeToken（场景 B） |
| `data` | object \| null | 附加数据 |

### channel_type 与 proof 对应关系

| channel_type | proof 类型 | proof 值 |
|-------------|-----------|---------|
| `captcha` | string | Turnstile token（仅用于前置验证） |
| `email_otp` | string | 6 位数字验证码 |
| `totp` | string | 6 位动态口令 |
| `webauthn` | string(JSON) | WebAuthn assertion response JSON |

### 错误响应

| HTTP 状态 | error | 说明 |
|-----------|-------|------|
| 400 | `invalid_request` | challenge 过期 / channel_type 不匹配 / proof 格式错误 / captcha 前置未完成 |
| 404 | `not_found` | challenge_id 不存在 |
| 500 | `server_error` | ChallengeToken 签发失败 |

---

## 3. ChallengeToken（签发后的凭证）

验证成功后返回的 `challenge_token` 是 PASETO v4.public Token，**由 handler 层负责签发**（service 层只返回验证结果）。

用途：

- **Delegate 登录**：作为 `POST /auth/login` 的 `proof` 字段
- **MFA 加固**：作为 `POST /auth/mfa/complete` 的 `challenge_token` 字段

### Token Claims

| Claim | Key | 类型 | 说明 |
|-------|-----|------|------|
| Subject | `sub` | string | 完成验证的 principal（邮箱 / 手机号 / user_id / credential_id） |
| Channel Type | `typ` | string | 使用的验证方式（email_otp / totp / webauthn ...） |
| Biz Type | `biz` | string \| 空 | 业务场景（login / forget_password，交换类为空） |
| Client ID | `cli` | string | 发起验证的应用 ID |
| Audience | `aud` | string | 目标服务 ID |
| Issuer | `iss` | string | 签发者 |
| Issued At | `iat` | datetime | 签发时间 |
| Expires At | `exp` | datetime | 过期时间（5 分钟） |

---

## 4. 分层职责

```
handler (ContinueChallenge)
  |-- challengeSvc.Verify()     → VerifyResult { Verified, Challenge }
  |-- [Verified == true]
  |     \-- handler.issueChallengeToken(Challenge)
  |           |-- token.NewChallengeTokenBuilder()  → Subject / Type / BizType
  |           |-- token.NewClaimsBuilder()          → Issuer / ClientID / Audience / ExpiresIn
  |           \-- tokenSvc.Issue()                  → "v4.public.xxx"
  \-- response { verified, challenge_token }
```

---

## 5. 完整交互示例

### 5.1 Email OTP 登录（有 captcha 前置）

```
POST /auth/challenge
{ "client_id": "app_abc", "audience": "svc_xyz", "type": "login", "channel_type": "email_otp", "channel": "a@b.com" }
→ { "challenge_id": "xxx", "required": { "connection": "captcha", ... } }

PUT /auth/challenge?challenge_id=xxx
{ "channel_type": "captcha", "proof": "turnstile_token" }
→ { "challenge_id": "xxx", "data": { "next": "email_otp" } }

PUT /auth/challenge?challenge_id=xxx
{ "channel_type": "email_otp", "proof": "382910" }
→ { "verified": true, "challenge_token": "v4.public.xxx" }

POST /auth/login
{ "connection": "user", "proof": "v4.public.xxx" }
→ { "location": "https://app.example.com/callback?code=..." }
```

### 5.2 TOTP 登录（无前置）

```
POST /auth/challenge
{ "client_id": "app_abc", "audience": "svc_xyz", "type": "login", "channel_type": "totp", "channel": "user_123" }
→ { "challenge_id": "yyy", "channel_type": "totp", "expires_in": 300 }

PUT /auth/challenge?challenge_id=yyy
{ "channel_type": "totp", "proof": "123456" }
→ { "verified": true, "challenge_token": "v4.public.xxx" }
```

### 5.3 微信小程序换手机号（交换类）

```
POST /auth/challenge
{ "client_id": "app_abc", "audience": "svc_xyz", "channel_type": "wechat-mp", "channel": "<wx_phone_code>" }
→ { "challenge_id": "zzz", "token": "v4.public.xxx" }
```

交换类一步完成，不需要 PUT。

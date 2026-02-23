# Challenge API 接口文档

> 基于当前实现的 Challenge 接口规范
> 更新日期：2026-02-17

---

## 概览

| 方法 | 路径 | Handler | 说明 |
|------|------|---------|------|
| POST | `/auth/challenge` | InitiateChallenge | 创建 Challenge |
| POST | `/auth/challenge/:cid` | ContinueChallenge | 验证 Challenge |

---

## 设计原则

1. **Challenge 与 AuthFlow 完全独立**：Challenge 是独立的验证服务，不依赖 AuthFlow 会话
2. **Handler 编排 + Service 原子能力**：Handler 层负责业务流程编排，Service 层只提供原子操作
3. **前置条件由 ACManager 配置驱动**：通过 accessctl.Manager 根据全局/per-channelType 配置动态决策是否需要 captcha 前置条件
4. **client_id / audience 合法性校验**：Create 时校验应用存在、服务存在
5. **通过类型断言发现能力**：Service 通过 ChallengeVerifier / ChallengeExchanger 类型断言获取 Challenge 能力
6. **依赖注入保证完整性**：所有 Service 依赖通过 wire 注入，启动时 fail-fast

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
| `audience` | string | **必填** | 目标服务 ID。需为合法服务。 |
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

> `captcha` 不作为独立的 `channel_type`，作为 vchan（验证渠道）注册到 Registry，由 ACManager 根据配置动态决定是否需要 captcha 前置条件。
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

### Handler 编排流程

1. **Validate** — 参数校验（由轻到重）
2. **ProbeIPRate** — IP 维度限流（在构建 Challenge 之前）
3. **NewChallenge** — 构建 Challenge 对象
4. **StrikeRequirement** — 访问控制探测（Strike 记录每次验证尝试）：ACCaptcha 设前置 / ACAllowed 放行
5. **Initiate** — 执行副作用（发 OTP 等）
6. **Save** — 持久化

### 错误校验

服务端在创建 Challenge 前执行以下校验（由轻到重）：

1. `channel_type` 对应的 Provider 必须已注册（纯内存 map 查找）
2. 验证类 → `type` 必须非空（纯字段校验）
3. `client_id` 对应的应用必须存在（本地缓存）
4. `audience` 对应的服务必须存在（本地缓存）
5. 验证类 → 服务必须配置了该 challenge type（远程查询）

校验失败返回 HTTP 400。

### Response — 需要前置条件

当 ACManager 探测到需要 captcha 前置条件（ACCaptcha）时，返回 `required` 字段。此时不触发副作用（邮件不发送）。

```json
{
  "challenge_id": "abc123def456",
  "required": {
    "captcha": {
      "identifier": "0x4AAAAAAAxxxxxx",
      "strategy": ["turnstile"]
    }
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `challenge_id` | string | Challenge 会话 ID（16 位 Base62） |
| `required` | object / null | 前置条件。key 为 connection 名（如 "captcha"），value 为配置。 |
| `required.<connection>` | object | 前置条件配置 |
| `required.<connection>.identifier` | string | 公开标识（如 site_key） |
| `required.<connection>.strategy` | array | 认证策略（如 ["turnstile"]） |

### Response — 无前置条件

StrikeRequirement 返回 ACAllowed 时，直接调用 Initiate 完成，返回 Challenge 信息。

```json
{
  "challenge_id": "abc123def456",
  "retry_after": 60
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `challenge_id` | string | Challenge 会话 ID |
| `retry_after` | int | 下次可重发的冷却时间（秒） |

### Response — 被限流

限流触发时返回 **HTTP 429 Too Many Requests**。

**IP 维度限流**（Challenge 构建之前检查，无 challenge_id）：

```
HTTP/1.1 429 Too Many Requests

{ "retry_after": 60 }
```

**Channel 维度限流**（Initiate 阶段限流）：

```
HTTP/1.1 429 Too Many Requests

{ "retry_after": 60 }
```

前端读取 `retry_after` 倒计时后重试。

### 错误响应

错误仅返回 HTTP 状态码，无 `error` / `error_description` body。

| HTTP 状态码 | 说明 |
|-------------|------|
| 400 | 参数错误 / client_id 无效 / audience 无效 / channel_type 不支持 / type 缺失 |
| 429 | 被限流（附 `retry_after`，可选 `challenge_id`） |
| 500 | 服务端错误（initiate 失败等） |

---

## 2. POST /auth/challenge/:cid — 验证 Challenge

### Path Parameters

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `cid` | string | **必填** | 来自 POST 创建时返回的 challenge_id |

### Request Body

```json
{
  "type": "captcha",
  "proof": "turnstile_token_string"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | string | **必填** | 当前提交的验证类型。前置条件验证时为 connection 名（如 `"captcha"`），主验证时为 channel_type 名（如 `"email_otp"`）。通过结构体 `binding:"required"` 校验。 |
| `proof` | any | **必填** | 验证证明。通常是 string（OTP code / captcha token），WebAuthn 场景可能是 JSON object。 |

### Handler 编排流程

```
GetChallenge → 过期检查
      |
   IsUnmet?
   /       \
  yes       no
  |          |
VerifyRequirement    VerifyProof
  |                    |
 仍 Unmet?          verified?
 /    \              /      \
yes    no          yes      no
|      |            |        |
Save  Initiate    Delete   StrikeAndDecide
返回   Save       签发Token   |
required  返回     返回     ACCaptcha/error
       verified=false  verified=true
```

### 验证流程说明

**场景 A：提交前置条件验证**

当 Challenge 有未完成的前置条件（IsUnmet=true）时：

```json
{
  "type": "captcha",
  "proof": "turnstile_token"
}
```

Response（前置条件通过后触发主 Provider 副作用，如发邮件）：

```json
{
  "verified": false
}
```

前置条件验证通过后，Challenge 内部清空 `required`，自动调用 Initiate。后续提交会走实际验证分支。

**场景 B：提交实际验证**

前置条件已通过（或不需要前置条件）时：

```json
{
  "type": "email_otp",
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

```
HTTP/1.1 400 Bad Request
```

仅返回 HTTP 400 状态码，无响应体。

Response（验证失败次数达到阈值，重新触发前置条件）：

```json
{
  "verified": false,
  "required": {
    "captcha": {
      "identifier": "0x4AAAAAAAxxxxxx",
      "strategy": ["turnstile"]
    }
  }
}
```

### 响应字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `verified` | bool | 是否验证成功 |
| `challenge_token` | string / null | 验证成功后由 handler 签发的 ChallengeToken（PASETO v4） |
| `required` | object / null | 前置条件（未完成或重新触发时返回） |

### 错误响应

错误仅返回 HTTP 状态码，无 `error` / `error_description` body。

| HTTP 状态码 | 说明 |
|-------------|------|
| 400 | challenge 过期 / proof 格式错误 / 前置条件验证失败 / 验证失败 |
| 404 | challenge_id 不存在 |
| 429 | 被限流（附 `retry_after`，可选 `challenge_id`） |
| 500 | ChallengeToken 签发失败 / initiate 失败 |

---

## 3. ChallengeToken（签发后的凭证）

验证成功后返回的 `challenge_token` 是 PASETO v4.public Token，**由 handler 层负责签发**。

用途：

- **Delegate 登录**：作为 `POST /auth/login` 的 `proof` 字段
- **MFA 加固**：作为 MFA 流程中的验证凭证

### Token Claims

| Claim | Key | 类型 | 说明 |
|-------|-----|------|------|
| Subject | `sub` | string | 完成验证的 principal（邮箱 / 手机号 / user_id / credential_id） |
| Channel Type | `typ` | ChannelType | 使用的验证方式（email_otp / totp / webauthn ...） |
| Biz Type | `biz` | string / 空 | 业务场景（login / forget_password，交换类为空） |
| Client ID | `cli` | string | 发起验证的应用 ID |
| Audience | `aud` | string | 目标服务 ID |
| Issuer | `iss` | string | 签发者 |
| Issued At | `iat` | datetime | 签发时间 |
| Expires At | `exp` | datetime | 过期时间（5 分钟） |

---

## 4. 分层职责

```
Handler (InitiateChallenge)
  |-- Validate(ctx, &req)                → error
  |-- ProbeIPRate(ctx)                   → retryAfter (429 if hit)
  |-- NewChallenge(&req)                 → *Challenge
  |-- StrikeRequirement(ctx, ch)         → ACAction
  |-- BuildCaptchaRequired()             → *ChallengeRequired
  |-- Initiate(ctx, ch)                  → retryAfter, error (429 if hit)
  |-- Save(ctx, ch)                      → error
  \-- response { challenge_id, required }

Handler (ContinueChallenge)
  |-- GetChallenge(ctx, cid)             → *Challenge, error
  |-- [IsUnmet] VerifyRequirement(ctx, ch, &req)  → error
  |-- [!IsUnmet] VerifyProof(ctx, ch, proof)       → bool, error
  |-- [verified] Delete(ctx, ch.ID)
  |-- [verified] issueChallengeToken(ctx, ch)      → token string
  |-- [!verified] StrikeAndDecide(ctx, ch)         → ACAction
  \-- response { verified, challenge_token, required }
```

---

## 5. 完整交互示例

### 5.1 Email OTP 登录（有 captcha 前置）

```
POST /auth/challenge
{ "client_id": "app_abc", "audience": "svc_xyz", "type": "login", "channel_type": "email_otp", "channel": "a@b.com" }
→ { "challenge_id": "xxx", "required": { "captcha": { "identifier": "0x4AAA...", "strategy": ["turnstile"] } } }

POST /auth/challenge/xxx
{ "type": "captcha", "proof": "turnstile_token" }
→ { "verified": false }

POST /auth/challenge/xxx
{ "type": "email_otp", "proof": "382910" }
→ { "verified": true, "challenge_token": "v4.public.xxx" }

POST /auth/login
{ "connection": "user", "proof": "v4.public.xxx" }
→ { "location": "https://app.example.com/callback?code=..." }
```

### 5.2 TOTP 登录（无前置）

```
POST /auth/challenge
{ "client_id": "app_abc", "audience": "svc_xyz", "type": "login", "channel_type": "totp", "channel": "user_123" }
→ { "challenge_id": "yyy", "retry_after": 60 }

POST /auth/challenge/yyy
{ "type": "totp", "proof": "123456" }
→ { "verified": true, "challenge_token": "v4.public.xxx" }
```

### 5.3 微信小程序换手机号（交换类）

```
POST /auth/challenge
{ "client_id": "app_abc", "audience": "svc_xyz", "channel_type": "wechat-mp", "channel": "<wx_phone_code>" }
→ { "challenge_id": "zzz" }
```

> 交换类通过 ChallengeExchanger.Exchange 方法一步完成。

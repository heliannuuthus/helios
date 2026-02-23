# Challenge 服务设计文档

> 更新日期：2026-02-17

---

## 1. 概述

Challenge 是独立于 AuthFlow 的验证流程，用于完成需要异步交互的身份验证（如邮件验证码、TOTP、WebAuthn 等）。Challenge 验证通过后签发短期 ChallengeToken（PASETO v4），可作为 Login 接口的 proof 使用。

### 核心定位

- **Challenge 是验证能力**，不是业务逻辑。每次 Challenge 只验证一个认证因子。
- **Challenge 是 MFA 的组成部分**——MFA = 主认证 + 追加 Challenge，两个不同类别的因子组合。
- **Challenge 是 Delegate 登录的基础**——Delegate 路径 = 独立完成一次 Challenge → 签发 ChallengeToken → 作为 Login 的 proof。

### 核心设计原则

- **单一 Challenge ID 贯穿整个验证流程**：创建后返回 challenge_id，后续所有操作围绕该 ID。
- **Handler 编排 + Service 原子能力**：Handler 层负责业务流程编排（校验 → 限流 → 访问控制 → 发起 → 保存 → 响应），Service 层只提供原子操作（Validate / StrikeRequirement / ProbeIPRate / Initiate / Save / Delete / VerifyRequirement / VerifyProof / StrikeAndDecide 等），不包含任何编排逻辑。
- **三类 Provider 各自独立接口**：idp.Provider / factor.Provider / vchan.Provider 分属不同包、代表不同概念。每类有对应的包装器，同时实现 Authenticator 接口和 Challenge 能力接口。
- **前置条件由 ACManager 配置驱动**：访问控制管理器（accessctl.Manager）根据全局/per-channelType 配置判断是否需要 captcha 前置条件，Handler 通过 Service 的 StrikeRequirement 决策自动编排，不硬编码任何具体的前置逻辑。
- **通过类型断言发现能力**：Challenge Service 从 Registry 获取 Authenticator 后，通过 ChallengeVerifier 或 ChallengeExchanger 类型断言发现其 Challenge 能力。
- **依赖 Registry 而非自持 Provider**：challenge.Service 通过 authenticator.Registry 按需获取验证能力，不重复持有任何 Provider 或 Verifier 实例。
- **依赖注入保证完整性**：所有 Service 依赖通过 wire 注入，启动时 fail-fast，Handler 不做任何 nil 防御检查。

---

## 2. 三层模型

Challenge 请求由三个维度描述。

### 2.1 Type（业务场景）

**由业务 Service 定义**，描述"为什么要做这个验证"。例如 login（登录验证）、forget_password（密码重置）、bind_phone（绑定手机号）、bind_email（绑定邮箱）等，可按需扩展。

Type 的作用：

- **限流策略**：不同 type 可配置不同的频率限制
- **消息模板**：不同 type 发送不同的验证码邮件/短信文案
- **审计日志**：记录这次验证的业务目的
- **策略控制**：某些 channel_type 只允许在特定 type 下使用

**Type 只适用于验证类 Challenge，交换类不需要 Type。**

### 2.2 Channel Type（验证方式）

**由系统定义**，描述"通过什么方式验证"。按交互模式分为两大类。

#### 验证类

用户需要主动提交 proof 完成验证，支持 Type 场景配置。

| Channel Type | 交互模式 | 因子类别 | Create 行为 | Verify 行为 |
|-------------|---------|---------|------------|------------|
| email_otp | 发送-验证 | Possession | 发邮件验证码 | 比对验证码 |
| sms_otp | 发送-验证 | Possession | 发短信验证码 | 比对验证码 |
| totp | 输入-验证 | Possession | 构建 Challenge（无副作用） | 比对动态码 |
| webauthn | 挑战-签名 | Inherence + Possession | 生成 challenge options | 验签 |

email_otp 和 sms_otp 的 captcha 前置条件由 ACManager 根据配置动态决定（而非 Provider 静态声明）。captcha 本身是 vchan 类型的验证渠道，通过 vchan.Provider 接口实现。

#### 交换类

平台侧的固定能力，用 code 换取用户信息，通过 ChallengeExchanger 接口的 Exchange 方法一步完成。

| Channel Type | 平台 | 换取什么 |
|-------------|------|---------|
| wechat-mp | 微信小程序 | 手机号 |
| alipay-mp | 支付宝小程序 | 手机号 |

交换类不需要 Type，因为交换是一次性即时完成的，没有消息模板可选，触发由前端用户授权决定。

### 2.3 Channel（验证目标）

**由前端/用户提供**，是验证的具体操作数。

| Channel Type | Channel 含义 | 示例 |
|-------------|-------------|------|
| email_otp | 目标邮箱 | a@b.com |
| sms_otp | 目标手机号 | +8613800138000 |
| totp | 用户标识 | user_123 |
| webauthn | 用户标识（可空） | user_123 或空 |
| wechat-mp | 微信 code | wx_code |
| alipay-mp | 支付宝 code | alipay_code |

---

## 3. 分层架构

### 3.1 Handler 层（编排）

Handler 是业务流程的编排层，从方法签名即可读出完整业务主线：

**InitiateChallenge**：validate → IP rate limit → build → access control (StrikeRequirement) → initiate → save

**ContinueChallenge**：load → prerequisite / main verify → failure decision → issue token

Handler 直接构造 HTTP 响应（CreateResponse / VerifyResponse），不依赖 Service 返回的中间结构体。

### 3.2 Service 层（原子能力）

Service 只提供无编排的原子操作，每个方法做一件事：

| 方法 | 职责 | 返回值 |
|------|------|--------|
| Validate | 校验请求参数合法性（由轻到重） | error |
| NewChallenge | 根据请求构建 Challenge 对象（不持久化） | *Challenge |
| StrikeRequirement | 记录验证尝试并决策是否需要 captcha 前置条件 | ACAction |
| BuildCaptchaRequired | 构建 captcha 前置条件配置 | *ChallengeRequired |
| ProbeIPRate | IP 维度频率限流 | retryAfter int |
| Initiate | 执行 ChallengeVerifier.Initiate（发 OTP 等） | retryAfter, error |
| Save | 保存 Challenge 到缓存 | error |
| Delete | 删除 Challenge | error |
| VerifyRequirement | 验证前置条件 proof 并标记 | error |
| VerifyProof | 验证主 Challenge proof | bool, error |
| StrikeAndDecide | 记录验证尝试并返回访问控制决策 | ACAction |
| GetChallenge | 获取 Challenge | *Challenge, error |

### 3.3 接口体系

#### 底层 Provider 接口（三类独立）

| 接口 | 包 | 方法 | 代表概念 |
|------|-----|------|---------|
| idp.Provider | authenticator/idp | Type / Login / FetchAdditionalInfo / Prepare | 身份提供商 |
| factor.Provider | authenticator/factor | Type / Initiate / Verify / Prepare | 认证因子 |
| vchan.Provider | authenticator/vchan | Type / Initiate / Verify / Prepare | 验证渠道 |

vchan.Provider 与 factor.Provider 方法签名相同，但它们是独立接口、分属不同包，代表不同的业务概念。

#### Challenge 能力接口

| 接口 | 方法 | 说明 |
|------|------|------|
| ChallengeVerifier | Initiate / Verify | 两阶段验证（factor / vchan 的包装器实现） |
| ChallengeExchanger | Exchange | 一步交换（部分 IDP 的包装器条件实现） |

#### 包装器（每类一个，实现多接口）

| 包装器 | 持有 | 实现的接口 | 说明 |
|--------|------|-----------|------|
| FactorAuthenticator | factor.Provider | Authenticator + ChallengeVerifier | 所有 factor 都支持 Challenge 两阶段验证 |
| VChanAuthenticator | vchan.Provider | Authenticator + ChallengeVerifier | 所有 vchan 都支持 Challenge 两阶段验证 |
| IDPAuthenticator | idp.Provider | Authenticator + 条件 ChallengeExchanger | 底层实现了 idp.Exchangeable 时自动获得 Exchange 能力 |

#### 能力发现

Challenge Service 通过类型断言发现能力：

- authenticator.(ChallengeVerifier) → factor / vchan：两阶段 Initiate + Verify
- authenticator.(ChallengeExchanger) → 部分 IDP：一步 Exchange
- ACManager.Strike() → 根据配置决策是否需要 captcha 前置（验证计数）

#### 架构总览

```
Registry (key: Type())
│
├── IDPAuthenticator [Authenticator + ?ChallengeExchanger]
│   ├── GitHubProvider    (idp.Provider)
│   ├── GoogleProvider    (idp.Provider)
│   ├── WechatMPProvider  (idp.Provider + Exchangeable → ChallengeExchanger)
│   └── AlipayMPProvider  (idp.Provider + Exchangeable → ChallengeExchanger)
│
├── FactorAuthenticator [Authenticator + ChallengeVerifier]
│   ├── EmailOTPProvider  (factor.Provider)
│   ├── TOTPProvider      (factor.Provider)
│   └── WebAuthnProvider  (factor.Provider)
│
└── VChanAuthenticator [Authenticator + ChallengeVerifier]
    └── CaptchaProvider   (vchan.Provider)
```

---

## 4. 数据结构

### 4.1 Challenge 实体

Challenge 是存储在 Redis 中的临时会话状态，验证通过后即删除。

| 字段 | 类型 | 说明 |
|------|------|------|
| ID | string | 16 位 Base62 唯一标识 |
| ClientID | string | 发起验证的应用 ID |
| Audience | string | 目标服务 ID |
| Type | string | 业务场景（验证类必填，交换类为空） |
| ChannelType | ChannelType | 验证方式 |
| Channel | string | 验证目标（邮箱 / user_id / wx_code 等） |
| Required | ChallengeRequired | 通用前置条件状态（可为空） |
| CreatedAt | time.Time | 创建时间 |
| ExpiresAt | time.Time | 过期时间 |
| Data | map | 临时验证数据（masked_email、session 等） |

Challenge 提供两个状态判断：IsUnmet 检查是否有未完成的前置条件；IsExpired 检查是否已过期。

### 4.2 ChallengeRequired

通用前置条件集合，序列化到 Redis。

| 字段 | 类型 | 说明 |
|------|------|------|
| Conditions | RequiredCondition 数组 | 前置条件列表 |

每个 RequiredCondition 包含：

| 字段 | 类型 | 说明 |
|------|------|------|
| Connection | string | 前置条件的 connection 名（如 "captcha"） |
| Config | ConnectionConfig | 前端渲染配置（含 identifier、strategy 等） |
| Verified | bool | 内部状态，标记是否已通过。不暴露给前端（通过 ForClient 方法隐藏）。 |

ChallengeRequired 提供以下方法：HasPending（检查是否有未完成的条件）、GetPending（获取第一个未完成的条件）、GetCondition（按 connection 名获取条件）、Verified（标记指定条件已验证）、ForClient（返回隐藏 Verified 的客户端安全副本）。

### 4.3 CreateRequest

| 字段 | 必填 | 说明 |
|------|------|------|
| client_id | 必填 | 发起验证的应用 ID |
| audience | 必填 | 目标服务 ID |
| type | 验证类必填 | 业务场景 |
| channel_type | 必填 | 验证方式 |
| channel | 必填 | 验证目标 |

### 4.4 CreateResponse

| 字段 | 说明 |
|------|------|
| challenge_id | Challenge 会话 ID |
| required | 前置条件（有值时表示需要先提交前置验证） |

> 限流时不返回 200 + retry_after，而是返回 HTTP 429，body 为 `{ "retry_after": N }` 或 `{ "retry_after": N, "challenge_id": "..." }`。

### 4.5 VerifyRequest

| 字段 | 必填 | 说明 |
|------|------|------|
| type | 必填 | 当前提交的是哪个验证（前置条件对应 required 中的 connection，如 "captcha"；主验证对应 channel_type） |
| proof | 必填 | 验证证明 |

challenge_id 从 URL path 参数获取。`type` 字段通过结构体 `binding:"required"` 验证，不为空。

### 4.6 VerifyResponse

| 字段 | 说明 |
|------|------|
| verified | 是否验证成功 |
| challenge_token | 验证成功后签发的 ChallengeToken（PASETO v4） |
| required | 前置条件未完成或重新触发时返回 |

> 限流同 CreateResponse，返回 HTTP 429 + `{ "retry_after": N, "challenge_id": "..." }`。

---

## 5. 交互流程

### 5.1 Email OTP（有 captcha 前置）

最完整的流程，包含三次交互：

1. **POST /auth/challenge** — 前端提交 client_id、audience、type=login、channel_type=email_otp、channel=a@b.com。Handler 编排：Validate 校验参数 → ProbeIPRate 检查 IP 限流 → NewChallenge 构建对象 → StrikeRequirement 记录尝试并决策访问控制（返回 ACCaptcha）→ BuildCaptchaRequired 获取 captcha 配置 → Save 保存 → 返回 challenge_id 和 required。邮件不发送。

2. **POST /auth/challenge/:cid** — 前端完成 Turnstile 后提交 type=captcha、proof=turnstile_token。Handler 编排：GetChallenge 加载 → IsUnmet 判断走前置分支 → VerifyRequirement 验证 captcha proof 并标记 Verified → 前置全部满足 → ProbeIPRate + Initiate 发送邮件 → Save 保存 → 返回 verified=false。

3. **POST /auth/challenge/:cid** — 前端提交 type=email_otp、proof=382910。Handler 编排：GetChallenge 加载 → 无前置条件走主验证 → VerifyProof 比对验证码成功 → Delete 清理 → issueChallengeToken 签发 Token → 返回 verified=true 和 challenge_token。

### 5.2 TOTP（无 captcha 前置）

两次交互：

1. **POST /auth/challenge** — 前端提交 channel_type=totp、channel=user_123。Handler 编排：Validate → ProbeIPRate → NewChallenge → StrikeRequirement 返回 ACAllowed → Initiate 构建 Challenge → Save → 返回 challenge_id。

2. **POST /auth/challenge/:cid** — 前端提交 type=totp、proof=123456。Handler 编排：GetChallenge → VerifyProof 比对动态码成功 → Delete + issueChallengeToken → 返回 verified=true 和 challenge_token。

### 5.3 微信小程序换手机号（交换类）

一次交互：

1. **POST /auth/challenge** — 前端提交 channel_type=wechat-mp、channel=wx_phone_code。后端通过类型断言获取 ChallengeExchanger，调用 Exchange 方法，内部通过微信 API 用 code 换取手机号。返回 challenge_id。

---

## 6. InitiateChallenge 流程（Handler 编排）

Handler 编排 6 个阶段，每个阶段调用 Service 的一个原子方法：

1. **Validate** — 由轻到重校验：Provider 已注册（内存查找）→ 验证类 type 非空（字段校验）→ 应用存在（本地缓存）→ 服务存在（本地缓存）→ 验证类的服务配置存在（远程查询）
2. **ProbeIPRate** — IP 维度频率限流。在构建 Challenge 对象之前执行，避免限流时创建无用对象。限流时返回 HTTP 429 + `{ "retry_after": N }`，无 challenge_id。
3. **NewChallenge** — 根据请求参数构建 Challenge 对象（纯内存，不持久化）。
4. **StrikeRequirement** — 调用 ACManager.Strike 记录验证尝试，根据 per-channelType 的 Policy 配置决策。两种结果：
   - **ACCaptcha** → BuildCaptchaRequired 构建前置条件 → Save 保存 → 返回 challenge_id + required，不触发副作用
   - **ACAllowed** → 继续下一步
5. **Initiate** — 调用 ChallengeVerifier.Initiate 执行副作用（发邮件等）。如果 Provider 内部限流返回 retryAfter > 0，返回 HTTP 429 + `{ "retry_after": N, "challenge_id": "..." }`。
6. **Save** — 持久化 Challenge 到 Redis。

---

## 7. ContinueChallenge 流程（Handler 编排）

Handler 根据 Challenge 内部状态（IsUnmet）自动分支：

1. **GetChallenge** — 从 Redis 读取，检查是否过期。
2. **前置条件分支（IsUnmet = true）**：
   - VerifyRequirement 验证 proof 并标记 Verified
   - 仍有未满足条件 → Save → 返回 required
   - 全部满足 → rateInitiateAndSave（Initiate + Save）→ 返回 verified=false
3. **主验证分支（IsUnmet = false）**：
   - VerifyProof 验证主 proof
   - **验证成功** → Delete 清理 + issueChallengeToken 签发 → 返回 verified=true + challenge_token
   - **验证失败** → StrikeAndDecide 记录尝试并决策：
     - ACCaptcha → BuildCaptchaRequired 追加前置条件 → Save → 返回 required
     - ACAllowed → 返回 verification failed 错误

---

## 8. Provider 接口

### 8.1 factor.Provider

每个认证因子实现自己的完整验证逻辑。Provider 接口包含四个方法：

- **Type** — 返回因子类型标识（email_otp / totp / webauthn）
- **Initiate** — 校验 channel、执行副作用（发邮件等）、返回 retryAfter。
- **Verify** — 验证凭证。
- **Prepare** — 返回前端所需的公开配置（ConnectionConfig）。

| Provider | 类型 | Initiate 行为 | Verify 行为 |
|----------|------|--------------|------------|
| EmailOTPProvider | email_otp | 校验邮箱 → channel 限流 → 生成 OTP → 保存到 Redis → 发邮件 → 返回 retryAfter | 从 Redis 取 OTP → 比对 |
| TOTPProvider | totp | 构建 Challenge（无副作用） | 通过 credentialSvc 获取密钥 → 比对动态码 |
| WebAuthnProvider | webauthn | 生成 challenge options → 存 session → 返回 retryAfter | 验签 WebAuthn assertion |

captcha 前置条件不再由 Provider 静态声明，而是由 ACManager 根据配置动态决定。

### 8.2 vchan.Provider

验证渠道 Provider，与 factor.Provider 方法签名相同但分属不同包。

| Provider | 类型 | Initiate 行为 | Verify 行为 |
|----------|------|--------------|------------|
| CaptchaProvider | captcha | 无副作用，返回 0 | 调用内部 captcha.Verifier 验证（通过 context 传递 remoteIP） |

CaptchaProvider 内部持有 captcha.Verifier（如 TurnstileVerifier），将其适配为 vchan.Provider 接口。

### 8.3 idp.Provider + Exchangeable

部分 IDP 支持 Exchange 能力（如小程序用 code 换手机号）。通过可选的 Exchangeable 接口声明：

| Provider | Exchangeable | Exchange 行为 |
|----------|-------------|--------------|
| WechatMPProvider | 是 | 手机号授权 code → 调用微信 API → 返回手机号 |
| TTMPProvider | 是 | 手机号授权 code → 调用抖音 API → 返回手机号 |
| GitHubProvider | 否 | 不支持 |
| GoogleProvider | 否 | 不支持 |

---

## 9. ChallengeToken 与 Delegate 登录

### 9.1 Token 签发

ChallengeToken 由 **handler 层**签发，service 层只返回验证结果。handler 收到 verified=true 后，从 Challenge 中提取 Channel（作为 Subject）、ChannelType、Type，结合 ClientID、Audience、Issuer 构建 PASETO v4 Token，有效期 5 分钟。

### 9.2 Token Claims

| Claim | Key | 说明 |
|-------|-----|------|
| Subject | sub | 完成验证的 principal（邮箱 / user_id / credential_id） |
| Channel Type | typ | 验证方式 |
| Biz Type | biz | 业务场景（交换类为空） |
| Client ID | cli | 应用 ID |
| Audience | aud | 服务 ID |
| Issuer | iss | 签发者 |
| Issued At | iat | 签发时间 |
| Expires At | exp | 过期时间 |

### 9.3 Delegate 登录流程

1. 前端发起 Challenge（如 email_otp），完成验证后拿到 ChallengeToken。
2. 前端调用 POST /auth/login，connection=user，proof=ChallengeToken。
3. 后端校验 ChallengeToken 有效，且其 channel_type 在 user.delegate 列表中，登录成功。

### 9.4 Delegate 语义

ConnectionConfig.Delegate 的语义是 **"可以替代该 IDP 主认证的独立验证方式"**，而不是"主认证之后的附加 MFA"。

| 字段 | 逻辑关系 | 语义 |
|------|---------|------|
| strategy | OR | 主认证方式，proof 直接提交给 IDP |
| delegate | OR | 替代路径，proof 是 ChallengeToken |
| require | AND | 前置条件，必须全部通过 |

Strategy 和 Delegate 是同级替代关系：用户可以选择密码登录（strategy），也可以选择邮件验证码登录（delegate）。如果未来需要真正的 MFA（强制"密码 + TOTP"两步验证），应该用独立的配置字段，不复用 delegate。

---

## 10. 认证因子分类

| 因子类别 | 含义 | 对应的 Channel Type |
|---------|------|-------------------|
| Knowledge（你知道的） | 记忆中的秘密 | password（在 IDP strategy 中，不走 Challenge） |
| Possession（你拥有的） | 实体或虚拟设备 | email_otp, sms_otp, totp, wechat-mp, alipay-mp |
| Inherence（你本身的） | 生物特征 | webauthn（含设备持有 + 生物特征） |

- 单独使用任何一个 channel_type = 单因素认证
- 主认证（Knowledge）+ 追加 Challenge（Possession / Inherence）= 多因素认证
- Challenge 用于 delegate 登录 = 单因素替代路径
- Challenge 用于 MFA 加固 = 多因素的第二因子

验证能力本身不区分是单因素场景还是多因素场景，由编排层决定。

---

## 11. 状态机

```
                    POST /auth/challenge
                           |
                    Handler 编排
                           |
                   1. Validate (参数校验)
                   2. ProbeIPRate (IP 限流)
                           |
                     ┌─ 限流 → HTTP 429 { retry_after }
                     │
                   3. NewChallenge
                   4. StrikeRequirement
                           |
                    +------+------+
                    |             |
               ACCaptcha       ACAllowed
                    |             |
             BuildCaptchaRequired  5. Initiate()
                       Save       执行副作用
                       返回 { required }  6. Save
                           |      返回 { challenge_id }
                           |                   |
              POST /auth/challenge/:cid        |
              提交前置 proof                     |
              VerifyRequirement ✓               |
              Verified("captcha")              |
              全部通过 → Initiate()             |
              → 副作用                          |
              返回 { verified: false }          |
                           |                   |
                           +--------+----------+
                                    |
                    POST /auth/challenge/:cid
                    提交实际 proof
                    VerifyProof()
                                    |
              +------+------+
              |      |
            成功  Strike→ACCaptcha
              |      |
           Delete  追加captcha
           签发    前置条件
          Token   Save
              |      |
         { verified: true,   { required }
           challenge_token }
```

验证失败两级响应：验证失败时 ACManager.Strike 记录验证尝试并返回决策。ACCaptcha → 追加 captcha 前置条件，客户端需重新完成前置验证。ACAllowed → 返回 verification failed 错误。

---

## 12. 请求级元数据传递

请求级元数据（如 remoteIP）通过 `pkg/ctxutil` 注入 `context.Context`，而非作为函数参数显式传递：

- Handler 层：`ctxutil.WithRemoteIP(c.Request.Context(), c.ClientIP())`
- Service/Provider 层：`ctxutil.RemoteIPFrom(ctx)`

这样保持了 Service 方法签名的简洁性，同时提供了类型安全的 context value 存取。

---

## 13. 缓存策略

### Redis 数据

| Key 格式 | 用途 | TTL |
|----------|------|-----|
| {prefix}challenge:{id} | Challenge 会话 | 配置的 challenge 过期时间（默认 5 分钟） |
| {prefix}otp:{key} | OTP 验证码 | 配置的 OTP 过期时间 |

### 本地缓存（Ristretto）

| Key 格式 | 用途 | TTL |
|----------|------|-----|
| {prefix}challenge-config:{serviceID}:{challengeType} | Challenge 业务配置 | 配置的 TTL |

缓存层级：Challenge 会话存 Redis（分布式，TTL 自动过期），Challenge Config 走 Ristretto 本地缓存 → hermes DB，OTP 验证码存 Redis。

---

## 14. 访问控制（accessctl.Manager）

accessctl.Manager 统一管理频率限流和失败计数决策，底层依赖 pkg/throttle。Challenge 和 Login 流程共享同一个 ACManager 实例。

### 14.1 三种能力

| 能力 | 方法 | 说明 | 返回值 |
|------|------|------|--------|
| 频率限流 | CheckRate | 使用 Policy.Key + Limits，Peek → Allow 两阶段写入 | 0=放行，>0=需等待秒数 |
| 验证计数与决策 | Strike | 使用 Policy.Key + Window + CaptchaThreshold，写入一条验证尝试记录后返回决策 | ACAction |

Strike 记录每次验证尝试（包括 Create 和 Verify），不区分成功/失败，统一计数后根据 CaptchaThreshold 决策。Service 内部通过 `buildFailPolicy` 私有方法统一构建 failure policy，StrikeRequirement 和 StrikeAndDecide 共享同一构建逻辑。

### 14.2 决策枚举

| ACAction | 含义 | Challenge 行为 | Login 行为 |
|----------|------|---------------|------------|
| ACAllowed | 放行 | 正常处理 | 正常处理 |
| ACCaptcha | 需要 captcha | 设置 ChallengeRequired，返回 required | 返回 HTTP 300 Multiple Choices，Location 指向 captcha 流程（action redirect） |

### 14.3 配置层级

#### Challenge 访问控制

Policy 配置支持 per-channelType 覆盖全局默认：

| 配置路径 | 优先级 | 说明 |
|---------|--------|------|
| aegis.challenge.access-control.{channelType}.captcha-threshold | 最高 | 指定 channelType 的 captcha 阈值 |
| aegis.challenge.access-control.captcha-threshold | 中 | 全局 captcha 阈值 |
| 默认值 5 | 最低 | 编码默认值（0 = 始终需要 captcha） |

fail-window 同理支持 per-channelType 覆盖。

#### Login 访问控制

| 配置路径 | 优先级 | 说明 |
|---------|--------|------|
| aegis.login.access-control.{connection}.captcha-threshold | 最高 | 指定 connection 的 captcha 阈值 |
| aegis.login.access-control.captcha-threshold | 中 | 全局 captcha 阈值 |
| 默认值 5 | 最低 | 编码默认值 |

fail-window（默认 30 分钟）同理。

### 14.4 Key 维度

| 用途 | Key 格式 | 触发时机 |
|------|---------|---------|
| IP 频率限流 | rl:create:ip:{remoteIP} | Challenge Create 时（构建对象前）、前置条件通过后 |
| Channel 频率限流 | 由各 Provider.Initiate 内部构造 | Provider.Initiate 内部 |
| Challenge 失败决策 | rl:vfail:{audience}:{channel} | Challenge Create 和 Verify 时（Strike 记录每次尝试） |
| Login 失败决策 | rl:login:{audience}:{connection}:{principal} | Login 认证前和认证失败时（Strike 记录每次尝试） |

### 14.5 Login 访问控制流程

1. 构建 Policy：key = rl:login:{audience}:{connection}:{principal}
2. 执行认证
3. 认证失败：Strike 记录尝试并决策
   - ACCaptcha → 返回 HTTP 300 Multiple Choices，Location 指向需完成 captcha 的前端流程
   - ACAllowed → 返回认证失败
4. 认证成功：正常继续

Login 流程通过 HTTP 300 Multiple Choices 与 Location header 指示前端进行 action redirect（如完成 captcha），而非 JSON body 中的状态码。

---

## 15. 设计决策

### 15.1 为什么采用 Handler 编排 + Service 原子能力

之前 Service 既做原子操作又做编排（Create/Verify 大方法），Handler 只做透传。这导致 Handler 看不出业务主线，Service 方法过于庞大。现在 Handler 作为编排层清晰展示完整业务流程，Service 作为原子能力层只做一件事，职责分明。Handler 可直接构造 HTTP 响应，不需要 Service 返回中间结构体（如 VerifyResult）。

### 15.2 为什么采用三类独立 Provider 接口

idp.Provider / factor.Provider / vchan.Provider 虽然部分方法签名相同，但代表完全不同的业务概念。idp 是身份提供商，factor 是认证因子，vchan 是验证渠道（如 captcha）。独立接口保持语义清晰，防止概念混淆。

### 15.3 为什么用包装器而非直接实现多接口

包装器模式实现了"每类一个，实现多接口"的设计：底层 Provider 保持纯净，只关心自己的领域逻辑；包装器知道如何将 Provider 的能力翻译成 Authenticator（Login 流程）和 ChallengeVerifier/ChallengeExchanger（Challenge 流程）。注册一次即可通过类型断言发现所有能力。

### 15.4 为什么前置条件由 ACManager 配置驱动

之前的设计中，哪些 channel_type 需要 captcha 先是由 ChannelType.RequiresCaptcha() 硬编码，后改为 Provider 通过 Prepare().Require 静态声明。现在进一步演进为由 ACManager 根据全局/per-channelType 配置动态决定。好处：captcha 阈值可按 channelType 独立调整（如 email_otp 始终需要 captcha-threshold=0，totp 则 captcha-threshold=5），且验证尝试次数超过阈值后自动追加 captcha。配置变更无需改代码。

### 15.5 为什么 ChallengeExchanger 是独立接口

交换类（如小程序换手机号）是一步完成的，不需要 Initiate + Verify 两阶段。用独立的 ChallengeExchanger 接口表达这种能力差异，比在 ChallengeVerifier 中塞入空操作更清晰。

### 15.6 为什么验证失败后有两级响应

防止暴力猜测攻击。ACManager 根据验证尝试次数（Strike 记录每次尝试）提供两级响应：ACAllowed（未达阈值，返回 verification failed）→ ACCaptcha（达到 captcha 阈值，要求通过 captcha）。阈值、窗口均可按 channelType 配置。Challenge 和 Login 流程共享同一套两级响应机制。

### 15.7 为什么 Strike 记录每次验证尝试

Strike 统一记录每次验证尝试（Create 与 Verify 均计入），不区分成功或失败。基于窗口内尝试次数与 CaptchaThreshold 决策。Create 和 Verify 失败时均调用 Strike，保证计数一致、决策统一。

### 15.8 为什么 Login 也接入 ACManager

Login 流程是最常见的攻击面——密码暴力破解、ChallengeToken 重放等。通过 ACManager 的 Strike 机制，认证失败时记录尝试并决策。ACCaptcha 时返回 HTTP 300 Multiple Choices，Location 指向需完成 captcha 的前端流程，由前端根据 action redirect 完成后续步骤。按 audience + connection + principal 三维度计数，精确到具体用户和认证方式。

### 15.9 为什么 ChallengeToken 由 handler 签发而非 service

分层职责：service 只负责验证逻辑，不关心 Token 签发。灵活性：handler 可根据不同场景调整 Token claims。依赖隔离：service 不需要依赖 tokenSvc。

### 15.10 为什么 IP 限流在构建 Challenge 之前

之前 IP 限流在 NewChallenge 之后执行，导致限流时返回的响应没有 challenge_id，客户端收到 retry_after 后无法重试（无 ID），也无法重新创建（仍在限流中），形成死锁。将 IP 限流提前到构建之前，限流时不创建任何对象，返回 HTTP 429 + `{ "retry_after": N }`，客户端等待后重新发起即可。

### 15.11 为什么 Type 只适用于验证类

交换类是平台侧的固定能力，一次性即时完成，没有限流模板和消息模板的需求。

### 15.12 为什么用三层模型而非散装字段

type + channel_type + channel 统一了请求结构。不需要为每种验证方式单独加字段，新增 channel_type 只需注册 Provider，请求结构不变。

### 15.13 为什么依赖注入保证完整性而非运行时检查

所有 Service 依赖通过 wire 注入，启动时 fail-fast。如果 challengeSvc 为 nil 说明配置有误，不应带病运行到请求阶段。Handler 不做任何 `if svc == nil` 防御检查。

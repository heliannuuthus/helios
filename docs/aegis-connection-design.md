# Aegis Connection 设计与实现文档

> 涵盖：Connection 设计模型、数据结构、认证流程、API 端点、安全机制、客户端集成架构
> 更新日期：2026-02-17

---

## 目录

1. [概述](#1-概述)
2. [核心数据结构](#2-核心数据结构)
3. [Connection 类型体系](#3-connection-类型体系)
4. [API 端点](#4-api-端点)
5. [认证流程](#5-认证流程)
6. [缓存与状态管理](#6-缓存与状态管理)
7. [错误处理体系](#7-错误处理体系)
8. [安全机制与设计要点](#8-安全机制与设计要点)
9. [客户端（Atlas）集成架构](#9-客户端atlas集成架构)
10. [附录](#10-附录)

---

## 1. 概述

Helios 项目中的 "Connection" 是认证系统（Aegis 模块）的核心概念，代表一种**认证方式/身份提供商**的抽象。Connection 机制统一管理了三大类认证方式：

| 类别 | 缩写 | 含义 | 示例 |
|------|------|------|------|
| **IDP** | Identity Provider | 身份提供商 | github, google, wechat-mp, user, staff, passkey |
| **Required** | Required | 前置条件配置 | captcha |
| **Delegated** | Delegated | 委托路径配置 | email-otp, totp, webauthn |

整个认证流程遵循 **OAuth 2.1 + PKCE** 标准，使用 **PASETO v4** 代替 JWT 进行 Token 签发。

### Connection 设计模型

Connection 体系由三个维度定义：

- **connection** = 身份提供商/验证类型。不同的后端集成即不同的 connection。
  - IDP: `user`, `staff`, `github`, `google`, `wechat-mp`, `tt-mp`, `alipay-mp`, `passkey`, `wecom`...
  - Required: `captcha`
  - Delegated: `email-otp`, `totp`, `webauthn`
- **strategy** = 同一 connection 下的可选认证方式。
  - `user`/`staff`: `password` / `webauthn`
  - `captcha`: `turnstile`（可扩展 `recaptcha` / `hcaptcha`）
  - 其余 connection 验证方式唯一，不需要 strategy
  - 注意：`email-otp` 不是 strategy，只能通过 `delegate` 关联作为委托路径
- **channel** = 接入渠道（mp/web/oa），编码在 connection 名字里而非作为独立字段
  - 例如 `wechat-mp` 中的 `mp` 即微信小程序渠道

### 架构层次

```
路由注册
    |
Handler (编排层)
    |
authenticate.Service | authorize.Service | challenge.Service
    |
Authenticator Registry (全局注册表)
    |
IDPAuthenticator | VChanAuthenticator | FactorAuthenticator (胶水层)
    |
idp.Provider | captcha.Verifier | factor.Provider (底层实现)
    |
cache.Manager (本地缓存 + Redis)
    |
hermes.Service / hermes.UserService (DB)
```

### 三层认证器架构

Authenticator 采用统一接口 + 胶水层 + 底层实现的三层设计：

```
Authenticator 接口 (统一)
  Type() / Prepare() / Authenticate()
  |
  |-- IDPAuthenticator (胶水层)   -> idp.Provider 接口   -> Login() / Prepare()
  |-- VChanAuthenticator (胶水层) -> captcha.Verifier 接口 -> Verify() / GetIdentifier()
  \-- FactorAuthenticator (胶水层) -> factor.Provider 接口 -> Verify() / Prepare()
```

认证分发流程：Handler 解包 LoginRequest 后透传给 Service，Service 从 GlobalRegistry 按 connection 查找对应 Authenticator，各 Authenticator 内部自行处理 proof 类型断言和验证逻辑。

---

## 2. 核心数据结构

### 2.1 ConnectionConfig

返回给前端的公开配置，统一结构适用于 IDP、Required 和 Delegated。

- `Connection` (string): 唯一标识（如 github, captcha, email-otp）
- `Identifier` (string): 公开标识（client_id / site_key / rp_id）
- `Strategy` ([]string): 认证方式（user/staff: password, passkey; captcha: turnstile; 其余忽略）
- `Delegate` ([]string): 可替代主认证的独立验证方式（email_otp, totp），通过 Challenge 完成后以 ChallengeToken 作为 proof 登录
- `Require` ([]string): 前置条件（captcha），登录前必须全部通过
- `Verified` (bool): 在 AuthFlow 中动态标记是否已验证

#### Strategy / Delegate / Require 语义模型

三者共同定义了一个 IDP Connection 的完整登录条件，是**同级关系而非层级关系**：

| 字段 | 逻辑关系 | 完成时机 | 语义 |
|------|---------|---------|------|
| `Strategy` | OR（选一种） | 主认证 | IDP 自身直接验证的方式，proof 提交给 IDP |
| `Delegate` | OR（选一种） | 可替代主认证 | IDP 委托给 Challenge 流程的独立验证方式，proof 是 ChallengeToken |
| `Require` | AND（全部通过） | 主认证**之前** | 前置条件，必须全部通过后才能提交主认证 |

Strategy 和 Delegate 是**同级替代关系**：用户可以选择用密码登录（strategy），也可以选择用邮件验证码登录（delegate）。Delegate 不是"主认证之后的附加委托验证"，而是"可以替代主认证的独立路径"。

示例配置：

```json
{
  "connection": "user",
  "strategy": ["password", "passkey"],
  "delegate": ["email_otp", "totp"],
  "require": ["captcha"]
}
```

对应的登录路径：

| 登录方式 | 流程 |
|---------|------|
| 密码登录 | captcha → POST /login { connection: "user", strategy: "password" } |
| Passkey 登录 | captcha → POST /login { connection: "user", strategy: "passkey" } |
| 邮件验证码 | POST /challenge → 完成 email_otp → POST /login { connection: "user", proof: challenge_token } |
| TOTP | POST /challenge → 完成 totp → POST /login { connection: "user", proof: challenge_token } |

> Delegate 的核心含义：IDP 把登录能力委托给了这些 connection，它们的 ChallengeToken 就是合法的登录凭证。

### 2.2 ConnectionsMap

按类别分类的响应：IDP 列表、Required 列表、Delegated 列表。

### 2.3 AuthFlow

认证流程上下文，存储在 Redis 中，包含：
- 基本信息：ID, 创建时间, 过期时间（滑动窗口+绝对上限）
- 状态：initialized / authenticated / authorized / completed / failed
- 请求参数：AuthRequest（OAuth2 标准参数 + OIDC 扩展）
- 实体信息：Application, Service, User
- **Connection 配置：ConnectionMap（所有可用配置）, Connection（当前验证的）**
- 认证结果：Identities（用户身份列表）, Identify（IDP 身份信息）
- 授权结果：GrantedScopes
- 错误：FlowError

**Flow 状态机：**
```
initialized -> authenticated -> authorized -> completed
     |                                            |
     +----------------- failed <------------------+
```

### 2.4 LoginRequest 与登录响应

LoginRequest:
- `Connection` (string, 必填): 身份标识
- `Strategy` (string): 认证方式（user/staff: password/webauthn; captcha: turnstile; 其余忽略）
- `Principal` (string): 身份主体（用户名/邮箱/手机号）
- `Proof` (any): 凭证证明（password/OTP/OAuth code/ChallengeToken/WebAuthn assertion 等）

登录响应采用 **HTTP 300 Multiple Choices + Location header**，不再使用 JSON body 或 302/303 重定向：
- **登录成功**：300 + `Location` 为 `redirect_uri?code=xxx&state=xxx`。AJAX 请求不会自动跟随，前端通过 `Location` header 获取下一步指令。
- **未满足前置条件（captcha 等）**：300 + `Location` 指向当前页并附带 `?actions=xxx` 参数，前端据此渲染对应验证组件。
- **辅助验证（vchan/factor）完成**：300 重定向回登录页，前端继续下一步。

### 2.5 Authenticator 接口

统一认证器接口：
- `Type() string`: 返回类型标识
- `Prepare() *ConnectionConfig`: 返回前端公开配置
- `Authenticate(ctx, flow, params...) (bool, error)`: 执行认证

---

## 3. Connection 类型体系

### 3.1 IDP Connection 类型

| 值 | 域 | 说明 | 实现状态 |
|------|------|------|----------|
| wechat-mp | Consumer | 微信小程序 | 已实现 |
| tt-mp | Consumer | 抖音小程序 | 已实现 |
| alipay-mp | Consumer | 支付宝小程序 | 已实现 |
| wechat-web | Consumer | 微信网页授权 | 仅定义，未实现 |
| alipay-web | Consumer | 支付宝网页授权 | 仅定义，未实现 |
| tt-web | Consumer | 抖音网页授权 | 仅定义，未实现 |
| user | Consumer | C端用户账号密码 | 已实现 |
| wecom | Platform | 企业微信 | 仅定义，未实现 |
| github | Platform | GitHub | 已实现 |
| google | Platform | Google | 已实现 |
| staff | Platform | 运营人员账号密码 | 已实现 |
| passkey | 通用 | Passkey/WebAuthn 无密码登录 | 已实现 |
| global | 系统 | 全局身份（每域一个，作为 sub） | 非认证用 |

**实际注册到 Registry 的 IDP：** wechat-mp, tt-mp, alipay-mp, github, google, user, staff, passkey（共 8 个）

域划分由配置 `identity.consumer-idps` / `identity.platform-idps` 决定。

### 3.2 Required Connection 类型

| 标识 | 说明 | 实现状态 |
|------|------|----------|
| captcha | 人机验证 | 已实现（当前 Cloudflare Turnstile，strategy: turnstile） |

> captcha 是 connection，具体 provider（turnstile/recaptcha/hcaptcha）作为 strategy 配置。

### 3.3 Delegated Connection 类型

| 值 | 说明 |
|------|------|
| email-otp | 邮件验证码 |
| totp | 时间动态口令 |
| webauthn | WebAuthn/FIDO2 |

---

## 4. API 端点

### 认证相关路由 (/auth/*)

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /auth/authorize | 创建认证会话 |
| GET | /auth/connections | 获取可用 Connection 配置 |
| GET | /auth/context | 获取认证流程上下文 |
| POST | /auth/login | 使用 Connection 登录 |
| POST | /auth/challenge | 发起 Challenge |
| POST | /auth/challenge/:cid | 继续 Challenge（body: type + proof） |
| POST | /auth/token | 换取 Token |
| POST | /auth/revoke | 撤销 Token |
| POST | /auth/check | 关系权限检查（CAT 认证） |
| POST | /auth/logout | 登出（需携带 Token） |
| GET | /auth/pubkeys | 获取 PASETO 公钥 |

---

## 5. 认证流程

### 5.1 标准 OAuth 2.1 + PKCE 登录流程

```
客户端                    Aegis (Helios)                    前端 (Aegis UI)

1. POST /auth/authorize
   (client_id, audience,
    redirect_uri, PKCE)
   =========================>
                              创建 AuthFlow
                              设置 Cookie (aegis-session)
                              300 + Location 重定向到登录页
                              ===============================>

                              2. GET /auth/connections
                              <===============================
                              返回 ConnectionsMap (idp/required/delegated)
                              ===============================>

                              3. GET /auth/context
                              <===============================
                              返回应用/服务信息
                              ===============================>

                              [可选] POST /auth/challenge
                              (前置验证: captcha/email-otp)
                              <===============================
                              ===============================>

                              4. POST /auth/login
                              (connection, proof, strategy)
                              <===============================
                              认证 -> 查找/创建用户 -> 授权
                              生成授权码
                              HTTP 300 + Location header
                              (location = redirect_uri?code=xxx&state=xxx)
                              ===============================>

5. POST /auth/token
   (code, code_verifier,
    client_id, redirect_uri)
   =========================>
                              验证 PKCE, 签发 Token
   { access_token,
     refresh_token, ... }
   <=========================
```

### 5.2 登录端点核心逻辑

1. **Connection 验证**分两层：GlobalRegistry 检查系统支持 + flow.ConnectionMap 检查应用配置
2. **前置验证 (Require)**: 前端需先调用 /auth/login 传入 Required connection，全部通过才能继续
3. **Strategy 和 Delegate 是同级替代关系**：用户可选 Strategy（如密码）直接认证，也可选 Delegate（如 email_otp）通过 Challenge 获取 ChallengeToken 后作为 proof 提交登录

### 5.3 认证状态转换

Strategy 和 Delegate 是同级替代关系，用户选择其中一种路径完成主认证即可。

```
                    initialized
                        |
         +--------------+--------------+
         |              |              |
    [Required]        [Strategy]    [Delegate]
    captcha 等       密码/passkey   email_otp/totp
    前置条件          IDP 主认证    通过 Challenge 获取
    (AND, 全部通过)   (OR, 选一种)  ChallengeToken 登录
         |              |          (OR, 选一种)
         Verified       |              |
         =true          +--------------+
         |                     |
         +---------------------+
                        |
               AllRequiredVerified?
                        |
              +---------+---------+
              | No                | Yes
              | pending           |
              | (等待前置条件)    V
              |            resolveUser()
              |                   |
              |            authenticated
              |                   |
              |       CheckIdentityRequirements()
              |       ComputeGrantedScopes()
              |                   |
              |             authorized
              |                   |
              |          GenerateAuthCode()
              |                   |
              |             completed
              |
              +-- 等待前端再次调用 /auth/login
```

---

## 6. 缓存与状态管理

### 6.1 本地缓存（Ristretto）

| 缓存 | Key | Value | 用途 |
|------|-----|-------|------|
| domainCache | domain_id | DomainWithKey | 域信息及签名密钥 |
| applicationCache | app_id | ApplicationWithKey | 应用信息 |
| serviceCache | service_id | ServiceWithKey | 服务信息 |
| relationCache | service_id | []Relation | 关系列表 |
| appServiceCache | app_id:svc_id | bool | 应用-服务关系 |
| userCache | uid | UserWithDecrypted | 用户信息 |
| appOriginsCache | app_id | []string | 跨域配置 |
| appIDPConfigCache | app_id | []*ApplicationIDPConfig | 应用 IDP 配置 |
| pubKeyCache | client_id | KeyEntry | 公钥 |

### 6.2 Redis 数据

| Key 格式 | 用途 | TTL |
|----------|------|-----|
| auth:flow:{flowID} | AuthFlow 序列化 | 滑动窗口+绝对过期 |
| auth:code:{code} | 授权码 | 5 分钟 |
| auth:rt:{token} | Refresh Token | 可配置(默认365天) |
| auth:user:rt:{userID} | 用户 Refresh Token 集合 (Redis Set) | 跟随 RT 过期 |
| auth:ch:{challengeID} | Challenge 会话 | 5 分钟 |
| auth:otp:email-otp:{challengeID} | Email OTP 验证码 | 5 分钟 |

### 6.3 AuthFlow 生命周期

```
创建 -> SaveFlow (Redis SET + TTL)
  |
GetAndValidateFlow -> 检查过期 -> RenewFlow -> SaveFlow
  |
[成功] DeleteFlow (设置短 TTL 后自然过期)
[失败] SaveFlow (保留供重试)
```

滑动窗口续期: 每次访问 Flow 都会续期 ExpiresAt，但不超过 MaxExpiresAt 绝对上限。

---

## 7. 错误处理体系

### 设计原则

1. **前端仅依赖 HTTP 状态码**判断错误类型和显示策略，不解析 `error` / `error_description` 字段
2. **`/auth/authorize` 是唯一例外**——返回 OAuth 2.0 标准错误体 `{"error": "...", "error_description": "..."}`，因为该接口是 SDK 对接入口
3. **其他接口只返回 HTTP 状态码**，无 JSON body；需要附加数据时（428/429），仅返回 `data` 对象
4. **300 redirect URL 不携带 error**，错误通过 status code 或 navigate state 传递

### HTTP 状态码映射

| HTTP 状态码 | 内部错误码 | 说明 | 触发场景 |
|-------------|-----------|------|----------|
| 400 | invalid_request | 请求参数错误 | 不支持的 Connection / 参数缺失 |
| 400 | client_not_found | 应用不存在 | client_id 无效 |
| 400 | service_not_found | 服务不存在 | audience 无效 |
| 401 | invalid_credentials | 凭证无效 | 密码/OTP/ChallengeToken 错误 |
| 401 | invalid_token | Token 无效 | Token 过期/伪造 |
| 403 | access_denied | 访问被拒 | 应用无权访问服务 / 注册不允许 |
| 404 | not_found | 资源不存在 | Challenge 不存在等 |
| 408 | flow_expired | Flow 已过期 | 超过最大生命周期 |
| 409 | flow_invalid | Flow 状态非法 | 状态不允许当前操作 |
| 410 | invalid_grant | 授权码无效 | code 已使用/过期 |
| 412 | flow_not_found | Flow 不存在 | Cookie 丢失/Session 过期 |
| 426 | no_connection_available | 无可用 Connection | 应用未配置 IDP |
| 428 | identity_required | 需要绑定身份 | 服务要求特定身份（附 `data.required`） |
| 429 | rate_limited | 请求被限流 | IP/Channel 限流（附 `data.retry_after`） |
| 500 | server_error | 服务器错误 | IDP 调用失败等 |

### 前端错误处理策略

| HTTP 状态码 | 前端行为 |
|-------------|---------|
| 400 | 显示"请求参数无效" |
| 401 | 显示"认证失败" |
| 403 | 显示"访问被拒绝" |
| 404 | 显示"资源不存在" |
| 408/409/412 | 识别为 flow 过期，重新发起 authorize |
| 410 | 显示"授权已失效" |
| 426 | 显示"无可用登录方式" |
| 428 | 读取 `data.required`，引导用户绑定身份 |
| 429 | 读取 `data.retry_after`，倒计时后重试 |
| 500 | 显示"服务器错误" |

---

## 8. 安全机制与设计要点

### 8.1 OAuth 2.1 + PKCE

- 强制 S256 Code Challenge Method（不允许 plain）
- Token 交换必须提供 code_verifier
- 授权码一次性使用（原子读删）

#### redirect_uri 精确匹配（OAuth 2.1 Section 2.3.1）

OAuth 2.1 要求 `redirect_uri` 必须预注册并精确匹配：

> Authorization servers MUST require clients to register their complete redirect URI (including the path component).
> Authorization servers MUST reject authorization requests that specify a redirect URI that doesn't exactly match one that was registered.

本系统在授权阶段采用**规范化后比较**，而非 OAuth 2.1 要求的 Simple String Comparison（RFC 3986 Section 6.2.1）。规范化包括：统一 scheme/host 小写、移除默认端口（80/443）、移除末尾斜杠。这比规范要求略宽松，但在工程实践中更实用。

```
注册: https://atlas.heliannuuthus.com/auth/callback
请求: https://Atlas.heliannuuthus.com/auth/callback/  → 规范化后匹配（本系统允许）
                                                       → Simple String Comparison 不匹配（OAuth 2.1 严格模式不允许）
```

而在 Token 交换阶段，对 redirect_uri 执行**严格字符串比较**（非规范化），客户端必须提供与授权请求完全一致的 redirect_uri，否则返回 `invalid_grant`。

#### redirect_uri 与 state 的职责分离

OAuth 2.1 明确规定（Section 2.3.1）：

> The client MAY use the `state` request parameter to achieve per-request customization if needed rather than varying the redirect URI per request.

`redirect_uri` 是固定的安全入口（如 `/auth/callback`），`state` 用于携带动态数据（如用户原始访问页面）。本系统的 state 传递链路：

```
客户端 state → AuthRequest.State → AuthorizationCode.State → redirect_uri?code=xxx&state=yyy
```

### 8.2 Session Cookie

- Secure=true (仅 HTTPS)
- HttpOnly=true (防 XSS)
- SameSite=None (跨站 OAuth)

### 8.3 Token

- PASETO v4 (无算法混淆风险)
- Access Token 短 TTL (默认2h), 不可吊销
- Refresh Token 存 Redis, 可吊销, 数量上限 (默认10个)
- Refresh Token 超过上限时自动删除最旧的

### 8.4 Connection 安全

- 系统账号(user/staff)错误不泄露具体原因(统一返回 "authentication failed")
- Captcha 前置验证: 高风险操作需先通过人机验证。访问控制仅保留 ACAllowed / ACCaptcha 两级，由 Strike 记录每次尝试并决策
- Delegate 路径: 与 Strategy 同级的替代登录方式（如 email_otp, totp），通过 Challenge 流程获取 ChallengeToken 后作为 proof 提交 /auth/login
- MFA: 主认证成功后由风险评估动态触发的追加验证阶段，详见 mfa-orchestration-design.md
- 域隔离: Consumer/Platform 分域, IDP 不可跨域

### 8.5 密码学

- 敏感字段加密存储 (AES-GCM)
- Token 签名 Ed25519, 支持密钥轮换
- Footer 中加密存储内部 UID

---

## 9. 客户端（Atlas）集成架构

Atlas 作为 OAuth 2.1 客户端应用，通过 `@aegis/sdk` 与 Aegis 认证服务器交互。

### 9.1 整体架构

```
Atlas 前端                         Aegis 认证服务
(atlas.heliannuuthus.com)          (aegis.heliannuuthus.com)

┌─────────────────┐
│   AuthGuard     │  未登录
│   (路由守卫)     ├──────────────────────────────────────────────┐
│                 │  1. sessionStorage.setItem('auth_return_to') │
└─────────────────┘  2. auth.authorize()                         │
                     3. window.location.href = authorize URL     │
                                                                  V
                                                      ┌─────────────────────┐
                                                      │  /authorize          │
                                                      │  创建 AuthFlow       │
                                                      │  300 → /login        │
                                                      └──────────┬──────────┘
                                                                  │
                                                      ┌──────────V──────────┐
                                                      │  Aegis-UI 登录页    │
                                                      │  用户完成认证        │
                                                      └──────────┬──────────┘
                                                                  │
                                                      ┌──────────V──────────┐
                                                      │  /auth/login         │
                                                      │  300 + Location:     │
                                                      │  redirect_uri?code=  │
┌─────────────────┐                                   │  &state=             │
│  /auth/callback  │ <────────────────────────────────┘──────────────────────┘
│  (Atlas 路由)    │
│                  │  4. handleCallback(code, state)
│  ┌─────────────┐ │     a. consumeState() → 验证 CSRF
│  │ @aegis/sdk  │ │     b. consumeCodeVerifier()
│  │ handleCall- │ │     c. POST /auth/token (code + code_verifier + redirect_uri)
│  │ back()      │ │     d. 保存 token 到 localStorage
│  └─────────────┘ │
│                  │  5. navigate(sessionStorage.getItem('auth_return_to'))
└────────┬─────────┘
         │
┌────────V─────────┐
│   AuthGuard      │  已登录
│   initialize()   │  auth.isAuthenticated() → true
│   渲染业务页面    │
└──────────────────┘
```

### 9.2 SDK 存储布局（localStorage）

| Key | 用途 | 生命周期 |
|-----|------|----------|
| `aegis_access_token` | Access Token | Token 交换后写入，登出/过期时清除 |
| `aegis_refresh_token` | Refresh Token | Token 交换后写入（需 offline_access scope） |
| `aegis_expires_at` | Token 过期时间戳(ms) | 与 access_token 同步 |
| `aegis_scope` | 授权的 scope | 与 access_token 同步 |
| `aegis_code_verifier` | PKCE code_verifier | authorize 时写入，handleCallback 时消费（读后即删） |
| `aegis_state` | CSRF state | authorize 时写入，handleCallback 时消费（读后即删） |
| `aegis_audience` | 目标服务 audience | authorize 时写入，handleCallback 时消费 |
| `aegis_redirect_uri` | 回调地址 | authorize 时写入，handleCallback 时消费 |

### 9.3 关键设计决策

**1. redirect_uri 固定为 `/auth/callback`**

Atlas 注册的 redirect_uri 为 `https://atlas.heliannuuthus.com/auth/callback`。用户原始访问的页面地址通过 `sessionStorage('auth_return_to')` 在客户端本地保存，callback 成功后跳转回去。这符合 OAuth 2.1 的要求——redirect_uri 固定，动态数据通过 state 或客户端本地存储传递。

**2. 一次性凭据的消费语义**

`code_verifier`、`state`、`redirect_uri`、`audience` 采用 **consume（读后即删）** 模式，防止：
- 并发竞态：两个标签页同时处理 callback
- 重放攻击：同一 code_verifier 被多次使用

**3. Token 过期判断的双阈值**

| 调用方 | Buffer | 用途 |
|--------|--------|------|
| `isAuthenticated()` | 1 分钟 | 判断用户是否仍处于登录态 |
| `getAccessToken()` | 5 分钟 | 提前刷新，避免请求时 token 刚好过期 |

当 `getAccessToken()` 判定过期且**无 refresh_token** 时，会清除全部 token 存储。这意味着如果未请求 `offline_access` scope，token 在距离过期 5 分钟时会被主动清除。

**4. React StrictMode 的竞态风险**

React StrictMode 在开发环境下会**双重执行** useEffect，导致 `initialize()` 被调用两次。如果第一次 `initialize` 的异步操作（如 `getUserInfo`）中 `getAccessToken()` 触发了 token 清除，第二次 `initialize` 的 `isAuthenticated()` 会返回 false，引发重新登录。

受影响的时序：
```
第1次 initialize → isAuthenticated()=true → getUserInfo() → getAccessToken()
                   → isExpired(300s)=true + 无 refreshToken → clear() 清除全部 token
第2次 initialize → isAuthenticated()=false → 触发 login() → 重定向到 Aegis
```

---

## 10. 附录

### 附录 A: ConnectionsMap 响应示例

```json
{
  "idp": [
    { "connection": "user", "strategy": ["password", "webauthn"], "delegate": ["totp"], "require": ["captcha"] },
    { "connection": "github", "identifier": "Iv1.abc123..." },
    { "connection": "wechat-mp", "identifier": "wx1234567890" }
  ],
  "required": [
    { "connection": "captcha", "identifier": "0x4AAAAAAA...", "strategy": ["turnstile"] }
  ],
  "delegated": [
    { "connection": "email-otp" },
    { "connection": "totp" }
  ]
}
```

---

> **文档结束** - 覆盖了 Helios 中所有 Connection 相关的设计模型、数据结构、认证流程、API 端点、缓存策略、错误处理、安全机制及客户端集成架构。

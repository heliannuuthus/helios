# Aegis 认证授权系统设计文档

> 涵盖：认证授权流程、Token 体系、SSO 机制、多 Audience 授权、中间件、安全设计
> 更新日期：2026-02-17

---

## 目录

1. [概述](#1-概述)
2. [OAuth 2.1 授权码流程](#2-oauth-21-授权码流程)
3. [AuthFlow 状态机](#3-authflow-状态机)
4. [Token 体系](#4-token-体系)
5. [Token 交换](#5-token-交换)
6. [多 Audience 授权](#6-多-audience-授权)
7. [Token 刷新](#7-token-刷新)
8. [SSO 机制](#8-sso-机制)
9. [Token 验证中间件](#9-token-验证中间件)
10. [Token 撤销与登出](#10-token-撤销与登出)
11. [API 端点](#11-api-端点)
12. [缓存与存储](#12-缓存与存储)
13. [安全设计](#13-安全设计)
14. [附录](#14-附录)

---

## 1. 概述

Aegis 是 Helios 平台的认证授权服务，遵循 **OAuth 2.1 + PKCE** 标准，使用 **PASETO v4** 替代 JWT 进行 Token 签发。

### 1.1 核心职责

- OAuth 2.1 授权码流程（强制 PKCE S256）
- 多 IDP 身份认证（微信、支付宝、GitHub、Google、邮箱、Passkey 等）
- Token 签发与管理（Access Token、Refresh Token、SSO Token、Challenge Token）
- 多 Audience 授权（一次认证获取多个服务的独立凭证）
- 关系权限检查（ReBAC）
- SSO 会话管理

### 1.2 架构层次

```
Handler (编排层)
    │
    ├── authenticate.Service ──→ Authenticator Registry ──→ IDP/VChan/Factor Providers
    ├── authorize.Service ──→ Token Service ──→ 密钥 Resolver
    ├── challenge.Service ──→ Authenticator Registry ──→ ChallengeVerifier/ChallengeExchanger
    ├── user.Service ──→ hermes.UserService
    ├── cache.Manager ──→ Redis + Ristretto 本地缓存
    └── token.Service ──→ PASETO v4 签发/验证
```

### 1.3 设计原则

- **Handler 编排 + Service 原子能力**：Handler 负责业务流程编排，Service 只提供原子操作
- **Aegis 不直连数据库**：所有数据通过 Hermes 数据服务获取
- **依赖注入保证完整性**：所有 Service 依赖通过 Wire 注入，启动时 fail-fast

---

## 2. OAuth 2.1 授权码流程

### 2.1 完整交互序列

```
客户端 (Atlas)              Aegis (Helios)              Aegis-UI (登录页)

1. POST /auth/authorize
   (client_id, audience,
    scope, redirect_uri,
    code_challenge, state)
   ═══════════════════════►
                            验证 Application
                            验证 Service
                            验证 App-Service 关系
                            [尝试 SSO 快速路径]
                            创建 AuthFlow
                            设置 Cookie (aegis-session)
                            HTTP 300 + Location
                            ═══════════════════════════════►

                            2. GET /auth/connections
                            ◄═══════════════════════════════
                            返回 ConnectionsMap
                            (idp/required/delegated)
                            ═══════════════════════════════►

                            3. GET /auth/context
                            ◄═══════════════════════════════
                            返回应用/服务信息
                            ═══════════════════════════════►

                            [可选] POST /auth/challenge
                            (前置验证: captcha/email-otp)
                            ◄═══════════════════════════════
                            ═══════════════════════════════►

                            4. POST /auth/login
                            (connection, proof, strategy)
                            ◄═══════════════════════════════
                            认证 → 查找/创建用户
                            → 授权 → 生成授权码
                            → 签发 SSO Token
                            HTTP 300 + Location:
                            redirect_uri?code=xxx&state=xxx
                            ═══════════════════════════════►

5. POST /auth/token
   (code, code_verifier,
    client_id, redirect_uri)
   ═══════════════════════►
                            验证 PKCE
                            签发 Token
   { access_token,
     refresh_token, ... }
   ◄═══════════════════════
```

### 2.2 Authorize 端点（POST /auth/authorize）

Authorize 是认证流程的起点，负责创建 AuthFlow 认证会话。

**请求格式**：
- Method: POST
- Content-Type: application/x-www-form-urlencoded

| 参数 | 必填 | 说明 |
|------|------|------|
| client_id | 是 | 应用 ID |
| audience | 是 | 目标服务 ID |
| response_type | 是 | 固定 "code" |
| scope | 是 | 请求的 scope（如 "openid profile email offline_access"） |
| code_challenge | 是 | PKCE Code Challenge（S256） |
| code_challenge_method | 是 | 固定 "S256" |
| redirect_uri | 否 | 回调地址（不传则使用应用注册的默认地址） |
| state | 否 | CSRF 防护（原样返回） |
| prompt | 否 | 认证提示（none / login） |
| nonce | 否 | OIDC nonce |
| login_hint | 否 | 登录提示 |

**处理流程**：

1. 验证 Application（client_id 有效）
2. 验证 Service（audience 有效）
3. 验证 Application-Service 关系
4. SSO 快速路径检查（详见 [SSO 机制](#8-sso-机制)）
5. 获取应用 IDP 配置
6. 构建 AuthFlow（设置 ConnectionMap）
7. 持久化 Flow 到 Redis
8. 设置 `aegis-session` Cookie，HTTP 300 重定向到登录页

### 2.3 Login 端点（POST /auth/login）

Login 是认证的核心端点，处理用户身份验证。

**处理流程**：

1. 从 Cookie 获取 AuthFlow
2. 验证并设置 Connection
3. 前置条件检查（Required 中未 Verified 的 connection，如 captcha）
4. 执行认证（Authenticator.Authenticate）
5. 查找或创建用户（resolveUser，含 Account Linking）
6. 身份要求检查（CheckIdentityRequirements）
7. 计算授权 Scope（ComputeGrantedScopes）
8. 生成授权码（GenerateAuthCode）
9. 签发 SSO Token
10. HTTP 300 + Location 重定向

**登录响应采用 HTTP 300 Multiple Choices + Location header**：
- **登录成功**：Location 为 `redirect_uri?code=xxx&state=xxx`
- **需要前置验证**：Location 指向当前页并附带 `?actions=xxx`
- **辅助验证完成**：300 重定向回登录页继续下一步

### 2.4 Account Linking

当 IDP 认证返回的身份信息匹配到系统中已有用户时（通过邮箱/手机号），触发 Account Linking 流程：

1. 识别到已有用户 → 返回 `errIdentifiedUser`
2. 前端展示关联确认页（GET /auth/binding 获取信息）
3. 用户确认关联（POST /auth/binding）
4. 关联身份 → 继续授权流程

---

## 3. AuthFlow 状态机

AuthFlow 是认证流程的上下文，存储在 Redis 中，贯穿整个认证过程。

### 3.1 AuthFlow 结构

```go
type AuthFlow struct {
    ID           string                         // Flow ID（16位 Base62）
    CreatedAt    time.Time                      // 创建时间
    ExpiresAt    time.Time                      // 滑动窗口过期时间
    MaxExpiresAt time.Time                      // 最大生命周期（绝对过期）
    State        FlowState                      // 当前状态

    Request      *AuthRequest                   // OAuth2 请求参数
    Application  *models.ApplicationWithKey     // 应用信息
    Service      *models.ServiceWithKey         // 目标服务信息
    User         *models.UserWithDecrypted      // 已认证用户
    Identify     *models.TUserInfo              // IDP 身份信息（未绑定）

    ConnectionMap map[string]*ConnectionConfig  // 所有可用 Connection 配置
    Connection    string                        // 当前正在验证的 Connection

    Identities    models.Identities             // 用户全部身份绑定
    GrantedScopes []string                      // 授权的 scope
    Error         *FlowError                    // 错误状态
}
```

### 3.2 状态转换

```
                    initialized
                        │
         ┌──────────────┼──────────────┐
         │              │              │
    [Required]     [Strategy]     [Delegate]
    captcha 等    密码/passkey    email_otp/totp
    前置条件       IDP 主认证     通过 Challenge
    (AND, 全部)   (OR, 选一种)   (OR, 选一种)
         │              │              │
         Verified       ├──────────────┘
         =true          │
         │              │
         └──────────────┘
                        │
               AllRequiredVerified?
                        │
              ┌─────────┼─────────┐
              │ No               │ Yes
              │ pending          │
              │ (等待前置条件)    ▼
              │           resolveUser()
              │                 │
              │           authenticated
              │                 │
              │     CheckIdentityRequirements()
              │     ComputeGrantedScopes()
              │                 │
              │           authorized
              │                 │
              │        GenerateAuthCode()
              │                 │
              │           completed
              │
              └── 等待前端再次调用 /auth/login
```

**状态枚举**：

| 状态 | 含义 |
|------|------|
| `initialized` | AuthFlow 已创建，等待认证 |
| `authenticated` | 用户已通过身份验证 |
| `authorized` | 权限已计算，scope 已确定 |
| `completed` | 授权码已生成，流程完成 |
| `failed` | 流程失败 |

### 3.3 Flow 生命周期

```
创建 → SaveFlow (Redis SET + TTL)
  │
GetAndValidateFlow → 检查过期 → RenewFlow → SaveFlow
  │
[成功] DeleteFlow (设置短 TTL 后自然过期)
[失败] SaveFlow (保留供重试)
```

**滑动窗口续期**：每次访问 Flow 都会续期 `ExpiresAt`，但不超过 `MaxExpiresAt` 绝对上限。

---

## 4. Token 体系

Aegis 使用 **PASETO v4**（Platform-Agnostic Security Tokens）替代 JWT，消除算法混淆攻击风险。

### 4.1 Token 类型

| Token 类型 | 缩写 | 签发方 | 签名密钥 | Footer | 用途 |
|-----------|------|--------|---------|--------|------|
| UserAccessToken | UAT | Aegis | 域 Ed25519 密钥 | 加密（用户信息） | 用户访问资源服务 |
| ServiceAccessToken | SAT | Aegis | 域 Ed25519 密钥 | 无 | 服务间调用 |
| ClientAccessToken | CAT | 应用自身 | 应用自身密钥 | 无 | 应用调用 Aegis 管理 API |
| ChallengeToken | - | Aegis | 域 Ed25519 密钥 | 无 | Challenge 验证凭证（5分钟有效） |
| SSOToken | - | Aegis | 全局 Master Key | 加密（用户信息+认证方式） | SSO 会话 |

### 4.2 UAT（用户访问令牌）

UAT 是最核心的 Token 类型，由 Aegis 签发给客户端应用，用于访问资源服务。

**Claims（PASETO 标准字段）**：

| Claim | 说明 |
|-------|------|
| iss | 签发者（Aegis 实例标识） |
| aud | 目标服务 ID（audience） |
| sub | 用户唯一标识（OpenID） |
| iat | 签发时间 |
| exp | 过期时间 |
| jti | 唯一 Token ID |

**Encrypted Footer（用户信息）**：

Footer 使用对称密钥（AES）加密，包含根据 scope 过滤的用户信息：

| Scope | Footer 中包含的信息 |
|-------|-------------------|
| openid | open_id |
| profile | nickname, picture |
| email | email |
| phone | phone |

**只有持有对应 Service 的对称密钥的资源服务才能解密 Footer，获取用户信息。**

### 4.3 Token 签发流程

```
Token Service.Issue(token)
    │
    ├── UAT:  signKey(domain) + encryptKey(service) → PASETO v4.public + encrypted footer
    ├── SAT:  signKey(domain) → PASETO v4.public
    ├── ChallengeToken: signKey(domain) → PASETO v4.public
    ├── SSOToken: signKey(master) + encryptKey(master) → PASETO v4.public + encrypted footer
    └── CAT:  由客户端使用自身密钥签发（Aegis 不签发）
```

**密钥解析**：通过 Resolver 模式解耦密钥获取逻辑：
- `SignKeyResolver` — 根据 Token 的 claims（client_id → domain）解析签名密钥
- `FooterKeyResolver` — 根据 Token 的 claims（audience → service）解析加密密钥

### 4.4 密钥轮换

支持域级别的密钥轮换：
- 域可持有多个签名密钥（keys 列表）
- `main` 密钥用于签发新 Token
- 所有 `keys` 均可用于验证旧 Token
- 通过 `GET /auth/pubkeys` 暴露所有有效公钥

---

## 5. Token 交换

Token 交换通过 `POST /auth/token` 端点完成，支持两种 Content-Type：

| Content-Type | 模式 | 适用场景 |
|-------------|------|---------|
| `application/x-www-form-urlencoded` | 标准单 Audience | 传统 OAuth2 客户端 |
| `application/json` | 多 Audience | 需要同时访问多个服务的客户端 |

### 5.1 标准单 Audience Token 交换

**请求**（form-urlencoded）：

| 参数 | 必填 | 说明 |
|------|------|------|
| grant_type | 是 | `authorization_code` 或 `refresh_token` |
| code | authorization_code 时必填 | 授权码 |
| redirect_uri | authorization_code 时必填 | 回调地址（必须与 authorize 请求一致） |
| client_id | 是 | 应用 ID |
| code_verifier | authorization_code 时必填 | PKCE 验证器 |
| refresh_token | refresh_token 时必填 | 刷新令牌 |

**响应**：

```json
{
  "access_token": "v4.public.xxx",
  "refresh_token": "a1b2c3d4...",
  "token_type": "Bearer",
  "expires_in": 7200,
  "scope": "openid profile email"
}
```

**authorization_code 交换流程**：

1. 原子消费授权码（ConsumeAuthCode，Lua 脚本 get-and-delete，防重放）
2. 获取 AuthFlow
3. 验证 client_id 一致
4. 验证 redirect_uri 一致（严格字符串比较）
5. 验证 PKCE（code_verifier → S256 → 比对 code_challenge）
6. 签发 Access Token（根据 Flow 中的 scope 构建 footer）
7. 如果 scope 包含 `offline_access`，签发 Refresh Token
8. 异步清理 AuthFlow

---

## 6. 多 Audience 授权

多 Audience 授权允许客户端在一次认证后，同时获取多个服务的独立访问凭证。这解决了前端应用需要调用多个后端服务（如 hermes 管理服务 + iris 用户信息服务）的场景。

### 6.1 设计思路

- **Authorize 阶段不变**：仍然指定单个 audience 进行认证
- **Token 交换阶段扩展**：通过 JSON 请求体传入 `audiences` 字段，为每个 audience 签发独立的 Token
- **向下兼容**：`application/x-www-form-urlencoded` 请求走原有单 audience 逻辑

### 6.2 多 Audience Token 请求

**请求**（application/json）：

```json
{
  "grant_type": "authorization_code",
  "code": "AUTH_CODE",
  "redirect_uri": "https://atlas.heliannuuthus.com/auth/callback",
  "client_id": "app_xxx",
  "code_verifier": "PKCE_VERIFIER",
  "audiences": {
    "hermes": {
      "scope": "openid profile email"
    },
    "iris": {
      "scope": "openid profile"
    }
  }
}
```

| 参数 | 必填 | 说明 |
|------|------|------|
| grant_type | 是 | `authorization_code` 或 `refresh_token` |
| code | authorization_code 时必填 | 授权码 |
| redirect_uri | authorization_code 时必填 | 回调地址 |
| client_id | 是 | 应用 ID |
| code_verifier | authorization_code 时必填 | PKCE 验证器 |
| refresh_token | refresh_token 时必填 | 刷新令牌 |
| audiences | 是 | 目标服务及各自 scope 的映射 |

**audiences 字段**：

- key：服务 ID（audience）
- value：`{ "scope": "openid profile ..." }`
- scope 不指定时默认为 `openid`（业务逻辑内处理，不返回 400）
- 每个 audience 都必须通过 Application-Service 关系验证

### 6.3 多 Audience Token 响应

响应为 `map[audience]TokenResponse`，每个 audience 获得完整独立的 Token 信息：

```json
{
  "hermes": {
    "access_token": "v4.public.xxx",
    "refresh_token": "a1b2c3d4...",
    "token_type": "Bearer",
    "expires_in": 7200,
    "scope": "openid profile email"
  },
  "iris": {
    "access_token": "v4.public.yyy",
    "token_type": "Bearer",
    "expires_in": 7200,
    "scope": "openid profile"
  }
}
```

### 6.4 多 Audience 核心规则

| 规则 | 说明 |
|------|------|
| 独立签发 | 每个 audience 获得独立的 access_token，footer 中的用户信息按各自 scope 决定 |
| 独立 Refresh Token | 如果某个 audience 的 scope 包含 `offline_access`，该 audience 签发独立的 refresh_token |
| 关系验证 | 每个 audience 都要验证 Application-Service 关系 |
| scope 默认值 | 不指定 scope 时默认 `openid` |
| Content-Type 分发 | `application/json` → 多 audience，其他 → 单 audience |

### 6.5 Handler 分发逻辑

```go
func (h *Handler) Token(c *gin.Context) {
    if c.ContentType() == "application/json" {
        // 多 Audience：JSON 请求 → MultiAudienceTokenRequest
        h.tokenMultiAudience(c)
        return
    }
    // 单 Audience：form 请求 → TokenRequest（原逻辑）
    h.tokenSingleAudience(c)
}
```

### 6.6 多 Audience authorization_code 交换流程

1. 原子消费授权码
2. 获取 AuthFlow
3. 验证 client_id、redirect_uri、PKCE（与单 audience 一致）
4. **遍历 audiences**：
   - 验证 Application-Service 关系
   - 获取 Service 信息
   - 根据该 audience 的 scope 签发独立 access_token
   - 如果 scope 含 `offline_access`，签发独立 refresh_token
5. 异步清理 AuthFlow
6. 返回 `map[audience]TokenResponse`

---

## 7. Token 刷新

### 7.1 单 Audience 刷新

**请求**（form-urlencoded）：

```
grant_type=refresh_token
&refresh_token=TOKEN_VALUE
&client_id=app_xxx
```

**流程**：
1. 获取 Refresh Token（从 Redis）
2. 验证 client_id 一致
3. 获取用户、应用、服务信息
4. 签发新的 Access Token（使用 RT 中保存的 scope）
5. Refresh Token 保持不变（原样返回）

### 7.2 多 Audience 刷新

**请求**（application/json）：

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "TOKEN_VALUE",
  "client_id": "app_xxx",
  "audiences": {
    "hermes": { "scope": "openid profile email" },
    "iris": { "scope": "openid profile" }
  }
}
```

**流程**：
1. 获取传入的 Refresh Token（用于验证 client_id 和获取用户信息）
2. 验证 client_id 一致
3. 获取用户、应用信息
4. **遍历 audiences**：
   - 验证 Application-Service 关系
   - 获取 Service 信息
   - 签发独立的 Access Token
   - 如果 scope 含 `offline_access`，签发独立的 Refresh Token
5. 返回 `map[audience]TokenResponse`

---

## 8. SSO 机制

SSO（Single Sign-On）允许用户在一次登录后，后续访问同一 Aegis 实例下的其他应用时无需重新认证。

### 8.1 SSO Token

SSO Token 使用全局 Master Key 签发，存储在 SameSite=Lax 的 HttpOnly Cookie 中。

**Encrypted Footer 内容**：

| 字段 | 说明 |
|------|------|
| open_id | 用户唯一标识 |
| methods | 认证方式列表（如 ["password", "captcha"]） |
| level | 认证强度等级 |

### 8.2 SSO 快速路径

在 Authorize 阶段，如果用户携带了有效的 SSO Cookie，可以跳过整个登录页面直接签发授权码：

```
POST /auth/authorize
    │
    ├── 有 SSO Cookie?
    │   ├── 否 → 正常登录流程
    │   └── 是 → trySSO()
    │           │
    │           ├── 验证 SSO Token
    │           ├── 查找用户并验证状态
    │           ├── 获取应用 IDP 配置
    │           ├── 构建临时 AuthFlow
    │           ├── 授权并生成授权码
    │           ├── 续期 SSO Token（新 iat/exp/jti）
    │           └── HTTP 300 重定向到 redirect_uri?code=xxx&state=xxx
```

**SSO 快速路径不触发条件**：
- 请求包含 `prompt=login`（强制重新登录）
- SSO Cookie 不存在或已过期
- SSO Token 验签失败
- 用户状态异常（已禁用等）

### 8.3 SSO Cookie

| 属性 | 值 | 说明 |
|------|-----|------|
| Name | aegis-sso | Cookie 名称 |
| Secure | true | 仅 HTTPS |
| HttpOnly | true | 防 XSS |
| SameSite | Lax | 允许顶级导航携带 |
| Path | /auth | 限定认证路径 |

### 8.4 SSO Token 续期

每次 SSO 快速路径成功时，重新签发新的 SSO Token（新 iat/exp/jti），更新 Cookie。保持会话活跃。

---

## 9. Token 验证中间件

### 9.1 中间件架构

```go
type MiddlewareFactory struct {
    interpreter      *Interpreter     // Token 解析器
    publicKeyProvider                 // 验证 UAT 签名
    symmetricKeyProvider              // 解密 UAT footer
    privateKeyProvider                // 签发 CAT
}
```

**Factory 模式**：通过 `WithAudience(audience)` 创建绑定特定 audience 的中间件实例。

### 9.2 RequireAuth（认证中间件）

```
请求 → 提取 Bearer Token → Interpret（验签 + 解密 footer）→ 验证 audience → 设置到 Context
```

验证步骤：
1. 从 `Authorization: Bearer xxx` 提取 Token
2. 使用域公钥验证签名
3. 使用服务对称密钥解密 Footer
4. 检查 Token 的 audience 是否匹配当前服务
5. 将 Token 对象设置到 Gin Context（`aegis.ContextKeyUser`）

### 9.3 RequireRelation（鉴权中间件）

```
请求 → RequireAuth → 提取 Token 中的用户标识 → CheckRelation → 设置到 Context
```

在认证之上增加关系权限检查（ReBAC），验证用户是否具有指定的关系权限。

### 9.4 路由配置示例

```go
// Iris 用户信息路由（需要 iris audience 的 Token）
irisMw := app.MiddlewareFactory.WithAudience(irisconfig.GetAegisAudience())
userGroup := r.Group("/user")
userGroup.Use(irisMw.RequireAuth())
```

---

## 10. Token 撤销与登出

### 10.1 Revoke（POST /auth/revoke）

撤销指定的 Refresh Token。遵循 RFC 7009：即使 Token 无效也返回 200。

```
POST /auth/revoke
Content-Type: application/x-www-form-urlencoded

token=REFRESH_TOKEN_VALUE
```

### 10.2 Logout（POST /auth/logout）

需要携带有效的 Access Token（通过 RequireToken 中间件验证）。

1. 撤销该用户的所有 Refresh Token（RevokeUserRefreshTokens）
2. 清除 SSO Cookie

> Access Token 不可吊销（短 TTL 自然过期），登出后 Access Token 在过期前仍有效。

---

## 11. API 端点

### 11.1 认证路由（/auth/*）

| 方法 | 路径 | 说明 | CORS | 认证 |
|------|------|------|------|------|
| POST | /auth/authorize | 创建认证会话 | ✅ | 无 |
| GET | /auth/connections | 获取可用 Connection 配置 | ✅ | Cookie |
| GET | /auth/context | 获取认证流程上下文 | ✅ | Cookie |
| POST | /auth/login | 使用 Connection 登录 | ✅ | Cookie |
| GET | /auth/binding | 获取识别到的已有用户信息 | ✅ | Cookie |
| POST | /auth/binding | 确认/取消账户关联 | ✅ | Cookie |
| POST | /auth/challenge | 发起 Challenge | ✅ | 无 |
| POST | /auth/challenge/:cid | 继续 Challenge | ✅ | 无 |
| POST | /auth/token | 获取/刷新 Token（支持单/多 audience） | ✅ | 无 |
| POST | /auth/revoke | 撤销 Token | ✅ | 无 |
| POST | /auth/check | 关系权限检查 | 无 | CAT |
| POST | /auth/logout | 登出 | 无 | UAT |
| GET | /auth/pubkeys | 获取 PASETO 公钥 | 无 | 无 |

### 11.2 CORS

Aegis CORS 中间件支持**应用配置的 allowed_origins**，从 Application 的配置中动态读取。SPA 跨域调用认证 API 时需要 CORS 支持。

---

## 12. 缓存与存储

### 12.1 Redis 数据

| Key 格式 | 用途 | TTL |
|----------|------|-----|
| `auth:flow:{flowID}` | AuthFlow 序列化 | 滑动窗口 + 绝对过期 |
| `auth:code:{code}` | 授权码 | 5 分钟 |
| `auth:rt:{token}` | Refresh Token | 可配置（默认 365 天） |
| `auth:user:rt:{openid}` | 用户 Refresh Token 集合 | 跟随 RT 过期 |
| `auth:ch:{challengeID}` | Challenge 会话 | 5 分钟 |

### 12.2 本地缓存（Ristretto）

| 缓存 | Key | Value | 说明 |
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

### 12.3 授权码的原子消费

授权码采用 Lua 脚本实现 **get-and-delete** 原子操作，确保一次性使用：

```
GET auth:code:{code} → 如果存在 → DEL auth:code:{code} → 返回数据
                     → 如果不存在 → 返回错误
```

### 12.4 Refresh Token 数量管理

每用户每应用的 Refresh Token 有数量上限（默认 10 个）。签发新 RT 时异步检查，超过上限则删除最旧的。

---

## 13. 安全设计

### 13.1 OAuth 2.1 + PKCE

| 机制 | 说明 |
|------|------|
| 强制 PKCE S256 | 不允许 plain，防止授权码拦截攻击 |
| 授权码一次性使用 | Lua 脚本原子读删，防重放 |
| redirect_uri 验证 | Authorize 阶段规范化比较，Token 交换阶段严格字符串比较 |
| state 参数 | CSRF 防护 |

### 13.2 PASETO v4

| 特性 | 说明 |
|------|------|
| 无算法混淆 | PASETO 不允许选择算法，消除 JWT 的 `alg: none` 类攻击 |
| Ed25519 签名 | 非对称签名，公钥可公开分发 |
| AES-GCM 加密 Footer | 用户敏感信息加密存储在 Footer 中，需对称密钥解密 |
| 密钥轮换 | 支持域级别多密钥，平滑过渡 |

### 13.3 Cookie 安全

| Cookie | Secure | HttpOnly | SameSite | 用途 |
|--------|--------|----------|----------|------|
| aegis-session | ✅ | ✅ | None | AuthFlow 会话 |
| aegis-sso | ✅ | ✅ | Lax | SSO 会话 |

### 13.4 Token 安全

| 策略 | 说明 |
|------|------|
| Access Token 短 TTL | 默认 2 小时，不可吊销 |
| Refresh Token 可吊销 | 存 Redis，支持 Revoke |
| Refresh Token 数量上限 | 每用户每应用默认 10 个，超过则删除最旧的 |
| Footer 加密 | 用户信息使用 Service 对称密钥加密，只有目标服务可解密 |

### 13.5 访问控制

Aegis 内置两级访问控制机制（ACManager），适用于 Login 和 Challenge 流程：

| 决策 | 含义 | 触发条件 |
|------|------|---------|
| ACAllowed | 放行 | 验证尝试次数未达阈值 |
| ACCaptcha | 需要 captcha | 验证尝试次数达到 captcha 阈值 |

通过 Strike 机制统一记录每次验证尝试（不区分成功/失败），基于滑动窗口内的尝试次数进行决策。配置支持 per-connection / per-channelType 覆盖全局默认值。

### 13.6 Connection 安全

| 机制 | 说明 |
|------|------|
| 统一错误响应 | 系统账号（user/staff）认证失败不泄露具体原因 |
| 域隔离 | Consumer/Platform 分域，IDP 不可跨域 |
| Delegate 凭证 | ChallengeToken 5 分钟有效，一次性使用 |

---

## 14. 附录

### 附录 A: 错误码映射

| HTTP 状态码 | 错误码 | 说明 |
|-------------|--------|------|
| 400 | invalid_request | 请求参数错误 |
| 400 | client_not_found | 应用不存在 |
| 400 | service_not_found | 服务不存在 |
| 401 | invalid_credentials | 凭证无效 |
| 401 | invalid_token | Token 无效 |
| 403 | access_denied | 访问被拒 |
| 408 | flow_expired | Flow 已过期 |
| 409 | flow_invalid | Flow 状态非法 |
| 410 | invalid_grant | 授权码无效 |
| 412 | flow_not_found | Flow 不存在 |
| 428 | identity_required | 需要绑定身份 |
| 429 | rate_limited | 请求被限流 |
| 500 | server_error | 服务器错误 |

### 附录 B: Scope 定义

| Scope | 说明 | Token Footer 中包含 |
|-------|------|-------------------|
| openid | 必选，标识 OIDC 请求 | open_id |
| profile | 用户基本信息 | nickname, picture |
| email | 用户邮箱 | email |
| phone | 用户手机号 | phone |
| offline_access | 请求 Refresh Token | （控制是否签发 RT） |

### 附录 C: 多 Audience Token 请求示例

**authorization_code 交换**：

```json
POST /auth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "code": "AUTH_CODE_VALUE",
  "redirect_uri": "https://atlas.heliannuuthus.com/auth/callback",
  "client_id": "app_atlas",
  "code_verifier": "PKCE_VERIFIER_VALUE",
  "audiences": {
    "hermes": {
      "scope": "openid profile email offline_access"
    },
    "iris": {
      "scope": "openid profile"
    }
  }
}
```

**响应**：

```json
{
  "hermes": {
    "access_token": "v4.public.eyJpc3MiOiJhZWdpcyIsImF1ZCI6Imhlcm1lcyIs...",
    "refresh_token": "a1b2c3d4e5f6...",
    "token_type": "Bearer",
    "expires_in": 7200,
    "scope": "openid profile email offline_access"
  },
  "iris": {
    "access_token": "v4.public.eyJpc3MiOiJhZWdpcyIsImF1ZCI6ImlyaXMiLC...",
    "token_type": "Bearer",
    "expires_in": 7200,
    "scope": "openid profile"
  }
}
```

**refresh_token 刷新**：

```json
POST /auth/token
Content-Type: application/json

{
  "grant_type": "refresh_token",
  "refresh_token": "a1b2c3d4e5f6...",
  "client_id": "app_atlas",
  "audiences": {
    "hermes": {
      "scope": "openid profile email offline_access"
    },
    "iris": {
      "scope": "openid profile"
    }
  }
}
```

### 附录 D: 客户端集成架构

```
Atlas 前端                              Aegis 认证服务
(atlas.heliannuuthus.com)              (aegis.heliannuuthus.com)

┌─────────────────┐
│   AuthGuard     │  未登录
│   (路由守卫)     ├────────────────────────────────────────┐
│                 │  1. sessionStorage.setItem('auth_return_to')
└─────────────────┘  2. auth.authorize({ audience, scope })  │
                     3. window.location.href = authorize URL  │
                                                               ▼
                                                   ┌─────────────────┐
                                                   │  认证流程        │
                                                   │  (Aegis-UI)     │
                                                   └────────┬────────┘
                                                             │
┌─────────────────┐                                          │
│  /auth/callback  │◄────────────────────────────────────────┘
│  4. handleCallback(code, state)
│     a. consumeState() → 验证 CSRF
│     b. consumeCodeVerifier()
│     c. POST /auth/token (code + code_verifier)
│     d. 保存 token 到 localStorage
│  5. navigate(auth_return_to)
└────────┬────────┘
         │
┌────────▼────────┐
│   业务页面       │  已登录
│   使用 token     │  auth.isAuthenticated() → true
│   访问 API      │
└─────────────────┘
```

**SDK 存储布局（localStorage）**：

| Key | 用途 |
|-----|------|
| `aegis_access_token` | Access Token |
| `aegis_refresh_token` | Refresh Token |
| `aegis_expires_at` | Token 过期时间戳(ms) |
| `aegis_scope` | 授权的 scope |
| `aegis_code_verifier` | PKCE code_verifier（临时，读后即删） |
| `aegis_state` | CSRF state（临时，读后即删） |

### 附录 E: 关联文档

| 文档 | 说明 |
|------|------|
| [Connection 设计](aegis-connection-design.md) | Connection 设计模型、类型体系、客户端集成 |
| [Challenge 设计](challenge-design.md) | Challenge 服务、三层模型、访问控制 |
| [Challenge API](challenge-api.md) | Challenge API 端点详细定义 |
| [MFA 编排设计](mfa-orchestration-design.md) | MFA 风险评估与编排 |
| [WebAuthn 登录](webauthn-login.md) | WebAuthn/Passkey 登录流程 |

---

> **文档结束** — 覆盖了 Aegis 认证授权系统的完整设计，包括 OAuth 2.1 授权码流程、AuthFlow 状态机、Token 体系（PASETO v4）、多 Audience 授权、SSO 机制、中间件、安全设计等全部核心内容。

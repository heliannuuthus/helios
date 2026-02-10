# Aegis Connection 设计与实现文档

> 涵盖：Connection 设计模型、数据结构、认证流程、API 端点、Authenticator 注册与分发机制
> 更新日期：2026-02-10

---

## 目录

1. [概述](#1-概述)
2. [核心数据结构](#2-核心数据结构)
3. [Connection 类型体系](#3-connection-类型体系)
4. [API 端点与路由注册](#4-api-端点与路由注册)
5. [认证流程完整调用链](#5-认证流程完整调用链)
6. [各端点详细调用栈分析](#6-各端点详细调用栈分析)
7. [Connection 相关的基础设施连接](#7-connection-相关的基础设施连接)
8. [Authenticator 注册与分发机制](#8-authenticator-注册与分发机制)
9. [缓存与状态管理](#9-缓存与状态管理)
10. [错误处理体系](#10-错误处理体系)
11. [安全机制与设计要点](#11-安全机制与设计要点)
12. [附录](#12-附录)

---

## 1. 概述

Helios 项目中的 "Connection" 是认证系统（Aegis 模块）的核心概念，代表一种**认证方式/身份提供商**的抽象。Connection 机制统一管理了三大类认证方式：

| 类别 | 缩写 | 含义 | 示例 |
|------|------|------|------|
| **IDP** | Identity Provider | 身份提供商 | github, google, wechat-mp, user, oper, passkey |
| **VChan** | Verification Channel | 验证渠道/前置验证 | captcha |
| **MFA** | Multi-Factor Auth | 多因素认证 | email-otp, totp, webauthn |

整个认证流程遵循 **OAuth 2.1 + PKCE** 标准，使用 **PASETO v4** 代替 JWT 进行 Token 签发。

### Connection 设计模型

Connection 体系由三个维度定义：

- **connection** = 身份提供商/验证类型。不同的后端集成即不同的 connection。
  - IDP: `user`, `oper`, `github`, `google`, `wechat-mp`, `tt-mp`, `alipay-mp`, `passkey`, `wecom`...
  - VChan: `captcha`
  - MFA: `email-otp`, `totp`, `webauthn`
- **strategy** = 同一 connection 下的可选认证方式。
  - `user`/`oper`: `password` / `webauthn`
  - `captcha`: `turnstile`（可扩展 `recaptcha` / `hcaptcha`）
  - 其余 connection 验证方式唯一，不需要 strategy
  - 注意：`email-otp` 不是 strategy，只能通过 `delegate` 关联作为 MFA
- **channel** = 接入渠道（mp/web/oa），编码在 connection 名字里而非作为独立字段
  - 例如 `wechat-mp` 中的 `mp` 即微信小程序渠道

### 架构层次

```
main.go (路由注册)
    |
Handler (aegis/handler.go) - 编排层
    |
authenticate.Service | authorize.Service | challenge.Service
    |
authenticator.Registry (全局注册表)
    |
IDPAuthenticator | VChanAuthenticator | MFAAuthenticator (胶水层)
    |
idp.Provider | captcha.Verifier | mfa.Provider (底层实现)
    |
cache.Manager (本地缓存 + Redis)
    |
hermes.Service / hermes.UserService (DB)
```

---

## 2. 核心数据结构

### 2.1 ConnectionConfig

**文件：** `internal/aegis/types/authflow.go:265-274`

返回给前端的公开配置，统一结构适用于 IDP、VChan 和 MFA。

- `Connection` (string): 唯一标识（如 github, captcha, email-otp）
- `Identifier` (string): 公开标识（client_id / site_key / rp_id）
- `Strategy` ([]string): 认证方式（user/oper: password, webauthn; captcha: turnstile; 其余忽略）
- `Delegate` ([]string): 委托验证/MFA（totp, email-otp），登录后需完成其中一种
- `Require` ([]string): 前置验证（captcha），登录前必须全部通过
- `Verified` (bool): 在 AuthFlow 中动态标记是否已验证

### 2.2 ConnectionsMap

**文件：** `internal/aegis/types/authflow.go:282-287`

按类别分类的响应：IDP 列表、VChan 列表、MFA 列表。

### 2.3 AuthFlow

**文件：** `internal/aegis/types/authflow.go:26-54`

认证流程上下文，存储在 Redis 中，包含：
- 基本信息：ID, 创建时间, 过期时间（滑动窗口+绝对上限）
- 状态：initialized / authenticated / authorized / completed / failed
- 请求参数：AuthRequest（OAuth2 标准参数 + OIDC 扩展）
- 实体信息：Application, Service, User
- **Connection 配置：ConnectionMap（所有可用配置）, Connection（当前验证的）**
- 认证结果：Identities（用户身份列表）, UserInfoMap
- 授权结果：GrantedScopes
- 错误：FlowError

**Flow 状态机：**
```
initialized -> authenticated -> authorized -> completed
     |                                            |
     +----------------- failed <------------------+
```

### 2.4 LoginRequest

**文件：** `internal/aegis/types.go:32-45`

- `Connection` (string, 必填): 身份标识
- `Strategy` (string): 认证方式（user/oper: password/webauthn; captcha: turnstile; 其余忽略）
- `Principal` (string): 身份主体（用户名/邮箱/手机号）
- `Proof` (any): 凭证证明（password/OTP/OAuth code/WebAuthn assertion 等）

### 2.5 Authenticator 接口

**文件：** `internal/aegis/authenticator/registry.go:13-26`

统一认证器接口：
- `Type() string`: 返回类型标识
- `Prepare() *ConnectionConfig`: 返回前端公开配置
- `Authenticate(ctx, flow, params...) (bool, error)`: 执行认证

---

## 3. Connection 类型体系

### 3.1 IDP Connection 类型

**文件：** `internal/aegis/authenticator/idp/types.go`

types.go 中定义了全部常量，但并非每个都有 Provider 实现。下表标注了实际状态：

| 常量 | 值 | 域 | 说明 | 实现状态 |
|------|------|------|------|----------|
| TypeWechatMP | wechat-mp | CIAM | 微信小程序 | 已实现 (wechat/mp.go) |
| TypeTTMP | tt-mp | CIAM | 抖音小程序 | 已实现 (tt/mp.go) |
| TypeAlipayMP | alipay-mp | CIAM | 支付宝小程序 | 已实现 (alipay/mp.go + common.go) |
| TypeWechatWeb | wechat-web | CIAM | 微信网页授权 | 仅定义常量，无 Provider 实现 |
| TypeAlipayWeb | alipay-web | CIAM | 支付宝网页授权 | 仅定义常量，无 Provider 实现 |
| TypeTTWeb | tt-web | CIAM | 抖音网页授权 | 仅定义常量，无 Provider 实现 |
| TypeUser | user | CIAM | C端用户账号密码 | 已实现 (system/provider.go) |
| TypeWecom | wecom | PIAM | 企业微信 | 仅定义常量，无 Provider 实现 |
| TypeGithub | github | PIAM | GitHub | 已实现 (github/provider.go) |
| TypeGoogle | google | PIAM | Google | 已实现 (google/provider.go) |
| TypeOper | oper | PIAM | 运营人员账号密码 | 已实现 (system/provider.go) |
| TypePasskey | passkey | 通用 | Passkey/WebAuthn 无密码登录 | 已实现 (passkey/provider.go) |
| TypeGlobal | global | 系统 | 全局身份（每域一个，作为 sub） | 非认证用，无 Provider |

**实际注册到 Registry 的 IDP（init.go）：** wechat-mp, tt-mp, alipay-mp, github, google, user, oper, passkey（共 8 个）

域划分由配置 `identity.ciam-idps` / `identity.piam-idps` 决定。

### 3.2 VChan Connection 类型

| 标识 | 说明 | 实现状态 |
|------|------|----------|
| captcha | 人机验证 | 已实现（当前实现为 Cloudflare Turnstile，strategy: turnstile） |

> captcha 是 connection，具体 provider（turnstile/recaptcha/hcaptcha）作为 strategy 配置。

### 3.3 MFA Connection 类型

**文件：** `internal/aegis/authenticator/mfa/provider.go`

| 常量 | 值 | 说明 |
|------|------|------|
| TypeEmailOTP | email-otp | 邮件验证码 |
| TypeTOTP | totp | 时间动态口令 |
| TypeWebAuthn | webauthn | WebAuthn/FIDO2 |

---

## 4. API 端点与路由注册

**文件：** `main.go:101-119`

### 认证相关路由 (/auth/*)

| 方法 | 路径 | Handler | 中间件 | 说明 |
|------|------|---------|--------|------|
| POST | /auth/authorize | Authorize | aegisCORS | 创建认证会话 |
| GET | /auth/connections | GetConnections | aegisCORS | 获取可用 Connection 配置 |
| GET | /auth/context | GetContext | aegisCORS | 获取认证流程上下文 |
| POST | /auth/login | Login | aegisCORS | 使用 Connection 登录 |
| POST | /auth/challenge | InitiateChallenge | aegisCORS | 发起 Challenge |
| PUT | /auth/challenge | ContinueChallenge | aegisCORS | 继续 Challenge |
| POST | /auth/token | Token | 无 | 换取 Token |
| POST | /auth/revoke | Revoke | 无 | 撤销 Token |
| POST | /auth/check | Check | 无 | 关系权限检查（CAT认证） |
| POST | /auth/logout | Logout | RequireToken | 登出 |
| GET | /auth/pubkeys | PublicKeys | 无 | 获取 PASETO 公钥 |

---

## 5. 认证流程完整调用链

### 标准 OAuth 2.1 + PKCE 登录流程

```
客户端                    Aegis (Helios)                    前端 (Aegis UI)

1. POST /auth/authorize
   (client_id, audience,
    redirect_uri, PKCE)
   =========================>
                              创建 AuthFlow
                              设置 Cookie (aegis-session)
                              302 重定向到登录页
                              ===============================>

                              2. GET /auth/connections
                              <===============================
                              返回 ConnectionsMap (idp/vchan/mfa)
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
                              返回 { code, redirect_uri }
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

---

## 6. 各端点详细调用栈分析

### 6.1 POST /auth/authorize - 创建认证会话

入口: `Handler.Authorize()` (internal/aegis/handler.go:109)

```
Handler.Authorize(c)
  |-- c.ShouldBind(&req)                        // 绑定 AuthRequest
  |-- authenticateSvc.CreateFlow(c, &req)        // 创建认证流程
  |   |-- 验证 response_type == "code"
  |   |-- cache.GetApplication(ctx, clientID)    // 查询应用(本地缓存->hermes DB)
  |   |   \-- hermesSvc.GetApplicationWithKey()
  |   |-- app.ValidateRedirectURI(redirectURI)   // 验证重定向 URI
  |   |-- cache.GetService(ctx, audience)        // 查询服务
  |   |   \-- hermesSvc.GetServiceWithKey()
  |   |-- cache.CheckAppServiceRelation()         // 验证应用-服务关系
  |   |   \-- hermesSvc.CheckRelation()
  |   |-- cache.GetApplicationIDPConfigs()        // 获取应用 IDP 配置
  |   |   \-- hermesSvc.GetApplicationIDPConfigs()
  |   |-- types.NewAuthFlow(req, ttl, maxLifetime)  // 创建 AuthFlow
  |   |-- s.setConnections(idpConfigs)            // [关键] 构建 ConnectionMap
  |   |   |-- 遍历每个 ApplicationIDPConfig
  |   |   |-- authenticator.GlobalRegistry().Get(idpCfg.Type)  // 全局注册表
  |   |   |-- auth.Prepare()                      // 基础 ConnectionConfig
  |   |   \-- 合并应用级配置(strategy, delegate, require)
  |   \-- s.SaveFlow(ctx, flow)                   // 保存到 Redis
  |-- setAuthSessionCookie(c, flow.ID)           // 设置 Cookie
  \-- forwardNext(c, flow)                       // 重定向到登录页
```

关键点：
- `setConnections` 是 ConnectionMap 的唯一构建入口
- 将 Authenticator.Prepare() 基础配置与应用级 IDP 配置合并
- Cookie: SameSite=None + Secure=true（跨站 OAuth 场景）

### 6.2 GET /auth/connections - 获取可用 Connection 配置

入口: `Handler.GetConnections()` (internal/aegis/handler.go:185)

```
Handler.GetConnections(c)
  |-- getAuthSessionCookie(c)                     // 从 Cookie 获取 flowID
  |-- authenticateSvc.GetAndValidateFlow(ctx, flowID)
  |   |-- s.GetFlow(ctx, flowID)                 // Redis GET + json.Unmarshal
  |   |-- flow.IsMaxExpired()                    // 绝对过期检查
  |   |-- flow.IsExpired()                       // 滑动窗口过期检查
  |   \-- s.RenewFlow(flow)                     // 内存中续期
  |-- authenticateSvc.SaveFlow(ctx, flow)         // 持久化续期
  |-- authenticateSvc.GetAvailableConnections(flow)  // [关键] 构建 ConnectionsMap
  |   |-- 遍历 flow.ConnectionMap
  |   |   |-- 收集所有 IDP ConnectionConfig
  |   |   |-- 收集所有 Delegate -> mfaSet (去重)
  |   |   \-- 收集所有 Require -> vchanSet (去重)
  |   |-- resolveVChanConfigs(vchanSet)
  |   |   |-- GlobalRegistry().Get(conn) -> auth.Prepare()
  |   |   \-- 兼容 "captcha" 前缀匹配
  |   \-- resolveMFAConfigs(mfaSet)
  |       \-- GlobalRegistry().Get(conn) -> auth.Prepare()
  \-- c.JSON(200, connectionsMap)
```

返回示例:
```json
{
  "idp": [
    {"connection":"user","strategy":["password","webauthn"],"delegate":["totp"],"require":["captcha"]},
    {"connection":"github","identifier":"Iv1.abc123..."},
    {"connection":"wechat-mp","identifier":"wx1234567890"}
  ],
  "vchan": [
    {"connection":"captcha","identifier":"0x4AAAAAAA...","strategy":["turnstile"]}
  ],
  "mfa": [
    {"connection":"email-otp"},
    {"connection":"totp"}
  ]
}
```

### 6.3 POST /auth/login - 使用 Connection 登录

入口: `Handler.Login()` (internal/aegis/handler.go:276)

```
Handler.Login(c)
  |-- c.ShouldBindJSON(&req)                      // LoginRequest
  |-- getAuthSessionCookie(c)                      // flowID
  |-- authenticateSvc.GetAndValidateFlow(ctx, flowID)
  |-- defer h.authenticateSvc.CleanupFlow(...)     // 清理函数
  |   |-- success -> DeleteFlow (Redis DEL)
  |   \-- failure -> SaveFlow (保留供重试)
  |
  |-- authenticator.GlobalRegistry().Has(req.Connection)  // [关键] 验证 Connection
  |-- flow.SetConnection(req.Connection)
  |
  |-- authenticateSvc.Authenticate(ctx, flow, proof, principal, strategy, remoteIP)  // [关键] 执行认证
  |   |-- flow.CanAuthenticate()
  |   |-- GlobalRegistry().Get(flow.Connection)     // 按 connection 查找
  |   \-- auth.Authenticate(ctx, flow, params...)   // 透传分发到具体实现
  |       |
  |       |-- [IDP] IDPAuthenticator.Authenticate()
  |       |   |-- provider.Login(ctx, proof, extraParams...)
  |       |   |   |-- [github]    -> getAccessToken() + getUserInfo() + getPrimaryEmail()
  |       |   |   |-- [google]    -> getAccessToken() + getUserInfo()
  |       |   |   |-- [wechat-mp] -> 微信 jscode2session API
  |       |   |   |-- [tt-mp]     -> sendSessionRequest()
  |       |   |   |-- [alipay-mp] -> sendOAuthRequest() (RSA2签名+验签)
  |       |   |   |-- [user/oper] -> login() bcrypt 密码验证
  |       |   |   \-- [passkey]   -> webauthnSvc.FinishLogin()
  |       |   |-- userInfo.ToUserIdentity(domain, connection)
  |       |   |-- flow.AddIdentity(identity, userInfo)
  |       |   \-- connCfg.Verified = true
  |       |
  |       |-- [VChan] VChanAuthenticator.Authenticate()
  |       |   |-- verifier.Verify(ctx, proof, remoteIP)
  |       |   |   \-- [turnstile] -> POST Cloudflare siteverify API
  |       |   \-- connCfg.Verified = true
  |       |
  |       \-- [MFA] MFAAuthenticator.Authenticate()
  |           |-- provider.Verify(ctx, proof, extraParams...)
  |           |   |-- [email-otp] -> cache.GetOTP("email-otp:"+challengeID) 比对
  |           |   |-- [totp]      -> totp.Verifier.Verify(userID, code) (via credentialSvc)
  |           |   \-- [webauthn]  -> webauthnSvc.FinishLogin() + UpdateCredentialSignCount()
  |           \-- connCfg.Verified = true
  |
  |-- flow.AllRequiredVerified()                   // 检查前置验证
  |   \-- 遍历 connCfg.Require, 每个 Verified==true
  |-- flow.AnyDelegateVerified()                   // 检查委托验证
  |   \-- 遍历 connCfg.Delegate, 任一 Verified==true
  |
  |   [未全部通过] -> 返回 200 + {"status":"pending"}
  |
  |-- h.resolveUser(ctx, flow)                     // 查找或创建用户
  |   |-- flow.GetIdentity(connection)
  |   |-- userSvc.GetIdentities(ctx, identity)     // DB 查询全部身份
  |   |-- [不存在]
  |   |   |-- idp.IsIDPAllowedForDomain()          // 检查注册权限
  |   |   \-- userSvc.CreateUser()                 // 创建用户
  |   |-- userSvc.GetUser(ctx, uid)
  |   \-- flow.SetAuthenticated(user)
  |
  |-- h.completeLoginFlow(ctx, flow)               // 完成流程
  |   |-- authorizeSvc.PrepareAuthorization(ctx, flow)
  |   |   |-- checkIdentityRequirements()          // 检查身份要求
  |   |   |-- 解析/计算 scope 交集
  |   |   \-- flow.SetAuthorized(grantedScopes)
  |   |-- authorizeSvc.GenerateAuthCode(ctx, flow)
  |   |   |-- GenerateAuthorizationCode() (32位 Base62)
  |   |   |-- cache.SaveAuthCode (5分钟 TTL)
  |   |   \-- flow.SetCompleted()
  |   \-- authenticateSvc.SaveFlow()
  |
  |-- loginSuccess = true
  |-- clearAuthSessionCookie(c)
  \-- c.JSON(200, LoginResponse{Code, RedirectURI})
```

关键逻辑：
1. Connection 验证分两层：GlobalRegistry().Has() 检查系统支持 + flow.ConnectionMap 检查应用配置
2. 前置验证 (Require): 前端需先调用 /auth/login 传入 VChan connection
3. 委托验证 (Delegate): IDP 登录后需 MFA，只需任一通过

### 6.4 POST /auth/challenge - 发起 Challenge

入口: `Handler.InitiateChallenge()` (internal/aegis/handler.go:215)

```
Handler.InitiateChallenge(c)
  |-- c.ShouldBindJSON(&req)  // type: captcha/email-otp/totp
  |-- c.ClientIP()
  \-- challengeSvc.Create(ctx, &req, remoteIP)
      |-- [需 captcha 前置 & 无 token]
      |   \-- createChallengeWithCaptchaRequired()
      |       |-- 创建 pending Challenge (pending_captcha=true)
      |       |-- cache.SaveChallenge()
      |       \-- 返回 { challenge_id, required: {connection, identifier} }
      |
      |-- [需 captcha 前置 & 有 token]
      |   \-- captcha.Verify(ctx, token, remoteIP)
      |
      |-- [type=captcha] -> createCaptchaChallenge()
      |   |-- NewChallenge(5min TTL)
      |   \-- 返回 { challenge_id, type, expires_in, data:{site_key} }
      |
      |-- [type=totp] -> createTOTPChallenge()
      |   |-- NewChallenge(5min TTL) + SetData("user_id")
      |   \-- 返回 { challenge_id, type, expires_in }
      |
      \-- [type=email-otp] -> createEmailOTPChallenge()
          |-- NewChallenge(5min TTL) + SetData("email")
          |-- sendOTP()
          |   \-- EmailOTPProvider.SendOTP()
          |       |-- GenerateOTP(6)
          |       |-- cache.SaveOTP("email-otp:"+challengeID, code)
          |       \-- emailSender.SendCode()  // SMTP
          \-- 返回 { challenge_id, type, expires_in, data:{masked_email} }
```

### 6.5 PUT /auth/challenge - 继续 Challenge

入口: `Handler.ContinueChallenge()` (internal/aegis/handler.go:241)

```
Handler.ContinueChallenge(c)
  |-- c.Query("challenge_id")
  |-- c.ShouldBindJSON(&req)  // proof
  \-- challengeSvc.Verify(ctx, challengeID, &req, remoteIP)
      |-- cache.GetChallenge()
      |-- challenge.IsExpired()
      |
      |-- [pending_captcha=true]
      |   |-- verifyCaptcha() -> captcha.Verify()
      |   \-- continueAfterCaptcha()
      |       |-- [email-otp] -> sendOTP() -> 发送邮件
      |       \-- 返回 { challenge_id, data:{next:"email-otp"} }
      |
      |-- [type=captcha]
      |   \-- verifyCaptcha() -> TurnstileVerifier.Verify() -> Cloudflare API
      |
      \-- [type=totp/email-otp/webauthn]
          \-- verifyWithProvider()
              |-- [totp]      -> TOTPProvider.Verify(proof, userID)
              |-- [email-otp] -> EmailOTPProvider.Verify(proof, challengeID)
              \-- [webauthn]  -> WebAuthnProvider.Verify(proof, httpRequest)
```

### 6.6 POST /auth/token - 换取 Token

入口: `Handler.Token()` (internal/aegis/handler.go:437)

```
Handler.Token(c)
  |-- c.ShouldBind(&req)  // TokenRequest
  \-- authorizeSvc.ExchangeToken(ctx, &req)
      |
      |-- [grant_type=authorization_code]
      |   \-- exchangeAuthorizationCode()
      |       |-- cache.GetAuthCode(ctx, code)
      |       |-- cache.GetAuthFlow(ctx, flowID)
      |       |-- 验证 client_id, redirect_uri
      |       |-- verifyCodeChallenge(S256, challenge, verifier)  // PKCE
      |       |-- cache.MarkAuthCodeUsed()
      |       \-- generateTokens()
      |           |-- getSub(identities, domainID)  // 获取 sub
      |           |-- generateAccessToken()
      |           |   |-- token.NewClaimsBuilder()...Build(UAT)
      |           |   \-- tokenSvc.Issue()  // PASETO v4 签发
      |           \-- [scope含offline_access]
      |               \-- createRefreshToken()
      |                   |-- cleanupOldRefreshTokens() // 限制数量
      |                   \-- cache.SaveRefreshToken()
      |
      \-- [grant_type=refresh_token]
          \-- refreshToken()
              |-- cache.GetRefreshToken()
              |-- 验证 client_id
              |-- 获取 user/app/service
              \-- generateAccessToken()  // 只刷新 access_token
```

### 6.7 POST /auth/check - 关系权限检查

```
Handler.Check(c)
  |-- Authorization header -> CAT
  |-- tokenSvc.VerifyCAT(ctx, cat)
  |-- c.ShouldBindJSON(&req)  // CheckRequest
  \-- authorizeSvc.CheckRelation(ctx, serviceID, subjectID, relation, objectType, objectID)
      |-- cache.ListRelationships(ctx, serviceID, "user", subjectID)
      \-- 遍历匹配 relation + objectType + objectID
```

### 6.8 POST /auth/logout - 登出

```
Handler.Logout(c)
  |-- GetToken(c)  // 从中间件获取已验证的 Token
  |-- getInternalUID(claims)
  \-- authorizeSvc.RevokeAllTokens(ctx, userID)
      \-- cache.RevokeUserRefreshTokens()
```

---

## 7. Connection 相关的基础设施连接

### 7.1 MySQL 数据库连接

**文件：** `pkg/database/database.go`, `internal/database/database.go`

| 数据源 | 变量 | 用途 |
|--------|------|------|
| zweiDB | 业务数据库 | 菜谱、收藏、历史等 |
| hermesDB | IAM 数据库 | 用户、身份、应用、服务、关系等 |

连接池默认: maxIdleConns=10, maxOpenConns=30, connMaxLifetime=1h, connMaxIdleTime=30min

调用链: `config.Load() -> database.Init() -> pkgdb.Connect(dsn) -> gorm.Open(mysql) -> 配置连接池`

### 7.2 Redis 连接

**文件：** `internal/aegis/init.go:36-41`

`Initialize() -> pkgstore.NewGoRedisClient(GoRedisConfig{Host,Port,Password,DB})`

用途: AuthFlow 存储/续期, 授权码存储, Refresh Token 存储, OTP 验证码, Challenge 会话

### 7.3 SMTP 邮件连接

**文件：** `pkg/mail/sender.go`（Sender 封装）, `pkg/mail/client.go`（底层 SMTP Client）

```
initMailSender() (init.go:265)
  -> mail.NewSender(SenderConfig{Host, Port, Username, Password, UseSSL})
    -> sender.Verify()                // 验证 SMTP 连接
      -> Client.dial()               // TCP/TLS 连接
      -> smtp.NewClient()
      -> client.Hello("localhost")
      -> [STARTTLS] client.StartTLS()
      -> client.Auth(PlainAuth)
      -> client.Quit()
```

实际发送邮件时调用链: `EmailOTPProvider.SendOTP() -> emailSender.SendCode() -> Client.Send() -> setupConnection() + sendEnvelope() + sendContent()`

### 7.4 外部 HTTP 连接

| 连接目标 | 触发 Connection | 文件 |
|----------|----------------|------|
| Cloudflare Turnstile siteverify API | captcha | authenticator/captcha/turnstile.go |
| 微信小程序 jscode2session + getuserphonenumber | wechat-mp | authenticator/idp/wechat/mp.go |
| 抖音小程序 jscode2session + getphonenumber | tt-mp | authenticator/idp/tt/mp.go |
| 支付宝小程序 OAuth (RSA2 签名) | alipay-mp | authenticator/idp/alipay/mp.go + common.go |
| GitHub OAuth token + user API + emails API | github | authenticator/idp/github/provider.go |
| Google OAuth token + userinfo API | google | authenticator/idp/google/provider.go |

---

## 8. Authenticator 注册与分发机制

### 8.1 全局注册表初始化

**文件：** `internal/aegis/init.go:125-176`

```
initRegistry()
  |-- authenticator.NewRegistry()
  |
  |-- === IDP Authenticators (共 8 个，全部有实际 Provider 实现) ===
  |-- register(IDPAuthenticator(wechat.NewMPProvider()))     -> "wechat-mp"
  |-- register(IDPAuthenticator(tt.NewMPProvider()))          -> "tt-mp"
  |-- register(IDPAuthenticator(alipay.NewMPProvider()))      -> "alipay-mp"
  |-- register(IDPAuthenticator(github.NewProvider()))        -> "github"
  |-- register(IDPAuthenticator(google.NewProvider()))        -> "google"
  |-- register(IDPAuthenticator(user.NewProvider()))           -> "user" [需 userSvc != nil]
  |-- register(IDPAuthenticator(oper.NewProvider()))           -> "oper" [需 userSvc != nil]
  |-- register(IDPAuthenticator(passkey.NewProvider()))       -> "passkey" [需 webauthnSvc != nil]
  |
  |-- === VChan Authenticators ===
  |-- register(VChanAuthenticator(captchaVerifier))           -> "captcha" [需 captcha 配置启用, strategy: turnstile]
  |
  |-- === MFA Authenticators ===
  |-- register(MFAAuthenticator(EmailOTPProvider))            -> "email-otp" [需 mfa.email-otp.enabled + emailSender]
  |-- register(MFAAuthenticator(TOTPProvider))                -> "totp" [需 mfa.totp.enabled + totpVerifier]
  \-- register(MFAAuthenticator(WebAuthnProvider))            -> "webauthn" [需 mfa.webauthn.enabled + webauthnSvc]
```

### 8.2 三层认证器架构

```
Authenticator 接口 (统一)
  Type() / Prepare() / Authenticate()
  |
  |-- IDPAuthenticator (胶水层) -> idp.Provider 接口 -> Login() / Prepare()
  |-- VChanAuthenticator (胶水层) -> captcha.Verifier 接口 -> Verify() / GetIdentifier()
  \-- MFAAuthenticator (胶水层) -> mfa.Provider 接口 -> Verify() / Prepare()
```

### 8.3 分发流程

```
handler.Login() 解包 LoginRequest:
  // proof 保持 any 类型，由各 authenticator 内部自行断言
  authenticateSvc.Authenticate(ctx, flow, req.Proof, req.Principal, req.Strategy, c.ClientIP())

authenticateSvc.Authenticate(ctx, flow, params...)  // service 透传
  |-- flow.CanAuthenticate()
  |-- GlobalRegistry().Get(connection)
  \-- auth.Authenticate(ctx, flow, params...)       // 各 authenticator 按需取值
      |-- IDP:   provider.Login(ctx, proof, extraParams...)  -> flow.AddIdentity() + Verified=true
      |-- VChan: verifier.Verify(ctx, proof, remoteIP)       -> Verified=true
      \-- MFA:   provider.Verify(ctx, proof, extraParams...)  -> Verified=true
```

---

## 9. 缓存与状态管理

### 9.1 本地缓存（Ristretto）

**文件：** `internal/aegis/cache/manager.go`

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

### 9.2 Redis 数据

前缀可通过配置 `aegis.cache.{type}.prefix` 自定义，以下为默认值（定义在 `internal/config/aegis.go`）：

| Key 格式 | 用途 | TTL |
|----------|------|-----|
| auth:flow:{flowID} | AuthFlow 序列化 | 滑动窗口+绝对过期 |
| auth:code:{code} | 授权码 | 5 分钟 |
| auth:rt:{token} | Refresh Token | 可配置(默认365天) |
| auth:user:rt:{userID} | 用户 Refresh Token 集合 (Redis Set) | 跟随 RT 过期 |
| auth:ch:{challengeID} | Challenge 会话 | 5 分钟 |
| auth:otp:email-otp:{challengeID} | Email OTP 验证码 | 5 分钟 |

### 9.3 AuthFlow 生命周期

```
创建 -> SaveFlow (Redis SET + TTL)
  |
GetAndValidateFlow -> GetFlow (Redis GET) -> 检查过期 -> RenewFlow -> SaveFlow
  |
[成功] CleanupFlow -> DeleteFlow (Redis DEL)
[失败] CleanupFlow -> SaveFlow (保留供重试)
```

滑动窗口续期: 每次访问 Flow 都会续期 ExpiresAt，但不超过 MaxExpiresAt 绝对上限。

---

## 10. 错误处理体系

**文件：** `internal/aegis/errors/errors.go`

### Connection 相关错误码

| HTTP | 错误码 | 说明 | 触发场景 |
|------|--------|------|----------|
| 422 | no_connection_available | 无可用 Connection | 应用未配置 IDP |
| 422 | identity_required | 需要绑定身份 | 服务要求特定身份 |
| 400 | invalid_request | 请求参数错误 | 不支持的 Connection |
| 401 | invalid_credentials | 凭证无效 | 密码/OTP 错误 |
| 412 | flow_not_found | Flow 不存在 | Cookie 丢失 |
| 412 | flow_expired | Flow 已过期 | 超过最大生命周期 |
| 412 | flow_invalid | Flow 状态非法 | 状态不允许认证 |
| 400 | client_not_found | 应用不存在 | client_id 无效 |
| 400 | service_not_found | 服务不存在 | audience 无效 |
| 403 | access_denied | 访问被拒 | 应用无权访问服务 |
| 500 | server_error | 服务器错误 | IDP 调用失败等 |

错误响应格式: `{"error":"code","error_description":"...","data":{...}}`

---

## 11. 安全机制与设计要点

### 11.1 OAuth 2.1 + PKCE

- 强制 S256 Code Challenge Method（不允许 plain）
- Token 交换必须提供 code_verifier
- 授权码一次性使用 (MarkAuthCodeUsed)

### 11.2 Session Cookie

- Secure=true (仅 HTTPS)
- HttpOnly=true (防 XSS)
- SameSite=None (跨站 OAuth)

### 11.3 Token

- PASETO v4 (无算法混淆风险)
- Access Token 短 TTL (默认2h), 不可吊销
- Refresh Token 存 Redis, 可吊销, 数量上限 (默认10个)

### 11.4 Connection 安全

- 系统账号(user/oper)错误不泄露具体原因(统一返回 "authentication failed")
- Captcha 前置验证: 高风险操作需先通过人机验证
- MFA 委托验证: IDP 登录后可配置二次验证
- 域隔离: CIAM/PIAM 分域, IDP 不可跨域

### 11.5 密码学

- 敏感字段加密存储 (AES-GCM)
- Token 签名 Ed25519, 支持密钥轮换
- Footer 中加密存储内部 UID

### 11.6 Refresh Token 清理

配置 `aegis.max-refresh-token` (默认10), 超出时删除最旧的 token。

---

## 12. 附录

### 附录 A: ConnectionMap 生成流程

```
数据库 (t_application_idp_config)
  | GetApplicationIDPConfigs(clientID)
  V
[]*ApplicationIDPConfig (Type, Strategy, Delegate, Require)
  | setConnections()
  | 1. GlobalRegistry().Get(type) -> Authenticator
  | 2. auth.Prepare() -> 基础 ConnectionConfig
  | 3. 合并应用级配置
  V
map[string]*ConnectionConfig
  | GetAvailableConnections()
  V
ConnectionsMap
  |-- IDP:   直接来自 ConnectionMap
  |-- VChan: 从所有 IDP 的 Require 收集 -> Registry 解析
  \-- MFA:   从所有 IDP 的 Delegate 收集 -> Registry 解析
```

### 附录 B: Wire 初始化链

```
main.go -> InitializeApp() (wire_gen.go)
  |-- provideHermesService() -> hermes.NewService(hermesDB)
  |-- provideAegisHandler(hermesSvc)
  |   \-- aegis.Initialize(hermesSvc, userSvc, credentialSvc)
  |       |-- NewGoRedisClient()        // Redis
  |       |-- cache.NewManager()        // Ristretto + Redis
  |       |-- token.NewService()
  |       |-- mail.NewSender() [可选]
  |       |-- initProviders()           // WebAuthn + Captcha + TOTP
  |       |-- initRegistry()            // 注册所有 Authenticator
  |       |-- user/authenticate/authorize/challenge NewService()
  |       \-- NewHandler(所有服务)
  |-- provideIrisHandler(aegisHandler)
  |-- provideInterpreter()
  \-- provideGinMiddlewareFactory()
```

### 附录 C: 认证状态转换详图

```
                    initialized
                        |
         +--------------+--------------+
         |              |              |
    [VChan Login]  [IDP Login]   [MFA Login]
    captcha验证     身份登录      MFA验证
         |              |              |
         Verified       Verified       Verified
         =true          =true          =true
         |              |              |
         +--------------+--------------+
                        |
               AllRequiredVerified?
               AnyDelegateVerified?
                        |
              +---------+---------+
              | No                | Yes
              | pending           |
              | (等待更多验证)    V
              |            resolveUser()
              |                   |
              |            authenticated
              |                   |
              |         PrepareAuthorization()
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

> **文档结束** - 覆盖了 Helios 中所有 Connection 相关的请求路径、数据结构、代码调用栈、认证分发机制、缓存策略及安全设计。

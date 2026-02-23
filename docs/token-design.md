# Aegis Token 设计文档

## 1. 概述

Aegis 使用 **PASETO v4 Public Token**（Ed25519 签名）作为统一凭证格式，定义了 5 种 Token 类型：

| 类型 | 标识 | 用途 | 签发方 | 验证方 | Footer |
|------|------|------|--------|--------|--------|
| CAT | `cat` | 客户端自签发凭证 | 应用 | Aegis | 无 |
| UAT | `uat` | 用户访问令牌 | Aegis | 应用 | 有（加密） |
| SAT | `sat` | 服务访问令牌（M2M） | Aegis | 应用 | 无 |
| XAT | `challenge` | 验证挑战令牌 | Aegis | Aegis | 无 |
| SSO | `sso` | 单点登录会话（内部） | Aegis | Aegis | 有（加密） |

---

## 2. PASETO Token 格式

### 2.1 结构

```
v4.public.<payload>.<footer>
```

| 部分 | 说明 |
|------|------|
| `v4` | PASETO 版本 |
| `public` | 公钥签名模式（Ed25519） |
| `payload` | Base64URL(claims_json + signature) |
| `footer` | 可选，Base64URL(附加数据) |

### 2.2 通用 Claims

所有 Token 共享的标准字段：

```json
{
  "iss": "string",
  "aud": "string",
  "sub": "string",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-01T01:00:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "string"
}
```

| Claim | 类型 | 说明 |
|-------|------|------|
| `iss` | string | 签发者 |
| `aud` | string | 目标受众 |
| `sub` | string | 主体（可选） |
| `iat` | RFC3339 | 签发时间 |
| `exp` | RFC3339 | 过期时间 |
| `nbf` | RFC3339 | 生效时间 |
| `jti` | string | Token ID（16 字节随机 hex） |

### 2.3 扩展 Claims

| Claim | 使用者 | 说明 |
|-------|--------|------|
| `cli` | UAT, SAT, XAT | 应用 ID |
| `scope` | UAT, SAT | 授权范围（空格分隔） |
| `typ` | XAT | 验证方式（ChannelType） |
| `biz` | XAT | 业务场景 |

---

## 3. Token 类型详解

### 3.1 CAT (Client Access Token)

**用途**：应用自签发凭证，用于 Client-Credentials 流程向 Aegis 请求 SAT。

**Claims**

```json
{
  "iss": "app_123456",
  "sub": "app_123456",
  "aud": "https://aegis.heliannuuthus.com/api",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-01T00:05:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890"
}
```

| Claim | 说明 |
|-------|------|
| `iss` | 应用 ID（自签发） |
| `sub` | 应用 ID（⚠️ CAT 特殊：clientID 存于 sub） |
| `aud` | 固定为 `https://aegis.heliannuuthus.com/api` |

**Footer**：无

**流程**

```
┌────────────────────────────────────────────────────┐
│  应用                      Aegis                   │
├────────────────────────────────────────────────────┤
│  1. 使用私钥签发 CAT                                │
│  2. POST /oauth/token ──────────────────────────▶  │
│                            3. 验证 CAT 签名         │
│                            4. 签发 SAT              │
│  5. 获得 SAT  ◀──────────────────────────────────  │
└────────────────────────────────────────────────────┘
```

**特性**

- 短期有效（推荐 1-5 分钟）
- 一次性交换使用
- 不含 `cli`、`scope`

---

### 3.2 UAT (User Access Token)

**用途**：用户访问令牌，代表用户身份调用受保护资源。

**Claims**

```json
{
  "iss": "https://aegis.heliannuuthus.com/api",
  "cli": "app_123456",
  "aud": "service_789",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-01T01:00:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890",
  "scope": "openid profile email"
}
```

| Claim | 说明 |
|-------|------|
| `iss` | 固定为 `https://aegis.heliannuuthus.com/api` |
| `cli` | 发起请求的应用 ID |
| `aud` | 目标资源服务 |
| `scope` | 授权范围（空格分隔） |

**Footer**（加密存储）

```json
{
  "sub": "openid_xxx",
  "nickname": "张三",
  "picture": "https://example.com/avatar.jpg",
  "email": "user@example.com",
  "phone": "13800138000"
}
```

| Key | 说明 | 依赖 Scope |
|-----|------|------------|
| `sub` | 用户 OpenID | `openid` |
| `nickname` | 用户昵称 | `profile` |
| `picture` | 用户头像 | `profile` |
| `email` | 用户邮箱 | `email` |
| `phone` | 用户手机号 | `phone` |

**Scope 定义**

| Scope | 允许访问 | 备注 |
|-------|----------|------|
| `openid` | sub | 具备 openid 权限的 scope 才能访问 sub |
| `profile` | nickname, picture | 具备 profile 权限的 scope 才能访问 nickname, picture |
| `email` | email | 具备 email 权限的 scope 才能访问 email |
| `phone` | phone | 具备 phone 权限的 scope 才能访问 phone |
| `offline_access` | 请求 Refresh Token | - |
**流程**

```
┌────────────────────────────────────────────────────┐
│  用户         应用           Aegis       资源服务   │
├────────────────────────────────────────────────────┤
│  1. 登录认证                                        │
│  2. 授权同意                                        │
│              3. 获取 UAT ◀────                     │
│              4. 调用 API ─────────────────────────▶ │
│                                    5. 验证 UAT      │
│              6. 响应数据 ◀───────────────────────── │
└────────────────────────────────────────────────────┘
```

**特性**

- 推荐有效期 15-60 分钟
- 配合 Refresh Token 使用
- 敏感信息加密存储于 Footer

---

### 3.3 SAT (Service Access Token)

**用途**：服务间 M2M 通信凭证，无用户上下文。

**Claims**

```json
{
  "iss": "https://aegis.heliannuuthus.com/api",
  "cli": "app_123456",
  "aud": "service_789",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-02T00:00:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890",
}
```

| Claim | 说明 |
|-------|------|
| `iss` | 固定为 `https://aegis.heliannuuthus.com/api` |
| `cli` | 请求方应用 ID |
| `aud` | 目标服务 |

**Footer**：无

**流程**

```
┌────────────────────────────────────────────────────┐
│  服务 A                   Aegis         服务 B      │
├────────────────────────────────────────────────────┤
│  1. 签发 CAT                                        │
│  2. 请求 SAT ──────────────▶                        │
│                            3. 验证 CAT              │
│  4. 获得 SAT ◀──────────────                        │
│  5. 调用 API ──────────────────────────────────────▶│
│                                      6. 验证 SAT    │
│  7. 响应 ◀─────────────────────────────────────────│
└────────────────────────────────────────────────────┘
```

**特性**

- 推荐有效期 1-24 小时
- 无用户信息
- 适用于后台任务、微服务调用

**CAT vs SAT 对比**

| 维度 | CAT | SAT |
|------|-----|-----|
| 签发方 | 应用自己 | Aegis |
| 用途 | 请求 SAT | 访问资源 |
| 有效期 | 分钟级 | 小时级 |
| clientID 位置 | `sub` | `cli` |

---

### 3.4 XAT (Challenge Token)

**用途**：证明用户已完成特定身份验证挑战，用于 MFA 和敏感操作。

**Claims**

```json
{
  "iss": "https://aegis.heliannuuthus.com/api",
  "cli": "app_123456",
  "aud": "https://aegis.heliannuuthus.com/api",
  "sub": "user@example.com",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-01T00:15:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890",
  "ctp": "email_otp",
  "typ": "login"
}
```

| Claim | 说明 |
|-------|------|
| `iss` | 固定为 `https://aegis.heliannuuthus.com/api` |
| `cli` | 发起验证的应用 ID |
| `aud` | 固定为 `https://aegis.heliannuuthus.com/api` |
| `sub` | 完成验证的 principal |
| `ctp` | 验证方式（ChannelType） |
| `typ` | 验证场景（可选） |

**Footer**：无

**ChannelType 枚举**

| 值 | 分类 | sub 含义 |
|----|------|----------|
| `captcha` | 前置条件 | — |
| `email_otp` | 验证类 | 邮箱地址 |
| `sms_otp` | 验证类 | 手机号 |
| `totp` | 验证类 | 用户 OpenID |
| `tg_otp` | 验证类 | Telegram ID |
| `webauthn` | 验证类 | Credential ID |
| `wechat-mp` | 交换类 | 手机号 |
| `alipay-mp` | 交换类 | 手机号 |

**bizType 常见值**

| 值 | 说明 |
|----|------|
| `login` | 登录验证 |
| `forget_password` | 忘记密码 |
| `change_password` | 修改密码 |
| `bind_phone` | 绑定手机 |
| `bind_email` | 绑定邮箱 |

**流程（MFA 示例）**

```
┌────────────────────────────────────────────────────┐
│  用户                      Aegis                   │
├────────────────────────────────────────────────────┤
│  1. 完成密码登录                                    │
│                            2. 要求 TOTP 验证        │
│  3. 输入 TOTP 验证码 ─────────────────────────────▶ │
│                            4. 验证成功，签发 XAT    │
│  5. 获得 XAT ◀───────────────────────────────────  │
│  6. 提交 XAT 到 /authenticate ─────────────────▶   │
│                            7. 验证 XAT，完成登录    │
└────────────────────────────────────────────────────┘
```

**特性**

- 推荐有效期 5-15 分钟
- 一次性使用
- 绑定特定业务场景

---

### 3.5 SSO Token（内部专用）

**用途**：跨应用单点登录会话，存储于浏览器 Cookie，仅 Aegis 内部使用。

**Claims**

```json
{
  "iss": "https://aegis.heliannuuthus.com/api",
  "aud": "https://aegis.heliannuuthus.com/api",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-08T00:00:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890"
}
```

| Claim | 说明 |
|-------|------|
| `iss` | 固定为 `https://aegis.heliannuuthus.com/api` |
| `aud` | 固定为 `https://aegis.heliannuuthus.com/api` |

**Footer**（加密存储）

```json
{
  "domain_consumer": "openid_xxx",
  "domain_platform": "openid_yyy"
}
```

| Key | 说明 |
|-----|------|
| `{domain}` | 该域下的用户 OpenID |

**流程（SSO 快速路径）**

```
┌────────────────────────────────────────────────────┐
│  用户         应用 B        Aegis                  │
├────────────────────────────────────────────────────┤
│  （已在应用 A 登录，浏览器存有 SSO Cookie）          │
│  1. 访问应用 B                                      │
│              2. 重定向 /authorize ─────────────────▶│
│                             3. 检测 SSO Cookie      │
│                             4. 查找当前域 openID    │
│                             5. 验证用户状态         │
│                             6. 直接签发授权码       │
│              7. 重定向回应用 B ◀───────────────────│
│  8. 无需登录，直接进入                              │
└────────────────────────────────────────────────────┘
```

**特性**

- 默认有效期 7 天
- 域隔离身份（每个域独立 OpenID）
- 自签发自验证（iss = aud = issuer URL）
- 无 `cli`、无 `scope`

**Cookie 配置**

| 配置项 | 默认值 |
|--------|--------|
| name | `aegis-sso` |
| ttl | `168h` |
| Secure | `true` |
| HttpOnly | `true` |
| SameSite | `Lax` |

**prompt 参数交互**

| prompt | 行为 |
|--------|------|
| （无） | 优先使用 SSO 快速路径 |
| `login` | 忽略 SSO，强制重新登录 |
| `none` | 仅使用 SSO，不可用则报错 |

---

## 4. 安全设计

### 4.1 签名与加密

| Token | 签名密钥 | Footer 加密 |
|-------|----------|-------------|
| CAT | 应用私钥 | — |
| UAT | 服务私钥 | 服务对称密钥 |
| SAT | 服务私钥 | — |
| XAT | 服务私钥 | — |
| SSO | SSO 主密钥派生 | SSO 对称密钥 |

### 4.2 SSO 密钥派生

SSO Token 使用单一 master key 通过 KDF 派生：

- Ed25519 签名私钥
- Ed25519 验证公钥
- 对称加密密钥（Footer）

### 4.3 有效期建议

| Token | 推荐有效期 | 说明 |
|-------|------------|------|
| CAT | 1-5 分钟 | 一次性交换 |
| UAT | 15-60 分钟 | 配合 Refresh Token |
| SAT | 1-24 小时 | M2M 场景 |
| XAT | 5-15 分钟 | 验证窗口 |
| SSO | 7-30 天 | 会话保持 |

---

## 5. Token 类型检测

### 5.1 判断逻辑

```
1. 有 "typ" 字段，有 "cli" 字段 → XAT
2. 有 "cli" 字段，无 Footer → SAT
3. 有 "cli" 字段，有 Footer → UAT
4. 仅有 "sub"，无 "cli"/"typ" → CAT
5. "iss" = "aud" = issuer URL → SSO
```

### 5.2 识别规则

| 特征 | Token 类型 |
|------|------------|
| 有 `typ`，有 `cli` | XAT |
| 有 `cli`，无 Footer | SAT |
| 有 `cli`，有 Footer | UAT |
| 仅 `sub`，无 `cli`/`typ` | CAT |
| `iss` = `aud` = issuer URL | SSO |

# Aegis Token 设计文档

## 1. 概述

Aegis 使用 **PASETO v4 Public Token**（Ed25519 签名）作为统一凭证格式，定义了 5 种 Token 类型：

| 类型 | 标识 | 用途 | 签发方 | 验证方 | Footer | 加密数据 |
|------|------|------|--------|--------|--------|----------|
| CAT | `cat` | 客户端自签发凭证 | 应用 | Aegis | kid | 无 |
| UAT | `uat` | 用户访问令牌 | Aegis | 应用 | kid | sub（v4.local） |
| SAT | `sat` | 服务访问令牌（M2M） | Aegis | 应用 | kid | 无 |
| XAT | `challenge` | 验证挑战令牌 | Aegis | Aegis | kid | 无 |
| SSO | `sso` | 单点登录会话（内部） | Aegis | Aegis | kid | sub（v4.local） |

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
| `footer` | JSON，包含 kid（密钥标识） |

### 2.2 Footer 格式（所有 Token 统一）

```json
{"kid":"k4.pid.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
```

- `kid`：PASERK 格式的签名密钥标识符
- 使用 BLAKE2b-264 从公钥派生，确定性、不可逆
- 用于密钥轮换场景下精确匹配验签公钥

### 2.3 通用 Claims

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
| `sub` | string | 主体（可选，UAT/SSO 为加密的 v4.local token） |
| `iat` | RFC3339 | 签发时间 |
| `exp` | RFC3339 | 过期时间 |
| `nbf` | RFC3339 | 生效时间 |
| `jti` | string | Token ID（16 字节随机 hex） |

### 2.4 扩展 Claims

| Claim | 使用者 | 说明 |
|-------|--------|------|
| `cli` | UAT, SAT, XAT, SSO | 应用/签发者 ID |
| `scope` | UAT, SAT | 授权范围（空格分隔） |
| `ctp` | XAT | 验证方式（ChannelType） |
| `typ` | XAT | 业务场景 |

---

## 3. 嵌套加密结构

### 3.1 双层 Token 架构（UAT/SSO）

UAT 和 SSO Token 使用嵌套 PASETO Token 结构存储敏感数据：

```
外层 v4.public Token（签名）:
  payload: { iss, aud, cli, scope, exp, ..., sub: "<v4.local token>" }
  footer:  { "kid": "k4.pid.xxxx" }   ← 签名密钥的 PASERK pid

内层 v4.local Token（加密，嵌在 sub 字段中）:
  payload: { 加密的用户信息 / 域身份映射 }
  footer:  { "kid": "k4.lid.yyyy" }   ← 加密密钥的 PASERK lid
```

- 外层 footer 的 `k4.pid` 标识签名密钥，用于验签
- 内层 footer 的 `k4.lid` 标识加密密钥，用于解密 sub
- 两个 kid 来自不同的 Seed，轮换完全独立

### 3.2 kid 派生（PASERK 规范）

**签名密钥 kid（k4.pid）**：

```
paserk = "k4.public." + base64url(ed25519_public_key_bytes)
h      = "k4.pid."
d      = BLAKE2b(message: h || paserk, output_size: 33)
kid    = h + base64url(d)    // 总长 51 字符
```

**加密密钥 kid（k4.lid）**：

```
paserk = "k4.local." + base64url(symmetric_key_bytes)
h      = "k4.lid."
d      = BLAKE2b(message: h || paserk, output_size: 33)
kid    = h + base64url(d)    // 总长 51 字符
```

---

## 4. Token 类型详解

### 4.1 CAT (Client Access Token)

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

**Footer**：`{"kid":"k4.pid.xxxx"}` — 应用密钥的 pid

**特性**

- 短期有效（推荐 1-5 分钟）
- 一次性交换使用
- 不含 `cli`、`scope`
- `sub` = 应用 ID（明文）

---

### 4.2 UAT (User Access Token)

**用途**：用户访问令牌，代表用户身份调用受保护资源。

**外层 Claims**

```json
{
  "iss": "https://aegis.heliannuuthus.com/api",
  "cli": "app_123456",
  "aud": "service_789",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-01T01:00:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890",
  "scope": "openid profile email",
  "sub": "v4.local.加密的用户信息..."
}
```

**外层 Footer**：`{"kid":"k4.pid.xxxx"}` — domain.main 的 pid

**内层 v4.local Token（sub 字段值）的解密内容**

```json
{
  "sub": "openid_xxx",
  "nickname": "张三",
  "picture": "https://example.com/avatar.jpg",
  "email": "user@example.com",
  "phone": "13800138000"
}
```

**内层 Footer**：`{"kid":"k4.lid.yyyy"}` — service.key 的 lid

**Scope 定义**

| Scope | 允许访问 |
|-------|----------|
| `openid` | sub |
| `profile` | nickname, picture |
| `email` | email |
| `phone` | phone |
| `offline_access` | 请求 Refresh Token |

**特性**

- 推荐有效期 15-60 分钟
- 配合 Refresh Token 使用
- 敏感信息加密存储于 sub 字段（嵌套 v4.local token）

---

### 4.3 SAT (Service Access Token)

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
  "jti": "a1b2c3d4e5f67890"
}
```

**Footer**：`{"kid":"k4.pid.xxxx"}` — domain.main 的 pid

**特性**

- 推荐有效期 1-24 小时
- 无用户信息，无 sub
- 适用于后台任务、微服务调用

---

### 4.4 XAT (Challenge Token)

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

**Footer**：`{"kid":"k4.pid.xxxx"}` — domain.main 的 pid

**特性**

- 推荐有效期 5-15 分钟
- 一次性使用
- `sub` = 完成验证的 principal（明文）

---

### 4.5 SSO Token（内部专用）

**用途**：跨应用单点登录会话，存储于浏览器 Cookie，仅 Aegis 内部使用。

**外层 Claims**

```json
{
  "iss": "aegis",
  "cli": "aegis",
  "aud": "aegis",
  "iat": "2024-01-01T00:00:00Z",
  "exp": "2024-01-08T00:00:00Z",
  "nbf": "2024-01-01T00:00:00Z",
  "jti": "a1b2c3d4e5f67890",
  "sub": "v4.local.加密的域身份映射..."
}
```

**外层 Footer**：`{"kid":"k4.pid.xxxx"}` — sso.master_key 的 pid

**内层 v4.local Token（sub 字段值）的解密内容**

```json
{
  "domain_consumer": "openid_xxx",
  "domain_platform": "openid_yyy"
}
```

**内层 Footer**：`{"kid":"k4.lid.yyyy"}` — sso.master_key 的 lid

**特性**

- 默认有效期 7 天
- 域隔离身份（每个域独立 OpenID）
- 自签发自验证（iss = cli = aud = "aegis"）
- 无 `scope`

---

## 5. 统一签发 / 验证架构

### 5.1 设计原则

所有 Token 类型共享统一的 `Issue` 和 `Verify` 入口，通过接口多态区分行为差异：

- **签发差异**由 `encryptableToken` 接口决定：实现该接口的 Token（UAT、SSO）会将 payload 加密到 sub 字段；未实现的（SAT、XAT）直接签名
- **验证差异**由 `decryptableToken` 接口决定：实现该接口的 Token 在验签后自动解密 sub 并填充数据
- **密钥选择**由 Token 自身的 `GetClientID()` 和 `GetAudience()` 驱动，无需特殊分支

### 5.2 Token 构建（Builder 模式）

所有 Token 通过统一的 `ClaimsBuilder + TokenTypeBuilder` 模式构建：

```
token := NewClaimsBuilder().
    Issuer(issuer).
    ClientID(clientID).
    Audience(audience).
    ExpiresIn(duration).
    Build(typeBuilder)    // UAT / SAT / XT / CAT / SSOTokenBuilder
```

`TokenTypeBuilder` 接口负责将通用 Claims 与类型特有字段组合为具体 Token 实例。

### 5.3 签发流程（`Service.Issue`）

```
1. Build: Token → *paseto.Token（通过 tokenBuilder 接口）
2. 检查是否实现 encryptableToken 且 HasUser()：
   是 → MarshalPayload → Encrypt(audience) → SetSubject(encrypted)
   否 → 跳过
3. Sign(clientID) → 返回 token 字符串
```

密钥选择规则：
- 签名：`domainKeyStore.Get(clientID)` — SSO 时 clientID = "aegis"
- 加密：`serviceKeyStore.Get(audience)` — SSO 时 audience = "aegis"

### 5.4 验证流程（`Service.Verify`）

```
1. UnsafeParse → 提取 claims（不验签）
2. DetectType → 判断 Token 类型
3. 选择验签 KeyStore：
   CAT → appKeyStore（应用自签，用应用公钥验证）
   其他 → domainKeyStore（Aegis 签发，用域公钥验证）
4. 验签（遍历候选 Seed，通过 kid 精确匹配）
5. ParseToken → 解析为具体 Token 类型
6. 检查是否实现 decryptableToken：
   是 → Decrypt(audience) → UnmarshalPayload → 填充数据
   否 → 跳过
7. 返回 Token（调用方按需类型断言）
```

验签密钥匹配细节：
```
a. 用 clientID 从 KeyStore 获取所有 Seed
b. 逐个派生公钥，计算 k4.pid
c. 与 footer kid 做 constant-time comparison
d. 匹配成功 → ParseV4Public 验签
```

---

## 6. 安全设计

### 6.1 签名与加密

| Token | 签名密钥来源 | Footer kid 类型 | 加密密钥来源 | 内层 kid 类型 |
|-------|-------------|-----------------|-------------|--------------|
| CAT | `app.key` | k4.pid | — | — |
| UAT | `domain.main` | k4.pid | `service.key` | k4.lid |
| SAT | `domain.main` | k4.pid | — | — |
| XAT | `domain.main` | k4.pid | — | — |
| SSO | `sso.master_key` | k4.pid | `sso.master_key` | k4.lid |

### 6.2 安全要点

- kid 是公钥/对称密钥的 BLAKE2b 哈希摘要，明文存放无安全风险
- 外层签名覆盖整个 payload（包括加密的 sub），防止加密数据被替换
- 内层 v4.local 使用 XChaCha20-Poly1305 (AEAD)，提供认证加密
- kid 比对使用 constant-time comparison，防止时序侧信道攻击
- UnsafeParse 仅用于确定 KeyStore 查找目标，kid 用于精确匹配

### 6.3 有效期建议

| Token | 推荐有效期 | 说明 |
|-------|------------|------|
| CAT | 1-5 分钟 | 一次性交换 |
| UAT | 15-60 分钟 | 配合 Refresh Token |
| SAT | 1-24 小时 | M2M 场景 |
| XAT | 5-15 分钟 | 验证窗口 |
| SSO | 7-30 天 | 会话保持 |

---

## 7. Token 类型检测

### 7.1 判断逻辑

```
1. iss == aud == cli（三者相等且非空） → SSO
2. 有 "ctp" 字段 → XAT
3. 有 "cli" 字段 → UAT（sub 加密）或 SAT（无 sub）
4. 无 "cli"/"ctp" → CAT
```

> SSO 优先判断，因为 SSO 也携带 `cli` 字段，必须先排除。

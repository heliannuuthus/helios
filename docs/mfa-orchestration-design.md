# MFA 编排设计文档

> 更新日期：2026-02-16

---

## 1. 概述

MFA（Multi-Factor Authentication，多因素认证）是在主认证成功之后，通过风险评估动态触发的**追加验证阶段**。

### 核心原则

- **MFA 不是预展示的**——不在 `ConnectionsMap` 中提前暴露 MFA 配置
- **MFA 是运行时决策**——由风险评估引擎在主认证成功后动态判断
- **MFA 是 Challenge 的编排**——MFA 的第二因子复用 Challenge 能力，不是独立的验证通道
- **MFA 发生在授权后、Token 签发前**——是 AuthFlow 的一个阶段

### 关键区分

| | Challenge（SFA） | MFA |
|---|---|---|
| 发起方 | 用户主动 | 系统触发 |
| 触发时机 | 登录前（delegate）/ 独立 | 主认证后 |
| 因子要求 | 一个因子 | ≥2 个不同类别因子 |
| 作用 | 完成一次认证 | 加固主认证 |
| 是否预展示 | 是（ConnectionsMap.delegated） | 否（运行时动态） |

---

## 2. AuthFlow 阶段扩展

MFA 作为新阶段加入 AuthFlow 状态机：

```
┌─────────┐    ┌─────────┐    ┌────────────┐    ┌────────────┐    ┌──────────┐
│  init    │───>│  authn   │───>│  authz     │───>│  mfa       │───>│  token   │
│         │    │         │    │           │    │ (optional) │    │  issued  │
└─────────┘    └─────────┘    └────────────┘    └────────────┘    └──────────┘
                   │                                                     │
                   │          无风险，跳过 MFA                             │
                   └────────────────────────────────────────────────────>│
```

### 阶段说明

| 阶段 | 名称 | 描述 |
|------|------|------|
| init | 初始化 | 创建 AuthFlow，获取 ConnectionsMap |
| authn | 主认证 | IDP 策略（password / passkey）或 Delegate 路径（SFA Token） |
| authz | 授权 | 获取用户身份，确认 client 权限 |
| **mfa** | **多因素加固** | **风险评估，条件触发追加验证** |
| token | Token 签发 | 签发 access_token / refresh_token |

---

## 3. 风险评估

### 3.1 评估时机

主认证成功、授权通过之后，Token 签发之前。

### 3.2 评估维度

```go
type RiskContext struct {
    UserID        string            // 用户 ID
    ClientID      string            // 应用 ID
    LoginMethod   string            // 主认证方式（password / passkey / delegate:email_otp ...）
    IP            string            // 请求 IP
    UserAgent     string            // 浏览器 UA
    GeoLocation   *GeoLocation      // IP 归属地
    DeviceID      string            // 设备指纹
    LastLoginAt   *time.Time        // 上次登录时间
    FailedAttempts int              // 近期失败次数
    Metadata       map[string]any   // 扩展字段
}
```

### 3.3 评估结果

```go
type RiskAssessment struct {
    Level          RiskLevel         // 风险等级
    RequireMFA     bool              // 是否需要 MFA
    AllowedChannels []string         // 允许的 SFA channel_type 列表
    Reason         string            // 风险原因（审计用）
}

type RiskLevel string

const (
    RiskNone     RiskLevel = "none"     // 无风险，直接签发 Token
    RiskLow      RiskLevel = "low"      // 低风险，可选 MFA
    RiskMedium   RiskLevel = "medium"   // 中风险，建议 MFA
    RiskHigh     RiskLevel = "high"     // 高风险，强制 MFA
    RiskBlocked  RiskLevel = "blocked"  // 极高风险，直接拒绝
)
```

### 3.4 评估规则（示例）

| 条件 | 风险等级 | 处理 |
|------|---------|------|
| 常用设备 + 常用 IP | none | 直接签发 |
| 新设备，常用 IP | low | 可选 MFA |
| 常用设备，陌生 IP/地域 | medium | 建议 MFA |
| 新设备 + 陌生 IP | high | 强制 MFA |
| 近期多次失败 | high | 强制 MFA |
| 主认证方式为 passkey | 降级 -1 | passkey 本身是 MFA 因子 |
| 黑名单 IP/设备 | blocked | 拒绝 |

---

## 4. MFA 触发机制

### 4.1 触发流程

当风险评估结果为 `RequireMFA = true` 时：

```
后端                                         前端
 │                                            │
 │  主认证 + 授权完成                           │
 │  风险评估：RequireMFA = true                │
 │  AllowedChannels: [totp, email_otp]        │
 │                                            │
 │  HTTP 302                                  │
 │  Location: /mfa?channels=totp,email_otp    │
 │            &flow_id=xxx                    │
 │ ─────────────────────────────────────────> │
 │                                            │  前端根据 channels 条件渲染
 │                                            │  显示 TOTP 输入 或 Email OTP 选项
 │                                            │
```

### 4.2 HTTP 响应设计

#### 需要 MFA

```http
HTTP/1.1 302 Found
Location: /mfa?channels=totp,email_otp&flow_id=abc123
```

前端解析 `channels` 参数，条件渲染对应的验证 UI。

#### 实际 API 形式（SPA 场景）

对于 SPA 应用，不实际做浏览器 302，而是返回结构化 JSON：

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "status": "mfa_required",
    "flow_id": "abc123",
    "allowed_channels": ["totp", "email_otp"],
    "expires_in": 300
}
```

前端收到 `status: "mfa_required"` 后路由到 MFA 页面。

#### 不需要 MFA

直接签发 Token，正常返回 authorization_code 或 token。

---

## 5. MFA 验证流程

### 5.1 前端完成 MFA

MFA 复用 Challenge 能力。前端根据 `allowed_channels` 选择一种 channel_type 发起 Challenge：

```
前端                                          后端
 │                                             │
 │  POST /auth/challenge                       │
 │  { client_id: "app_abc",                    │
 │    audience: "svc_xyz",                     │
 │    type: "login",                           │
 │    channel_type: "totp",                    │
 │    channel: "user_123" }                    │
 │ ──────────────────────────────────────────> │
 │                                             │
 │  { challenge_id: "yyy" }                    │
 │ <────────────────────────────────────────── │
 │                                             │
 │  POST /auth/challenge/yyy                   │
 │  { type: "totp",                            │
 │    proof: "123456" }                        │
 │ ──────────────────────────────────────────> │
 │                                             │
 │  { verified: true,                          │
 │    challenge_token: "v4.public.xxx" }       │
 │ <────────────────────────────────────────── │
 │                                             │
 │  POST /auth/mfa/complete                    │
 │  { flow_id: "abc123",                       │
 │    challenge_token: "v4.public.xxx" }       │
 │ ──────────────────────────────────────────> │
 │                                             │  验证 ChallengeToken：
 │                                             │    channel_type ∈ allowed_channels ✓
 │                                             │    因子类别 ≠ 主认证因子类别 ✓
 │                                             │  MFA 完成 → 签发 Token
 │                                             │
 │  { access_token: "...",                     │
 │    token_type: "Bearer" }                   │
 │ <────────────────────────────────────────── │
```

### 5.2 MFA Complete 接口

```go
// POST /auth/mfa/complete
type MFACompleteRequest struct {
    FlowID         string `json:"flow_id"`          // AuthFlow ID
    ChallengeToken string `json:"challenge_token"`  // Challenge 完成后签发的 ChallengeToken
}
```

后端验证逻辑：

1. **FlowID 有效**——AuthFlow 存在且处于 `mfa` 阶段
2. **ChallengeToken 有效**——PASETO v4 签名、未过期
3. **Channel Type 在允许列表中**——`challenge_token.channel_type ∈ flow.allowed_channels`
4. **因子类别不同**——Challenge 使用的因子类别与主认证因子类别不同（这才是真正的 MFA）
5. 验证通过 → 进入 `token` 阶段 → 签发 access_token

### 5.3 因子类别校验

| 主认证方式 | 主认证因子类别 | 允许的 MFA 因子类别 | 允许的 Channel Type |
|-----------|-------------|-------------------|-------------------|
| password | Knowledge | Possession, Inherence | totp, email_otp, sms_otp, webauthn |
| passkey | Inherence + Possession | Knowledge | 一般不需要 MFA |
| delegate:email_otp | Possession | Knowledge, Inherence | webauthn |
| delegate:sms_otp | Possession | Knowledge, Inherence | webauthn |
| delegate:totp | Possession | Knowledge, Inherence | webauthn |

---

## 6. AuthFlow 存储扩展

```go
type AuthFlow struct {
    // ... 现有字段 ...

    // MFA 相关
    MFARequired     bool     `json:"mfa_required,omitempty"`      // 是否需要 MFA
    MFAAllowedChannels []string `json:"mfa_allowed_channels,omitempty"` // 允许的 channel_type
    MFACompletedAt  *time.Time `json:"mfa_completed_at,omitempty"` // MFA 完成时间
    RiskLevel       string   `json:"risk_level,omitempty"`        // 风险等级
    RiskReason      string   `json:"risk_reason,omitempty"`       // 风险原因
}
```

---

## 7. 前端实现

### 7.1 MFA 页面路由

前端收到 `mfa_required` 后，路由到 `/mfa` 页面（或弹出 MFA 弹层）。

### 7.2 条件渲染

```tsx
// allowed_channels = ["totp", "email_otp"]

{allowedChannels.includes("totp") && <TOTPInput />}
{allowedChannels.includes("email_otp") && <EmailOTPFlow />}
{allowedChannels.includes("sms_otp") && <SMSOTPFlow />}
{allowedChannels.includes("webauthn") && <WebAuthnFlow />}
```

### 7.3 用户选择

如果有多个可选 channel，展示选择界面，让用户挑选最方便的验证方式。

---

## 8. 安全设计

### 8.1 时效控制

- MFA 阶段有独立超时时间（如 5 分钟）
- 超时后 AuthFlow 失效，需重新登录

### 8.2 尝试次数限制

- 单个 AuthFlow 内 MFA 验证尝试次数有限制（如最多 5 次）
- 超过后 AuthFlow 锁定

### 8.3 降级策略

- passkey 主认证自带双因子（设备持有 + 生物特征），风险评估可降级处理
- 已绑定可信设备的用户，可降低 MFA 触发概率

### 8.4 记住设备

MFA 验证成功后，可选择"信任此设备 N 天"，在有效期内同设备不再触发 MFA。

```go
type TrustedDevice struct {
    DeviceID   string    `json:"device_id"`
    UserID     string    `json:"user_id"`
    TrustedAt  time.Time `json:"trusted_at"`
    ExpiresAt  time.Time `json:"expires_at"`
}
```

---

## 9. 设计决策

### 9.1 为什么不在 ConnectionsMap 中预展示 MFA

ConnectionsMap 是"登录前看到什么"，MFA 是"登录后需要什么"。提前暴露 MFA 配置：
- 泄露安全策略（攻击者知道 MFA 方式后可针对性准备）
- 增加前端复杂度（需要区分"delegate 用的 email_otp"和"MFA 用的 email_otp"）
- 语义错误（MFA 是运行时的动态决策，不是静态配置的展示）

### 9.2 为什么用 SPA JSON 而不是真 302

真 302 适合传统 MPA（多页应用），对 SPA 不友好。返回结构化 JSON + 前端路由是更自然的方式。设计文档中提到 302 是表达"流程跳转"的语义，实现形式可根据架构调整。

### 9.3 为什么因子类别校验

不做因子类别校验的话，password + email（同为 Knowledge? 否，email_otp 是 Possession）基本上主流组合都满足 MFA。但严格校验能防止：
- password + password hint 之类的伪 MFA
- 确保真正的多因素覆盖

### 9.4 为什么 MFA 复用 Challenge 能力

不重复实现验证逻辑。Challenge 是统一的验证能力层，MFA 只负责编排：
- **决定是否需要验证**（风险评估）
- **决定允许什么方式**（channel_type 过滤）
- **校验因子是否满足 MFA 标准**（类别校验）
- 真正的验证动作全部委托给 Challenge（POST /auth/challenge + POST /auth/challenge/:cid）

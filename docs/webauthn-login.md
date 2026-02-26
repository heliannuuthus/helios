# WebAuthn 登录设计

> 状态：Implemented | 更新：2026-02-17

## 1. 目标

在登录页提供一个品牌化的 Passkey 快速入口（"头盔盖下来"式遮盖层），在不启用 Conditional UI 的前提下：

1. 用户可看到熟悉的欢迎信息（昵称/头像）
2. 用户可一键触发安全验证（指纹/面容/PIN）
3. 用户可随时切换到其他登录方式

## 2. 设计结论（已定）

### 2.1 不依赖 Conditional UI

本方案采用自定义遮盖层（`SecurityMask` 组件），不依赖浏览器输入框联想的 Conditional UI。

> 注意：当遮盖层显示时，页面级 Conditional UI 不会启动；关闭遮盖层后，如果 `shouldPageHandlePasskey` 为 true 且浏览器支持，才会激活 Conditional UI 作为备选入口。

### 2.2 不新增后端协议字段

`user_hints` 不是 WebAuthn 协议标准字段，本方案不要求后端新增该字段。  
用户信息来源为前端已登录态页面（个人信息页 `SecuritySettings`）中的现有数据。

### 2.3 本地缓存采用单用户覆盖策略

当前策略：同一浏览器同一站点仅缓存最近一次设置 Passkey 的用户提示信息。  
后续如业务明确要求多用户列表，可在同一 key 上扩展为数组结构。

## 3. 系统架构与组件关系

### 3.1 后端服务架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Aegis Handler (handler.go)                       │
│  编排层 — 路由入口 → 服务调用 → 响应                                      │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  POST /auth/authorize    → authenticateSvc.CreateFlow()                  │
│  GET  /auth/connections  → authenticateSvc.GetAvailableConnections()     │
│  GET  /auth/context      → flow.Application / flow.Service               │
│  POST /auth/challenge    → challengeSvc.Initiate() [WebAuthn begin]     │
│  POST /auth/challenge/:cid → challengeSvc.VerifyProof() [assertion]     │
│  POST /auth/login        → authenticateSvc.Authenticate()                │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│  内部分发                                                                 │
│                                                                          │
│  authenticator.GlobalRegistry()                                          │
│    ├─ idp/passkey.Provider   ── Discoverable Login (无用户名)             │
│    ├─ idp/user.Provider      ── 账号密码 / delegate                       │
│    ├─ idp/staff.Provider      ── 运营者账号                                │
│    ├─ factor/webauthn        ── MFA 二次验证                              │
│    └─ ...                                                                │
│                                                                          │
│  webauthn.Service (内部引擎)                                              │
│    ├─ BeginDiscoverableLogin() ── Passkey 登录                            │
│    ├─ BeginLogin()             ── 指定用户的 WebAuthn 验证                 │
│    ├─ BeginRegistration()      ── 凭证注册                                │
│    ├─ FinishLogin()            ── 验证 assertion                         │
│    └─ FinishRegistration()     ── 验证 attestation                       │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.2 前端组件关系

```
aegis-ui/src/
├── pages/Login/
│   ├── index.tsx                    # 登录页主入口，编排全部登录方式
│   │   ├── SecurityMask             # ★ Welcome Back 遮盖层
│   │   ├── Passkey                  # 独立 Passkey 按钮（手动触发）
│   │   ├── StaffLogin                # 邮箱+密码/delegate 登录
│   │   ├── IDPButton                # 社交登录按钮
│   │   └── ChallengeVerify          # Challenge 验证码输入
│   └── components/
│       ├── SecurityMask/index.tsx   # 遮盖层 UI：头像+昵称+主/次按钮
│       ├── Passkey/index.tsx        # 指纹/面容登录按钮
│       └── WebAuthn/
│           ├── index.tsx            # 工具函数 re-export
│           └── utils.ts             # base64url、options 转换、assertion 执行
├── pages/Profile/
│   └── components/
│       └── SecuritySettings.tsx     # MFA 管理：注册/删除 → 缓存写入/清除
└── utils/
    └── passkeyCache.ts             # ★ localStorage 缓存管理
```

### 3.3 Passkey vs WebAuthn 的区别

| 维度 | Passkey（IDP） | WebAuthn（Factor） |
|------|------|------|
| **角色** | 主身份提供者（替代账号密码） | MFA 二次验证因子 |
| **Connection 类型** | `idp` | `factor` |
| **Connection 标识** | `passkey` | `webauthn` |
| **登录方式** | Discoverable Credentials（无需提前知道用户） | 指定用户的 Allowed Credentials |
| **后端入口** | `idp/passkey.Provider.Login()` | `factor/webauthn.Verify()` |
| **前端触发** | `performPasskeyLogin()` / `SecurityMask` | staff delegate 中的 `webauthn` 选项 |

## 4. WebAuthn 域配置规范

### 4.1 RP ID 选择原则

WebAuthn 协议中 `rpId`（Relying Party Identifier）决定了凭证的绑定范围。浏览器会将凭证与 `rpId` 关联，只有当页面的 effective domain 是 `rpId` 本身或其子域时，该凭证才可被使用。

| 配置项 | 值 | 作用 |
|--------|-----|------|
| `rp-id` | 根域名（如 `heliannuuthus.com`） | 凭证绑定范围，决定哪些子域可以使用凭证 |
| `rp-display-name` | 友好名称（如 `Helios Auth`） | 仅用于浏览器 UI 展示，不参与安全校验 |
| `rp-origins` | 全部允许的页面 origin 列表 | 后端校验 assertion 时比对 `clientDataJSON.origin` |

### 4.2 跨子域共享设计

当认证入口分布在多个子域时（如 `app.heliannuuthus.com`、`aegis.heliannuuthus.com`），将 `rpId` 设为顶级域 `heliannuuthus.com` 可以实现凭证跨子域共享：

- 用户在 `aegis.heliannuuthus.com` 注册的 Passkey，可以在 `app.heliannuuthus.com` 使用
- 用户无需为每个子域分别注册凭证
- `rp-origins` 需要精确列出每一个合法的前端页面 origin（scheme + host），不支持通配符

### 4.3 RP ID 暴露机制

前端需要 `rpId` 来构建 `PublicKeyCredentialRequestOptions`。后端通过 `GET /auth/connections` 接口将 RP ID 包含在 `passkey` connection 的 `identifier` 字段中返回，前端无需硬编码此值。

### 4.4 安全约束

- `rp-origins` 校验的是**前端页面的 origin**，不是 API 服务地址
- 每新增一个需要发起 WebAuthn 的前端域，必须显式加入 `rp-origins` 列表
- 不得将 `rpId` 设为公共后缀域名（如 `.com`、`.co.uk`），浏览器会拒绝

## 5. 本地存储设计

### 5.1 Key 命名

统一采用带命名空间前缀的 key：

```text
heliannuuthus@aegis:passkey_user
```

### 5.2 Value 结构（单用户）

```json
{
  "uid": "u_xxx",
  "nickname": "heliannuuthus",
  "picture": "https://cdn.xxx/avatar.png",
  "updated_at": 1739100000000
}
```

字段说明：
- `uid`: 用户稳定标识（用于校验与清理）
- `nickname`: 遮盖层展示名称
- `picture`: 头像 URL（可空）
- `updated_at`: 最后更新时间戳（用于调试与过期策略）

### 5.3 缓存管理设计

缓存模块（`passkeyCache`）对外提供五个操作：

| 操作 | 语义 | 触发场景 |
|------|------|---------|
| `get` | 读取当前缓存的用户提示信息，不存在则返回 null | 登录页加载时判断是否展示遮盖层 |
| `set` | 写入缓存，自动附加 `updated_at` 时间戳 | 内部方法，不直接对外暴露 |
| `clear` | 清除缓存 | 用户删除最后一个 Passkey 凭证后；凭证失效检测时 |
| `setPendingUserInfo` | 将用户信息暂存到内存变量（不写入 localStorage） | Passkey 注册流程开始前 |
| `writeAfterRegistration` | 将内存中暂存的信息写入 localStorage | Passkey 注册成功后 |

#### 暂存-提交两阶段写入机制

直接在注册前写入 localStorage 存在风险：若注册失败（用户取消、设备不支持等），缓存中将留下"虚假"的 Passkey 提示信息，导致下次登录时显示遮盖层但实际无可用凭证。

为此采用两阶段机制：

1. **暂存阶段**（`setPendingUserInfo`）：个人信息页在调用 WebAuthn 注册 API 之前，先将当前用户的 `uid`、`nickname`、`picture` 写入模块内部的内存变量。此时 localStorage 不发生任何变化。
2. **提交阶段**（`writeAfterRegistration`）：WebAuthn 注册完整成功（后端 Finish 返回 `success: true`）后，才将内存中暂存的数据正式写入 localStorage。如果注册过程中任何环节失败，内存变量在页面刷新后自动丢弃。

这一设计保证了 localStorage 中的缓存始终与用户实际拥有的 Passkey 凭证一致。

## 6. 前端流程

### 6.1 缓存写入与清除时机

缓存的生命周期由个人信息页（`SecuritySettings`）管理，而非登录页。这是因为只有在已登录态下，才能获取到完整的用户信息（`uid`、`nickname`、`picture`）。

#### 写入场景：Passkey 注册成功

| 步骤 | 动作 | 说明 |
|------|------|------|
| 1 | 用户在个人信息页点击"添加安全密钥" | 进入 WebAuthn 注册流程 |
| 2 | 前端暂存当前用户信息到内存 | 调用 `setPendingUserInfo()`，此时不写 localStorage |
| 3 | 调用 Iris `POST /user/mfa`（Begin） | 获取 `PublicKeyCredentialCreationOptions` |
| 4 | 浏览器弹出系统验证弹窗 | 用户进行指纹/面容/PIN 认证 |
| 5 | 调用 Iris `POST /user/mfa`（Finish） | 提交 attestation，后端保存凭证 |
| 6 | 注册成功，提交缓存写入 | 调用 `writeAfterRegistration()`，正式写入 localStorage |

若步骤 3~5 中任何环节失败，步骤 6 不会执行，localStorage 保持不变。

#### 清除场景：删除最后一个 Passkey 凭证

当用户删除 WebAuthn/Passkey 凭证后，前端检查剩余凭证数量。如果该用户已无任何 WebAuthn/Passkey 类型的凭证（剩余列表为空），则立即清除 localStorage 中的 `passkey_user` 缓存。

这确保了下次访问登录页时不会展示已无效的 Welcome Back 遮盖层。

#### 不清除的场景

- **用户登出**：保留缓存，因为 Passkey 凭证仍然有效，回访时应展示遮盖层提升体验
- **用户切换到其他登录方式**：保留缓存，遮盖层仅关闭当次显示
- **用户取消系统验证弹窗**：保留缓存，用户下次仍可尝试

### 6.2 遮盖层展示判断

登录页加载完成后，通过三个独立条件的逻辑与（AND）决定是否展示 Welcome Back 遮盖层：

| # | 条件 | 检查方式 | 失败时行为 |
|---|------|---------|-----------|
| 1 | 本地存在 `passkey_user` 缓存 | 读取 localStorage，非 null | 直接走普通登录，不检查后续条件 |
| 2 | 服务端 `connections` 配置中包含 `passkey` | 在 `GET /auth/connections` 返回的 `idp` 数组中查找 `connection === "passkey"` | 说明当前应用未开启 Passkey，走普通登录 |
| 3 | 当前设备支持平台认证器 | 调用 WebAuthn API `isPlatformAuthenticatorAvailable()` | 设备不支持指纹/面容/PIN，走普通登录 |

#### 判断顺序与性能考量

- 条件 1（本地缓存读取）是同步操作，开销最小，作为第一道过滤
- 条件 2（connections 配置检查）依赖网络请求结果，在 connections 加载完成后才评估
- 条件 3（平台认证器检测）是异步 API 调用，仅在条件 1 和 2 都满足后才发起，避免不必要的系统调用

三个条件全部满足时设置 `showSecurityMask = true`，渲染 `SecurityMask` 组件覆盖在登录表单之上。

#### 遮盖层关闭后的状态

遮盖层关闭是单次会话行为（内存状态），不影响 localStorage 缓存。用户刷新页面后，如果三个条件仍满足，遮盖层会再次出现。

### 6.3 Passkey 登录完整时序

```
┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────┐
│  前端     │      │ /challenge│      │/challenge│      │ /login   │
│ (aegis-ui)│      │  (POST)  │      │  /:cid   │      │  (POST)  │
└────┬─────┘      └────┬─────┘      └────┬─────┘      └────┬─────┘
     │                  │                  │                  │
     │ 1. initiateChallenge               │                  │
     │  { client_id, audience,            │                  │
     │    type: "login",                  │                  │
     │    channel_type: "webauthn" }      │                  │
     ├─────────────────►│                  │                  │
     │                  │                  │                  │
     │  { challenge_id, │                  │                  │
     │    options }     │                  │                  │
     │◄─────────────────┤                  │                  │
     │                  │                  │                  │
     │ 2. convertToPublicKeyOptions()     │                  │
     │    navigator.credentials.get()     │                  │
     │    [用户触摸指纹/面容]               │                  │
     │    convertAssertionResponse()      │                  │
     │                  │                  │                  │
     │ 3. continueChallenge(cid,          │                  │
     │    { proof: assertionJSON })       │                  │
     ├────────────────────────────────────►│                  │
     │                  │                  │                  │
     │  { verified: true,                 │                  │
     │    challenge_token }               │                  │
     │◄────────────────────────────────────┤                  │
     │                  │                  │                  │
     │ 4. login({ connection: "passkey",  │                  │
     │    proof: challenge_token })       │                  │
     ├───────────────────────────────────────────────────────►│
     │                  │                  │                  │
     │  { location: redirect_uri?code=xxx }                  │
     │◄───────────────────────────────────────────────────────┤
     │                  │                  │                  │
     │ 5. window.location.href = location │                  │
```

### 6.4 遮盖层组件结构与交互设计

#### 视觉层次

`SecurityMask` 是一个全屏遮盖层组件，通过绝对定位覆盖在登录表单之上：

| 层级 | 元素 | 说明 |
|------|------|------|
| 顶部 | 标题区 | 固定文案"安全验证" |
| 中部 | 用户身份区 | 头像（圆形裁切，支持 fallback 默认图）+ 昵称 |
| 中部 | 说明文案 | "使用已注册的安全凭证快速登录" |
| 底部 | 主按钮 | "验证身份并登录"，Primary 样式，点击触发 WebAuthn 验证 |
| 底部 | 次按钮 | "使用其他方式登录"，Link 样式，点击关闭遮盖层 |

#### 主按钮行为

点击后执行以下步骤：

1. **终止 Conditional UI**：如果当前有 Conditional Mediation 正在运行（浏览器级别的被动等待），先通过 `AbortController.abort()` 终止它，避免两个 WebAuthn 请求并发竞争导致 `NotAllowedError`
2. **设置加载态**：按钮显示 loading spinner，禁用重复点击
3. **执行 Passkey 登录**：完整走完 Challenge → Assertion → Login 三步流程
4. **处理结果**：
   - 成功：通过 `window.location.href` 跳转到后端返回的 `location`（带 authorization code 的回调地址）
   - 失败：按第 8 节的错误分级模型处理

#### 次按钮行为

1. 将 `showSecurityMask` 设为 `false`，遮盖层组件卸载
2. **不清除缓存**：下次页面加载时遮盖层仍可能出现
3. 普通登录表单显示后，登录页会检测是否应自动激活 Conditional UI（详见 6.5）

### 6.5 遮盖层与 Conditional UI 的协作

WebAuthn Conditional UI（也称 Conditional Mediation）是浏览器提供的被动式 Passkey 发现机制，当用户聚焦到带有 `autocomplete="webauthn"` 的输入框时，浏览器自动弹出 Passkey 选择器。

本方案中 Conditional UI 与 SecurityMask 遮盖层是**互斥**关系，同一时刻只有一种机制处于活跃状态：

#### 状态转换模型

```
登录页加载
  ├─ 三条件满足 → 显示 SecurityMask，Conditional UI 不启动
  │   ├─ 用户点击主按钮 → 模态弹窗方式执行 Passkey 登录（主动触发）
  │   └─ 用户点击次按钮 → 关闭遮盖层 → 激活 Conditional UI（被动等待）
  │
  └─ 三条件不满足 → 显示普通登录表单
      └─ shouldPageHandlePasskey === true → 自动激活 Conditional UI
```

#### 设计理由

- 遮盖层存在时启动 Conditional UI 会造成两个 WebAuthn 操作竞争，导致 `NotAllowedError`
- 遮盖层是"品牌化"体验（显示用户信息），Conditional UI 是"通用"体验（仅浏览器原生提示）
- 遮盖层关闭后激活 Conditional UI 作为兜底，确保不浪费 Passkey 能力

#### `shouldPageHandlePasskey` 计算逻辑

当遮盖层不显示（无缓存或用户主动关闭）时，登录页会自行判断是否应接管 Passkey 激活：

- 如果遮盖层**从未展示**（条件不满足），且 connections 中有 `passkey`，且浏览器支持 Conditional UI → 激活
- 如果遮盖层**已关闭**（用户点击次按钮），且浏览器支持 Conditional UI → 激活
- Conditional UI 通过 `AbortController` 管理生命周期，在组件卸载或手动触发 Passkey 登录时终止

## 7. 后端 Passkey 登录链路

### 7.1 `/auth/connections` 响应中的 Passkey

```json
{
  "idp": [
    {
      "type": "idp",
      "connection": "passkey",
      "identifier": "heliannuuthus.com"
    }
  ]
}
```

`identifier` 为 RP ID，由 `passkey.Provider.Prepare()` → `webauthnSvc.GetRPID()` 填充。

### 7.2 Challenge 流程（Registry 分发机制）

#### 设计原则

Challenge 的创建和验证通过 `authenticator.Registry` 统一分发，`challengeSvc` 不直接依赖具体的 WebAuthn 服务。这一设计使得新增验证方式（如 TOTP、SMS OTP）时，只需注册对应的 `Authenticator` 到 Registry，无需修改 Challenge 服务本身。

#### 接口体系

Registry 中每个 `Authenticator` 实现基础的认证接口（`Type()` / `ConnectionType()` / `Prepare()` / `Authenticate()`）。部分 Authenticator 额外实现能力接口：

| 能力接口 | 适用场景 | 发现方式 | 实现者 |
|---------|---------|---------|--------|
| `ChallengeVerifier` | 需要两阶段验证的方式（先发起 → 再验证） | 类型断言 | Factor（WebAuthn / Email OTP / TOTP）、VChan |
| `ChallengeExchanger` | 需要一步交换的方式（如小程序 code 换手机号） | 类型断言 | 部分 IDP |

`challengeSvc` 通过类型断言（`authenticator.(ChallengeVerifier)`）发现当前 Authenticator 是否具备 Challenge 能力，而非硬编码依赖。

#### Initiate 阶段（创建 Challenge）

```
POST /auth/challenge
  → Handler: 参数校验 + 构建 Challenge 对象
  → challengeSvc.Initiate()
      → 从 Registry 获取 channel_type 对应的 Authenticator
      → 类型断言为 ChallengeVerifier
      → 调用 verifier.Initiate(ctx, challenge)
          → WebAuthn: 根据 channel 是否为空选择 DiscoverableLogin 或 Login
          → 将 WebAuthn session 数据写入 Challenge.Data
  → challengeSvc.Save(): 序列化 Challenge 到 Redis（含 session 数据）
  → Handler: 返回 challenge_id + options
```

**channel 路由规则**：当 `channel` 为空串时，WebAuthn Provider 调用 `BeginDiscoverableLogin()`（Passkey 场景，无需预知用户）；当 `channel` 非空（为用户邮箱或 ID）时，调用 `BeginLogin()`（Factor 场景，指定用户的 `allowCredentials`）。

#### Verify 阶段（验证 Challenge）

```
POST /auth/challenge/:cid
  → Handler: 从 Redis 加载 Challenge 对象（含 session 数据）
  → challengeSvc.VerifyProof()
      → 从 Registry 获取 Authenticator → 类型断言为 ChallengeVerifier
      → 调用 verifier.Verify(ctx, challenge, proof)
          → WebAuthn: 解析 assertion JSON → 调用 FinishLogin
          → 通过 credential ID 反查用户 OpenID
  → Handler: 签发 challenge_token（PASETO v4.public 格式）
      → Claims: { sub: openid, aud: audience, exp: +5min, challenge_id: cid }
```

**Session 传递机制**：WebAuthn 协议要求 `BeginLogin` 和 `FinishLogin` 之间共享 session 数据（包含 challenge nonce、expected credentials 等）。本方案将 session 数据序列化后存入 `Challenge.Data["session"]`，随 Challenge 对象一起持久化到 Redis。Verify 阶段从 Redis 加载 Challenge 时自动恢复 session，TTL 为 5 分钟。

#### Login 阶段

```
POST /auth/login { connection: "passkey", proof: challenge_token }
  → Handler: 获取 AuthFlow，设置当前 connection
  → authenticateSvc.Authenticate()
      → 从 Registry 获取 "passkey" → IDPAuthenticator
      → 调用 passkey.Provider.Login()
          → 验证 challenge_token 的 PASETO 签名和有效期
          → 从 token claims 中提取用户 OpenID
          → 返回 UserInfo
  → Handler: 解析用户身份 → 签发 authorization code → 返回 redirect location
```

### 7.3 Passkey Provider 登录参数映射

```
LoginRequest {
  connection: "passkey"    → flow.SetConnection("passkey")
  proof:      challenge_token → passkey.Provider.Login(ctx, proof, principal, strategy)
  principal:  challenge_id    → 用于关联 WebAuthn session（当前通过 params[0] 传递）
}
```

> TODO：`challengeID` 当前暂用 `principal` 参数传递，后续应从 `challenge_token` claims 中直接提取。

## 8. 失败与降级策略

### 8.1 错误分级模型

Passkey 登录过程中的错误按来源和严重程度分为三级：

| 级别 | 来源 | 含义 | 用户影响 |
|------|------|------|---------|
| **可恢复** | 浏览器 WebAuthn API | 用户主动取消验证弹窗 | 可立即重试 |
| **凭证异常** | 后端验证 / 浏览器 API | 凭证不存在、已删除或不匹配 | 需切换登录方式 |
| **系统错误** | 网络 / 后端服务 | 请求超时、服务不可用等 | 可延迟重试 |

### 8.2 各场景处理策略

| # | 场景 | 错误识别特征 | 行为 | 遮盖层 | 缓存 |
|---|------|------------|------|--------|------|
| 1 | 用户取消系统验证弹窗 | 错误类型为 `NotAllowedError` 或消息包含 `cancel` | 提示"本次验证已取消" | 保持 | 保留 |
| 2 | 凭证不存在/已删除 | 错误消息包含 `not found` 或 `credential` | 提示"未检测到可用的安全凭证" | 关闭，切回普通登录 | 应清除 |
| 3 | 其他验证错误 | 不匹配上述特征的 Error | 提示"验证失败，请重试" | 保持 | 保留 |
| 4 | 设备不支持平台认证器 | 展示判断阶段条件 3 不满足 | 不展示遮盖层，直接走普通登录 | 不展示 | — |
| 5 | 配置中无 `passkey` connection | 展示判断阶段条件 2 不满足 | 同上 | 不展示 | — |
| 6 | 本地无 `passkey_user` 缓存 | 展示判断阶段条件 1 不满足 | 同上 | 不展示 | — |

### 8.3 错误判定优先级

错误处理采用优先匹配策略，按以下顺序判定：

1. **先判断用户主动取消**：通过错误的 `name` 属性（`NotAllowedError`）或消息中的 `cancel` 关键词识别。此类错误不是真正的失败，仅提示用户操作已取消，不做任何状态变更。
2. **再判断凭证异常**：通过错误消息中的 `not found` 或 `credential` 关键词识别。此类错误意味着本地缓存与服务端凭证已不一致，应关闭遮盖层并引导用户使用其他方式登录。
3. **兜底为系统错误**：不匹配以上模式的错误视为临时性故障，提示用户重试但不改变遮盖层或缓存状态。

### 8.4 降级路径

```
遮盖层展示中
  ├─ 用户点击"验证身份并登录"
  │   ├─ 成功 → 重定向到目标应用
  │   ├─ 用户取消 → 提示后保持遮盖层，可再次点击
  │   ├─ 凭证异常 → 关闭遮盖层，切回普通登录表单
  │   └─ 系统错误 → 提示重试，保持遮盖层
  └─ 用户点击"使用其他方式登录"
      └─ 关闭遮盖层 → 激活 Conditional UI（如支持）→ 普通登录表单
```

> **待改进**：场景 2（凭证异常）中应同时清除 localStorage 缓存，当前实现仅关闭遮盖层但未清缓存，导致下次访问仍会展示已无效的遮盖层。

## 9. 登录失败访问控制

### 9.1 整体机制

登录认证内置了基于失败次数的**渐进式访问控制**，通过 `accessctl.Manager` 实现两级递进响应：

| 级别 | 状态码 | 含义 | 触发条件 | 对用户影响 |
|------|--------|------|---------|-----------|
| `ACAllowed` | 允许 | 当前失败次数在安全范围内 | 失败次数 < `captcha_at` | 正常返回认证失败 |
| `ACCaptcha` | 要求人机验证 | 失败次数已达警戒阈值 | 失败次数 ≥ `captcha_at` | 前端动态渲染 Captcha |

每次登录请求的处理流程：

1. **Strike**：记录本次验证尝试（无论成功或失败），根据当前计数返回决策级别
2. **Execute**：调用 Registry 分发到具体的 Authenticator 执行认证
3. **Response**：根据决策级别构建响应——`ACCaptcha` 时返回 HTTP 300 Multiple Choices，`Location` 指向需完成 captcha 的前端流程，并将此状态持久化到 AuthFlow

### 9.2 Rate Limit Key 维度

```
rl:login:{audience}:{connection}:{principal}
```

例如：`rl:login:svc_xxx:staff:user@example.com`

每个维度独立计数，不同 connection（staff / passkey）的失败不会交叉影响。

### 9.3 配置参数

| 参数 | 说明 | 配置路径 |
|------|------|---------|
| `fail_window` | 失败计数滑动窗口时长 | `login.ac.{connection}.fail-window` |
| `captcha_at` | 触发 captcha 的失败次数阈值 | `login.ac.{connection}.captcha-threshold` |

### 9.4 `require_captcha` 响应格式

当失败次数达到 captcha 阈值时，登录流程使用 **HTTP 300 Multiple Choices** 而非 JSON body 指示前端：

- 后端返回 `300 Multiple Choices`，`Location` header 指向当前页并附带 `?action=xxx` 参数
- 前端通过 `Location` header 获取下一步指令，据此渲染 Captcha 组件（Turnstile）

前端处理路径（`VerifyStep` 密码登录场景）：

1. 前端捕获 HTTP 300 响应，读取 `Location` header
2. 若 `Location` 含 `action=captcha` 等参数，动态切换为"需要人机验证"模式：渲染 Captcha 组件（Turnstile）
3. 将已验证标记重置为 false，强制用户完成人机验证后才能再次提交密码
4. 后续密码登录请求会先提交 Captcha token（`connection: "captcha"`），验证通过后后端在 flow 中标记 `captcha.Verified = true`，之后同一 flow 内的密码重试无需再次验证
5. 这一机制仅影响密码登录场景；Passkey 登录因走独立的 Challenge 流程，不涉及密码级别的 Captcha 要求

### 9.5 Challenge 级别的访问控制

Challenge 验证（`challenge/service.go`）有独立的访问控制链：

| 维度 | Key 格式 | 说明 |
|------|---------|------|
| IP 限流 | `rl:create:ip:{remoteIP}` | 防止 IP 级别暴力创建 Challenge |
| 验证失败 | `rl:verify:fail:{audience}:{channel}` | 防止暴力验证 OTP / WebAuthn |

决策与登录级别相同：`ACAllowed → ACCaptcha`。

## 10. UI 文案（当前实现）

| 位置 | 文案 |
|------|------|
| 标题 | `安全验证` |
| 昵称 | `{userHint.nickname}` |
| 副标题 | `使用已注册的安全凭证快速登录` |
| 主按钮 | `验证身份并登录` |
| 次按钮 | `使用其他方式登录` |
| 取消提示 | `本次验证已取消` |
| 凭证失效提示 | `未检测到可用的安全凭证，请使用其他方式登录` |
| 通用失败提示 | `验证失败，请重试` |

## 11. 实施清单

- [x] 登录页新增 Welcome Back 遮盖层组件（`SecurityMask`）
- [x] 接入三条件判断逻辑（缓存/设备能力/connections）
- [x] 个人信息页 Passkey 注册成功后写入缓存（`SecuritySettings` → `passkeyUserCache.writeAfterRegistration()`）
- [x] Passkey 删除后清理缓存（`SecuritySettings` → `passkeyUserCache.clear()`）
- [x] Conditional UI 与遮盖层的互斥协作
- [x] 独立 Passkey 按钮（非遮盖层时的手动触发入口）
- [ ] 凭证失效场景自动清除 localStorage 缓存
- [ ] 缓存过期策略（`updated_at` 超过 N 天自动失效）
- [ ] 补充端到端测试：
  - [ ] 首次无缓存 → 普通登录表单
  - [ ] 有缓存且验证成功 → 重定向
  - [ ] 有缓存但凭证已删除 → 关闭遮盖层 + 清缓存
  - [ ] 用户取消验证 → 保持遮盖层
  - [ ] 关闭遮盖层后 Conditional UI 自动激活

## 12. 兼容性与安全说明

### 12.1 安全边界

| 原则 | 说明 |
|------|------|
| 缓存不参与认证 | localStorage 中的 `passkey_user` 仅用于 UI 提示展示（昵称、头像），不作为身份验证的依据。实际身份由后端 WebAuthn 验签 + PASETO token 确认 |
| 缓存不含高敏字段 | 缓存中仅存储 `uid`、`nickname`、`picture`。**不得**写入邮箱、手机号、token 等可用于身份关联或认证的信息 |
| 缓存可被篡改 | 攻击者修改 localStorage 只能影响 UI 展示（显示错误的昵称/头像），无法绕过后端认证流程 |

### 12.2 并发安全

- **Conditional UI 与模态触发互斥**：浏览器同一时刻只允许一个 `navigator.credentials.get()` 调用。在触发 Passkey 登录前，必须先通过 `AbortController.abort()` 终止正在运行的 Conditional Mediation，否则会产生 `NotAllowedError`
- **WebAuthn Session TTL**：后端 Challenge 对象（含 WebAuthn session 数据）存储在 Redis 中，TTL 为 5 分钟。超过此窗口的 assertion 提交将被拒绝，前端需重新发起 Challenge

### 12.3 浏览器兼容性

| 能力 | 最低版本要求 | 降级行为 |
|------|------------|---------|
| WebAuthn API | Chrome 67+, Safari 13+, Firefox 60+ | 不展示 Passkey 按钮和遮盖层 |
| Platform Authenticator | 取决于设备硬件 | 检测失败时不展示遮盖层 |
| Conditional UI | Chrome 108+, Safari 16+ | 不启动被动 Passkey 发现，不影响主动触发 |
| Discoverable Credentials | 取决于认证器固件 | 部分旧安全密钥不支持，无法用于 Passkey IDP |

### 12.4 登出时的缓存策略

登出操作**不清除** `passkey_user` 缓存。理由：

- Passkey 凭证存储在设备/认证器中，与登录态无关
- 保留缓存可以在用户回访时立即展示 Welcome Back 遮盖层，提升回访体验
- 如需提供"在此设备上移除我的信息"功能，可在登出界面增加可选开关

## 13. API 参考

### 13.1 Challenge API

#### `POST /auth/challenge` — 创建 Challenge

请求：

```json
{
  "client_id": "app_xxx",
  "audience": "svc_xxx",
  "type": "login",
  "channel_type": "webauthn",
  "channel": ""
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `client_id` | string | 是 | 应用 ID |
| `audience` | string | 是 | 目标服务 ID |
| `type` | string | 验证类可选 | 业务场景（`login` / `bind` / `verify` 等） |
| `channel_type` | string | 是 | 验证方式（`webauthn` / `email_otp` / `totp`） |
| `channel` | string | 是 | 验证目标（Passkey 登录时为空串，WebAuthn Factor 时为邮箱） |

响应：

```json
{
  "challenge_id": "ch_xxx",
  "required": null,
  "retry_after": 0
}
```

WebAuthn 类型的响应会额外包含 `options`（`PublicKeyCredentialRequestOptions`）：

```json
{
  "challenge_id": "ch_xxx",
  "options": {
    "publicKey": {
      "challenge": "base64url...",
      "rpId": "heliannuuthus.com",
      "timeout": 300000,
      "userVerification": "preferred",
      "allowCredentials": []
    }
  }
}
```

#### `POST /auth/challenge/:cid` — 验证 Challenge

请求：

```json
{
  "type": "webauthn",
  "proof": "{...assertionJSON}"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `type` | string | 是 | 当前提交的验证类型（`webauthn` / `captcha` / `email_otp`） |
| `proof` | any | 是 | 验证证明（WebAuthn 为 assertion JSON 字符串，OTP 为验证码） |

响应（验证成功）：

```json
{
  "verified": true,
  "challenge_token": "v4.public.xxx..."
}
```

响应（前置条件未满足）：

```json
{
  "verified": false,
  "required": {
    "conditions": [
      {
        "connection": "captcha",
        "config": { "identifier": "0x4AAA...", "strategy": ["turnstile"] },
        "verified": false
      }
    ]
  }
}
```

### 13.2 Login API

#### `POST /auth/login` — 登录

Passkey 登录请求：

```json
{
  "connection": "passkey",
  "proof": "v4.public.challenge_token_xxx..."
}
```

Staff 密码登录请求：

```json
{
  "connection": "staff",
  "strategy": "password",
  "principal": "user@example.com",
  "proof": "my_password"
}
```

Staff Delegate（WebAuthn/Email OTP）登录请求：

```json
{
  "connection": "staff",
  "principal": "user@example.com",
  "proof": "v4.public.challenge_token_xxx..."
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `connection` | string | 是 | 连接标识（`passkey` / `staff` / `github` 等） |
| `strategy` | string | 否 | 认证策略（仅 `staff` 的 `password` 策略需要） |
| `principal` | string | 否 | 身份标识（邮箱；Passkey 登录不需要） |
| `proof` | any | 是 | 认证凭证（密码 / challenge_token） |

成功响应：

```json
{
  "location": "https://app.example.com/callback?code=xxx&state=yyy"
}
```

### 13.3 MFA 管理 API（Iris）

所有 MFA 接口需要 Bearer Token 认证（`Authorization: Bearer {access_token}`）。

#### `GET /user/mfa` — 获取 MFA 状态

响应：

```json
{
  "status": { "totp_enabled": false, "webauthn_count": 2 },
  "credentials": [
    {
      "id": 1,
      "type": "webauthn",
      "credential_id": "base64url_credential_id",
      "last_used_at": "2026-02-10T12:00:00Z"
    }
  ]
}
```

#### `POST /user/mfa` — 设置 MFA（WebAuthn 注册）

**Begin 阶段**请求：

```json
{
  "type": "webauthn",
  "action": "begin"
}
```

响应：

```json
{
  "type": "webauthn",
  "action": "begin",
  "options": { "publicKey": { "...PublicKeyCredentialCreationOptions..." } },
  "challenge_id": "ch_xxx"
}
```

**Finish 阶段**请求：

```json
{
  "type": "webauthn",
  "action": "finish",
  "challenge_id": "ch_xxx",
  "credential": { "id": "...", "rawId": "...", "type": "public-key", "response": { "...attestation..." } }
}
```

响应：

```json
{
  "type": "webauthn",
  "action": "finish",
  "success": true,
  "credential_id": "base64url_credential_id"
}
```

#### `PUT /user/mfa` — 验证 MFA（WebAuthn 验证）

**Begin 阶段**请求：

```json
{
  "type": "webauthn",
  "action": "begin"
}
```

响应（同 Setup Begin，但 `options` 中 `allowCredentials` 包含用户已注册的凭证）。

**Finish 阶段**请求：

```json
{
  "type": "webauthn",
  "action": "finish",
  "challenge_id": "ch_xxx",
  "credential": { "id": "...", "rawId": "...", "type": "public-key", "response": { "...assertion..." } }
}
```

响应：

```json
{
  "type": "webauthn",
  "action": "finish",
  "success": true,
  "openid": "u_xxx"
}
```

#### `PATCH /user/mfa` — 启用/禁用 MFA

请求：

```json
{
  "type": "webauthn",
  "credential_id": "base64url_credential_id",
  "enabled": false
}
```

#### `DELETE /user/mfa` — 删除 MFA

请求：

```json
{
  "type": "webauthn",
  "credential_id": "base64url_credential_id"
}
```

响应：

```json
{ "success": true }
```

## 14. WebAuthn 作为 MFA Factor（Staff Delegate）流程

### 14.1 概述

当 `staff` connection 配置了 `delegate: ["webauthn"]` 时，用户在输入邮箱后可以选择使用安全密钥/指纹代替密码进行登录。

#### 与 Passkey IDP 的本质区别

两者虽然都使用 WebAuthn 协议和相同的底层 `webauthn.Service`，但设计目标不同：

- **Passkey IDP**（`connection: "passkey"`）：作为独立的身份提供者，用户身份未知，使用 Discoverable Credentials 让浏览器/认证器自行选择凭证并返回用户信息。适用于"一键登录"场景。
- **Factor WebAuthn**（`connection: "staff"` + delegate）：作为 staff 连接的认证策略之一，用户身份已知（通过邮箱步骤确认），使用指定用户的 `allowCredentials` 限制可用凭证范围。适用于"知道用户是谁，验证是否是本人"的场景。

#### Delegate 机制说明

`staff` connection 支持多种认证策略，通过 `strategy` 参数（显式密码）或自动推断（challenge_token 即为 delegate）区分：

| 策略 | 参数 | 说明 |
|------|------|------|
| 密码 | `strategy: "password"`, `proof: 密码` | 传统密码认证 |
| Email OTP（delegate） | `proof: challenge_token` | 通过邮箱验证码 Challenge 获取 token |
| WebAuthn（delegate） | `proof: challenge_token` | 通过 WebAuthn Challenge 获取 token |

Delegate 策略的 `proof` 均为 `challenge_token`（PASETO 格式），后端通过验证 token 签名和 claims 确认用户身份，不区分 token 来源是 Email OTP 还是 WebAuthn。

### 14.2 前端流程

WebAuthn Delegate 登录发生在 `VerifyStep` 组件中，用户已经在上一步（邮箱步骤）确认了身份。

#### 步骤说明

| 步骤 | 动作 | 关键参数 | 说明 |
|------|------|---------|------|
| 1 | 创建 WebAuthn Challenge | `channel_type: "webauthn"`, `channel: 用户邮箱` | **注意 `channel` 非空**，后端据此查找该用户已注册的凭证，构建 `allowCredentials` |
| 2 | 浏览器系统弹窗 | `PublicKeyCredentialRequestOptions`（含 `allowCredentials`） | 浏览器仅展示该用户的凭证，非 Discoverable 模式 |
| 3 | 验证 assertion | `proof: assertionJSON` | 后端验证签名，反查用户，签发 `challenge_token` |
| 4 | Login | `connection: "staff"`, `principal: email`, `proof: challenge_token` | **注意 connection 是 `staff`** 而非 `passkey` |
| 5 | 重定向 | `location` | 后端返回含 authorization code 的回调地址 |

#### 与 Passkey IDP 流程的关键差异点

- **步骤 1**：Passkey IDP 的 `channel` 为空串，WebAuthn Factor 的 `channel` 为用户邮箱
- **步骤 2**：Passkey IDP 响应的 `allowCredentials` 为空（让浏览器/认证器自选），Factor 响应的 `allowCredentials` 列出该用户的所有已注册凭证 ID
- **步骤 4**：Passkey IDP 的 `connection` 为 `"passkey"` 且不需要 `principal`，Factor 的 `connection` 为 `"staff"` 且需要 `principal`（邮箱）

#### 错误处理

与 Passkey 登录类似，但处理上下文不同：

- **用户取消**（`NotAllowedError`）：静默忽略，不报错，用户仍在 VerifyStep 中可选择其他方式
- **其他错误**：通过 `onError` 回调向上层组件传递，由 StaffLogin 统一处理错误展示

### 14.3 与 Passkey IDP 的关键差异对照

| 维度 | Passkey IDP | WebAuthn Factor (Staff Delegate) |
|------|-------------|--------------------------------|
| `channel` | 空串 | 用户邮箱（已在邮箱步骤确认） |
| `allowCredentials` | 空（Discoverable） | 非空（指定用户的已注册凭证） |
| `login.connection` | `"passkey"` | `"staff"` |
| `login.principal` | 不需要 | 用户邮箱 |
| 后端 WebAuthn 方法 | `BeginDiscoverableLogin()` | `BeginLogin()` |
| 前端触发组件 | `SecurityMask` / `Passkey` 按钮 | `VerifyStep` 中的"使用安全验证"按钮 |
| 前端用户选择 | 系统弹窗选择凭证 | 系统弹窗选择凭证（受 allowCredentials 限制） |

### 14.4 后端分发链路

Login 请求到达后端后的处理链路：

1. **Handler 层**：绑定请求参数，从 Redis 加载 AuthFlow，设置当前 connection 为 `"staff"`
2. **Authenticate Service**：调用访问控制 Strike → 从 Registry 获取 `"staff"` 对应的 Authenticator
3. **Staff Provider**：接收 `proof`（challenge_token）和 `principal`（邮箱），由于 `strategy` 为空且 `proof` 是 PASETO token 格式，自动识别为 delegate 模式
4. **Token 验证**：验证 challenge_token 的 PASETO v4.public 签名、有效期、`audience` 是否匹配当前服务
5. **身份解析**：从 token claims 中提取用户 OpenID，构建 UserInfo 返回
6. **Handler 层**：根据 UserInfo 解析完整用户身份 → 签发 authorization code → 返回 redirect `location`

Staff Provider 对 delegate 的处理是**token 来源无关**的——无论 challenge_token 是由 WebAuthn 验证还是 Email OTP 验证签发的，只要签名和 claims 合法即可通过认证。这使得新增 delegate 方式（如 TOTP）时，Staff Provider 无需任何修改。

## 15. 已知问题与后续优化

1. **challengeID 传递方式**：当前 Passkey 登录通过 `principal` 参数传递 `challengeID`，语义不够清晰。后续应直接从 `challenge_token` 的 JWT claims 中提取，消除对 `principal` 的滥用。

2. **凭证失效未清缓存**：`SecurityMask` 中检测到凭证不存在时仅关闭遮盖层，未调用 `passkeyUserCache.clear()`。下次访问仍会展示遮盖层。

3. **缓存过期策略**：当前 `updated_at` 字段仅用于调试，未实现自动过期。建议设定合理的 TTL（如 90 天），超期不展示遮盖层。

4. **多设备场景**：用户在设备 A 注册 Passkey 后在设备 B 登录，设备 B 无缓存不会显示遮盖层，但 Conditional UI（如果支持）可作为备选入口。

5. **Passkey 注册时的暂存依赖**：`setPendingUserInfo()` 依赖调用方（`SecuritySettings`）在注册前主动暂存。如果个人信息页重构，需确保此调用链不断。

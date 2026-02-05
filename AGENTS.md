# Helios Agent 规则

本文件包含 AI Agent 在修改此项目时必须遵守的规则。

## 项目架构

Helios 是一个身份与访问管理（IAM）平台，由三个独立的服务模块组成。为了简化部署和开发，这三个服务被融合到一个单体应用中，但在代码层面保持清晰的边界和职责分离。

### 模块概览

```
helios/
├── internal/
│   ├── aegis/      # 认证授权服务（OAuth2/OIDC）
│   ├── hermes/     # 身份数据服务（用户/应用/服务管理）
│   └── zwei/       # 业务网关服务（API 聚合与转发）
├── aegis.config.toml   # Aegis 配置
├── hermes.config.toml  # Hermes 配置
└── zwei.config.toml    # Zwei 配置
```

### Aegis - 认证授权服务

**职责**：处理 OAuth2/OIDC 认证流程，签发和验证 Token。

**核心功能**：
- OAuth2 授权码流程（PKCE）
- 用户认证（多 IdP 支持：微信、支付宝、Telegram、邮箱等）
- JWT Token 签发（Access Token、Refresh Token、ID Token）
- Token 验证与刷新
- 多域（Domain）支持：CIAM（C端用户）、PIAM（B端用户）

**配置文件**：`aegis.config.toml`
- 域签名密钥（sign-key）：Ed25519 JWK，用于签名 JWT
- IdP 配置：各身份提供商的 AppID 和密钥
- 缓存配置：应用、服务、用户等数据的缓存策略

**依赖关系**：
- 依赖 Hermes 获取用户、应用、服务数据
- 通过内存缓存减少对 Hermes 的调用

**路由前缀**：`/auth/*`、`/idps/*`

### Hermes - 身份数据服务

**职责**：管理身份相关的核心数据，提供数据库访问层。

**核心功能**：
- 用户管理（创建、查询、更新用户信息）
- 应用管理（OAuth2 客户端注册与配置）
- 服务管理（资源服务器注册与密钥管理）
- 应用-服务关系管理（授权范围配置）
- 权限关系管理（ReBAC 权限模型）
- 敏感数据加密（手机号、服务密钥等）

**配置文件**：`hermes.config.toml`
- 数据库连接配置（MySQL）
- 数据库加密密钥（enc-key）：用于加密敏感数据
- 服务密钥（secret-key）：用于 Hermes 自身的 CAT 验证

**数据模型**：
- `t_user`：用户表
- `t_application`：应用表（OAuth2 客户端）
- `t_service`：服务表（资源服务器）
- `t_application_service_relation`：应用-服务关系表
- `t_relationship`：权限关系表（ReBAC）
- `t_identity`：用户身份表（多 IdP 绑定）

**路由前缀**：`/hermes/*`（管理 API）

### Zwei - 业务网关服务

**职责**：对外提供统一的 API 网关，聚合和转发请求。

**核心功能**：
- API 路由聚合
- 请求鉴权（验证 Access Token）
- 请求转发与代理
- 业务逻辑编排

**配置文件**：`zwei.config.toml`

**路由前缀**：`/api/*`

### 模块间通信

```
┌─────────────────────────────────────────────────────────────┐
│                        Helios 单体应用                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────┐     调用      ┌─────────┐     调用      ┌─────────┐
│  │  Zwei   │ ──────────► │  Aegis  │ ──────────► │ Hermes  │
│  │ (网关)   │             │ (认证)   │             │ (数据)   │
│  └─────────┘             └─────────┘             └─────────┘
│       │                       │                       │
│       │                       │                       │
│       ▼                       ▼                       ▼
│  zwei.config.toml      aegis.config.toml      hermes.config.toml
│                                                       │
│                                                       ▼
│                                                   MySQL DB
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**调用规则**：
- Zwei → Aegis：验证请求的 Access Token
- Aegis → Hermes：获取用户、应用、服务数据（通过内存缓存）
- Hermes → MySQL：持久化存储

**重要约定**：
- Aegis 不直接访问数据库，所有数据通过 Hermes 获取
- Hermes 负责所有敏感数据的加密/解密
- 缓存层在 Aegis 模块内，存储已解密的明文数据

### 密钥管理

**aegis.config.toml**：
- `aegis.domains.{domain}.sign-key`：域签名密钥（Ed25519 JWK），用于签名 JWT Token

**hermes.config.toml**：
- `db.enc-key`：数据库加密密钥（AES-256），用于加密敏感数据
- `aegis.secret-key`：Hermes 服务密钥（AES-256 JWK），用于验证 CAT

**密钥生成**：使用 `scripts/initialize-hermes.py` 脚本生成所有密钥

---

## 路由规则 - 不可修改

### `/auth/authorize` 端点

**重要：此路由必须保持为 POST 方法，不要修改为 GET！**

```go
authGroup.POST("/authorize", aegisCORS, app.AegisHandler.Authorize)
```

**原因**：
1. 前端有 nginx 网关，会将 `/api/*` 请求转发到后端的 `/auth/*`
2. aegis-ui 通过 `POST /api/authorize` 发起授权请求，网关转发到 `POST /auth/authorize`
3. 使用 POST + form 表单提交授权参数，而不是 GET + query 参数
4. Handler 使用 `ShouldBind` 绑定 form 数据

**请求格式**：
- Method: POST
- Content-Type: application/x-www-form-urlencoded
- Body: client_id, audience, scope, code_challenge, code_challenge_method, state, response_type, redirect_uri(可选)

**禁止操作**：
- 不要将 POST 改为 GET
- 不要将 `ShouldBind` 改为 `ShouldBindQuery`
- 不要修改路由路径 `/auth/authorize`

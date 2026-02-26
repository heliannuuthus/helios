# Helios Claude 规则

本文件包含项目的编码规范和约定，供 AI Agent 和开发者参考。

## 项目结构

```
helios/
├── main.go                          # 应用入口 + 路由注册
├── wire.go / wire_gen.go            # Wire 依赖注入
├── aegis/                           # 认证模块（OAuth2/OIDC 风格认证服务）
│   ├── config/                      # Aegis 配置（缓存、Cookie、Challenge、限流、邮件等）
│   ├── internal/
│   │   ├── authenticate/            # 认证逻辑（IDP/VChan/Factor 三类 Authenticator）
│   │   ├── authenticator/           # Authenticator Registry + 各类 Provider
│   │   │   ├── captcha/             # Captcha 验证器（Turnstile）
│   │   │   ├── factor/              # MFA Factor（Email OTP / TOTP / WebAuthn）
│   │   │   ├── idp/                 # Identity Provider（GitHub/Google/WeChat/Alipay/TT/User/Oper/Passkey）
│   │   │   ├── totp/                # TOTP 验证器
│   │   │   └── webauthn/            # WebAuthn 服务
│   │   ├── authorize/               # 授权逻辑（AuthCode 签发、Token 交换）
│   │   ├── cache/                   # Redis + 本地缓存管理
│   │   ├── challenge/               # Challenge 服务（SFA 三层模型）
│   │   ├── errors/                  # 自定义错误类型
│   │   ├── middleware/              # 认证中间件（Token 验证 + CORS）
│   │   ├── token/                   # Token 服务（PASETO 签发/验证）
│   │   ├── types/                   # 内部类型（AuthFlow 等）
│   │   └── user/                    # 用户服务（缓存层封装）
│   ├── handler.go                   # HTTP Handler（路由处理函数）
│   ├── init.go                      # 模块初始化（Redis/Cache/Token/Mail/Provider/Registry）
│   ├── consts.go                    # HTTP 常量
│   ├── types.go                     # 请求/响应类型
│   └── middleware.go                # CAT 认证中间件
├── hermes/                          # 数据模块（身份与访问管理数据层）
│   ├── config/                      # Hermes 配置 + DB 初始化
│   ├── models/                      # 数据模型（公开，aegis/iris 依赖）
│   ├── upload/                      # 文件上传 Handler
│   ├── handler.go                   # HTTP Handler
│   ├── service.go                   # 核心服务（Domain/Application/Service/Relationship/Group）
│   ├── user.go                      # 用户数据服务
│   ├── credential.go                # 凭证数据服务
│   └── types.go                     # 请求/响应类型
├── iris/                            # 用户信息模块（用户 Profile/MFA/Identity 管理）
│   ├── config/                      # Iris 配置
│   └── handler.go                   # HTTP Handler
├── zwei/                            # 业务模块（菜谱/推荐/收藏/历史等）
│   ├── config/                      # Zwei 配置 + DB 初始化
│   ├── internal/
│   │   └── models/                  # 业务数据模型（仅 zwei 内部使用）
│   ├── favorite/                    # 收藏
│   ├── history/                     # 浏览历史
│   ├── home/                        # 首页
│   ├── preference/                  # 用户偏好
│   ├── recipe/                      # 菜谱
│   ├── recommend/                   # 推荐
│   ├── tag/                         # 标签
│   └── types_api.go                 # API 类型
└── pkg/                             # 公共工具包
    ├── config/                      # 全局基础配置（Cfg 类型、Load、App/Server/Log/R2）
    └── ...                          # 其他工具包（database、logger、mail、patch 等）
```

## 模块职责与依赖关系

```
main.go + wire.go
├── aegis/      认证模块（不直连数据库，通过 hermes 获取数据）
│   └── depends on: hermes, pkg
├── hermes/     数据模块（身份与访问管理数据，Hermes DB）
│   └── depends on: pkg
├── iris/       用户信息模块（用户 Profile/MFA，使用 Hermes DB）
│   └── depends on: aegis, hermes, pkg
└── zwei/       业务模块（菜谱业务数据，Zwei DB）
    └── depends on: pkg
```

**关键约束**：
- Aegis 不直接访问数据库，所有数据通过 Hermes 服务获取
- Hermes 的 `models/` 是公开包（aegis 和 iris 依赖其数据类型）
- Zwei 的 `internal/models/` 是内部包（仅 zwei 使用）
- 各模块配置独立（`aegis/config/`、`hermes/config/`、`iris/config/`、`zwei/config/`）
- 各模块自行初始化数据库连接（hermes 和 zwei 在各自 config 包中提供 `InitDB()`）

## 配置架构

- `pkg/config/` — 全局基础配置：`Cfg` 类型、`Load()`、各模块配置单例、App/Server/Log/R2 通用配置
- `aegis/config/` — Aegis 认证配置：Cookie、Endpoint、Cache、Mail、Challenge、限流、Secret
- `hermes/config/` — Hermes 数据配置：DB 连接、域签名密钥、加密密钥、Aegis 集成
- `iris/config/` — Iris 配置：Aegis audience、密钥
- `zwei/config/` — Zwei 业务配置：DB 连接

## 代码质量检查

每次写完功能后，必须执行 `golangci-lint` 进行检查和自动修复：

```bash
golangci-lint run --fix ./...
```

如果存在无法自动修复的问题，需手动修复后再提交。

## 部分更新（PATCH）规范

### 设计原则

项目采用 **JSON Merge Patch (RFC 7396)** 语义处理所有资源的部分更新操作。

核心规则：

- **HTTP 方法**：所有部分更新 API 使用 `PATCH`，不使用 `PUT`（`PUT` 仅用于全量替换语义）
- **三态语义**：通过 `pkg/patch.Optional[T]` 泛型类型精确区分"未传"、"有值"和"设为 null"
- **禁止使用 `*T` 指针作为 Update 请求的可选字段**：指针无法区分"字段缺失"和"显式 null"

### `pkg/patch` 工具包

| 类型/函数            | 用途                                                                  |
| -------------------- | --------------------------------------------------------------------- |
| `Optional[T]`        | 三态可选字段：零值=未传，`HasValue()`=有值，`IsNull()`=显式 null      |
| `Field(column, opt)` | 从 `Optional` 构造单个数据库更新字段                                  |
| `Collect(fields...)` | 收集所有 `Field` 结果，构建 `map[string]any` 供 GORM `Updates()` 使用 |
| `Set[T](v)`          | 手动创建一个有值的 `Optional`（用于代码内部构造）                     |
| `Null[T]()`          | 手动创建一个 null 的 `Optional`（用于代码内部构造）                   |

### 三态语义对照

| JSON 请求体        | `Optional` 状态       | 数据库效果        |
| ------------------ | --------------------- | ----------------- |
| 字段缺失           | `IsPresent() = false` | 不更新该字段      |
| `"field": "value"` | `HasValue() = true`   | 更新为 value      |
| `"field": null`    | `IsNull() = true`     | 更新为数据库 NULL |

### 编写 Update 请求体的规范

**请求类型定义**（`types.go`）：

```go
// 所有可选更新字段使用 patch.Optional[T]
type ServiceUpdateRequest struct {
    Name        patch.Optional[string] `json:"name"`
    Description patch.Optional[string] `json:"description"`
}
```

**Service 层更新逻辑**（`service.go`）：

```go
func (s *Service) UpdateService(ctx context.Context, id string, req *ServiceUpdateRequest) error {
    // 使用 patch.Collect + patch.Field 构建更新 map
    updates := patch.Collect(
        patch.Field("name", req.Name),
        patch.Field("description", req.Description),
    )

    if len(updates) == 0 {
        return nil
    }

    return s.db.WithContext(ctx).Model(&models.Service{}).
        Where("service_id = ?", id).Updates(updates).Error
}
```

**需要特殊转换的字段**（如 JSON 序列化、时间解析）手动处理：

```go
// 示例：过期时间字段，null 表示清除，有值需要解析
if req.ExpiresAt.IsPresent() {
    if req.ExpiresAt.IsNull() {
        updates["expires_at"] = nil
    } else {
        exp, err := time.Parse(time.RFC3339, req.ExpiresAt.Value())
        if err != nil {
            return fmt.Errorf("解析过期时间失败: %w", err)
        }
        updates["expires_at"] = exp
    }
}
```

### 已应用的模块

以下模块的更新 API 已全部遵循此规范：

- `hermes/` — 服务、应用、关系、组的更新
- `iris/` — 用户信息更新
- `zwei/recipe/` — 菜谱更新

### 新增更新 API 的 checklist

1. 请求类型中的可选字段使用 `patch.Optional[T]`，而非 `*T`
2. Service 层使用 `patch.Collect` + `patch.Field` 构建更新 map
3. 路由注册使用 `.PATCH()` 方法
4. Handler 注释标注 `PATCH /path`
5. Create 请求体仍可使用 `*T` 指针（创建时不需要三态语义）

## 前端组件规范（Atlas / Aegis-UI）

两个前端项目（`atlas/`、`aegis-ui/`）均使用 **Ant Design 6** 作为 UI 组件库。

### 必须使用 antd 组件替代原生 HTML 元素

| 原生 HTML | antd 替代 | 说明 |
| --- | --- | --- |
| `<button>` | `Button` | 所有按钮必须使用 antd Button，根据场景选择 type（primary/default/text/link） |
| `<input>` | `Input` / `Input.TextArea` / `InputNumber` | 表单输入统一用 antd Input 系列 |
| `<select>` / `<option>` | `Select` | 下拉选择器 |
| `<table>` | `Table` | 数据表格 |
| `<form>` | `Form` + `Form.Item` | 表单容器 |
| `<img>` | `Image` | 图片展示，支持预览、加载状态、错误处理 |
| 加载占位 `<div>加载中...</div>` | `Spin` | 加载状态统一使用 Spin |
| `<input type="checkbox">` | `Checkbox` | 复选框 |
| `<input type="radio">` | `Radio` | 单选框 |

### 允许保留原生 HTML 的场景

- **布局 `<div>`、`<span>`**：结构性元素，无需替换
- **语义化文档内容**：`<h1>`-`<h6>`、`<p>`、`<ul>`/`<ol>`/`<li>`（如 Terms、Privacy 等纯文档页面）
- **外链 `<a href>`**：简单外部链接可保留原生
- **高度自定义交互组件**：如 OTP 输入框（`<input>` with 特殊键盘/粘贴处理）、Consent scope 选择器等
- **SVG 图形**：图标和装饰性 SVG

### 新增 UI 组件的 checklist

1. 优先从 antd 组件库中寻找合适的组件
2. 如确需自定义，考虑基于 antd 组件扩展而非使用原生 HTML
3. 按钮类交互元素**必须**使用 `antd Button`
4. 图片展示**必须**使用 `antd Image`
5. 加载状态**必须**使用 `antd Spin`

## Agent 注意事项

1. **不要修改** `/auth/authorize` 路由方法和路径
2. **不要使用** `*T` 指针做 PATCH 请求的可选字段，必须用 `patch.Optional[T]`
3. **Aegis 模块不直接访问数据库**，所有数据通过 Hermes 获取
4. **API 调用必须经过 services 层**，不要在组件中直接使用底层库
5. **修改代码后**必须运行 `golangci-lint run --fix ./...` 确认无错误
6. **提交前**确保 import 排序正确（三段式：标准库 / 第三方 / 项目内部）
7. **密钥和 token** 不要硬编码，不要提交 `.env` 文件
8. **各模块配置**在各自的 `config/` 包中，基础 `Cfg` 类型和加载机制在 `pkg/config/`

# Aegis SDK — ReBAC 关系鉴权设计

## 概述

Aegis SDK 的关系鉴权遵循 ReBAC（Relationship-Based Access Control）模型，以 Zanzibar 风格的关系元组作为核心抽象。SDK 负责认证（token 验证）和鉴权请求的发起，权限图的存储与遍历由 Aegis 服务端完成。

布尔组合逻辑的职责划分：
- **同资源多 relation 推导**（如 `view = owner + editor + viewer`）→ 服务端 Schema 定义
- **跨资源/混合场景组合**（如 `relation.Expr("service:x#admin") + Factor("sms")`）→ SDK 侧 `AnyOf`/`AllOf`/`Not` 并发查询

## 核心模型

### 关系元组（Relation Tuple）

每一条鉴权条件对应一个五元组：

```
subject_type:subject_id  #relation  object_type:object_id
```

| 字段 | 说明 | 要求 |
|------|------|------|
| SubjectType | 主体类型 | 为空时由 Enforce 层从 token 推断（user/app） |
| SubjectID | 主体标识 | 为空时由 Enforce 层从 token 推断（openID/clientID） |
| Relation | 关系名称 | **必填**，单一标识符 |
| ObjectType | 资源类型 | **必填**，业务方自行定义的资源类型 |
| ObjectID | 资源标识 | **必填**，具体资源实例 ID |

Object 没有默认值。每条关系都绑定到具体的资源实例，SDK 不做通配或自动补全。

所有字段均支持 `{key}` 占位符绑定，运行时通过 `Resolve(func(string) string)` 替换为实际值。占位符的解析策略由调用方决定——web 场景可从路由参数/请求体提取，非 web 场景可从任意来源提取。

### Subject 推断规则

Subject 推断在 **Enforce 层**（`web` 包）完成，不在 `relation` 包或 `Manager.Check` 中：

- SubjectType/SubjectID 为空时从 token 推断：
  - UserAccessToken（已 Identified）→ `subjectType=user, subjectID=openID`
  - ServiceAccessToken / ClientToken → `subjectType=app, subjectID=clientID`
- 业务方可通过 `.As()` 或 `QualifySubject()` 显式指定，跳过推断

## Check API 设计

### Manager.Check — 单 tuple 查询

```go
func (m *Manager) Check(ctx context.Context, audience,
    subjectType, subjectID, relation, objectType, objectID string) (bool, error)
```

- 单 relation 单次查询，返回 `(bool, error)`
- 不接收 token 参数，只需 `audience` 签发 CT 做服务间认证
- 不做 subject 推断，所有字段由调用方填好
- 请求体：`{subject_type, subject_id, relation, object_type, object_id}`
- 响应体：`{allowed: bool}`
- 错误处理：网络超时、服务端 5xx 等一律视为 check 失败，Enforce 层返回 403（fail-closed）

### 服务端 Schema

服务端按服务维度构建关系图谱，定义 relation 间的推导规则（Zanzibar namespace configuration 风格）：

```
definition service {
    relation owner: user
    relation admin: user
    relation editor: user
    relation viewer: user

    permission manage = owner + admin
    permission edit = manage + editor
    permission view = edit + viewer
}

definition document {
    relation parent: folder
    relation editor: user
    relation viewer: user

    permission view = editor + viewer + parent->viewer
}
```

SDK 只需查单个 permission/relation，服务端按 Schema 展开并遍历关系图。Schema 设计独立于 Check API，两者互不影响。

### 并发查询策略

SDK 侧 `AnyOf`/`AllOf`/`Not` 通过 goroutine 并发 Enforce + context cancel 短路：

- **AnyOf**：并发执行，任一成功即 cancel 剩余，返回 nil
- **AllOf**：errgroup 并发执行，任一失败即 cancel 剩余，返回 error
- **Not**：单个 Enforce 取反，不涉及并发

## relation 包 API 设计

`relation` 包（`pkg/aegis/utils/relation`）是**纯数据层**，负责元组的构造和占位符解析。不依赖 context、token、web 或任何运行时概念。

### Tuple — 最终产物

```go
type Tuple struct {
    SubjectType string
    SubjectID   string
    Relation    string
    ObjectType  string
    ObjectID    string
}
```

### 构造方式一：Expr（Zanzibar 元组字符串）

`relation.Expr(s)` 解析完整的 Zanzibar 元组表达式，要求包含 `#`（object 和 relation 必须存在）：

```go
relation.Expr("service:{path.id}#admin")
relation.Expr("service:zwei#admin@user:alice")
relation.Expr("zone:{path.zid}#control@device:{path.did}")
```

解析规则：
- `#` 必须存在 — `#` 左边为 `objectType:objectID`，右边为 relation 部分
- `@` 可选 — `@` 右边为 `subjectType:subjectID`
- 不含 `#` → panic（配置错误快速暴露）

返回 `*Expression`，持有预解析的元组（可能含占位符）。

### 构造方式二：Build 链式构建

`relation.Build(rel)` 从纯 relation 标识符开始，通过 `.On()` 补全 object，`.As()` 可选补全 subject：

```go
relation.Build("admin").On("service", "{path.id}")
relation.Build("control").On("zone", "{path.zid}").As("device", "{path.did}")
```

`Build(rel)` 返回 `*Builder`，未调用 `.On()` 前不能 Resolve（object 缺失会报错）。

### 构造方式三：Qualify / QualifySubject 快捷构造

```go
relation.Qualify("admin", "service:{path.id}")
relation.Qualify("editor", "document:{path.doc_id}")

relation.QualifySubject("device:{path.did}", "control", "zone:{path.zid}")
relation.QualifySubject("user:{body.open_id}", "admin", "service:zwei")
```

### Resolve — 占位符替换

所有构造方式最终通过 `Resolve` 产出完整的 `*Tuple`：

```go
func (e *Expression) Resolve(fn func(string) string) *Tuple
func (b *Builder) Resolve(fn func(string) string) *Tuple
```

`fn` 接收占位符内的 key（如 `path.id`、`body.user.name`），返回实际值。`relation` 包不关心值从哪来——可以是 HTTP path 参数、token 字段、gRPC metadata、环境变量等任何来源。

Resolve 时校验 object 和 relation 是否完整，不完整则 panic。

### HasBinding — 检查是否含占位符

```go
func (e *Expression) HasBinding() bool
func (b *Builder) HasBinding() bool
```

无占位符时可跳过 Resolve，直接取静态 Tuple。

### 三种构造方式对比

| 入口 | 风格 | 适合场景 |
|------|------|---------|
| `relation.Expr(s)` | Zanzibar 字符串一把写完 | 简洁，一行搞定 |
| `relation.Build(r).On().As()` | 链式构建 | relation 固定，object/subject 动态 |
| `relation.Qualify` / `QualifySubject` | 参数式 | 可读性优先 |

## web/requirement 包 API 设计

Requirement 相关的所有类型和函数定义在 `web/requirement` 子包中（`pkg/aegis/web/requirement`），`web` 包通过别名引用：

```go
import reqr "github.com/heliannuuthus/helios/pkg/aegis/web/requirement"
```

### Requirement 接口

```go
// package requirement

type Requirement interface {
    Enforce(ctx context.Context) error
}
```

### Relation — 元组 Requirement 包装

`reqr.Relation()` 接收 `relation` 包的构造产物，返回 `Requirement`：

```go
// 接收 *Expression
reqr.Relation(relation.Expr("service:{path.id}#admin"))

// 接收 *Builder（已 On）
reqr.Relation(relation.Build("admin").On("service", "{path.id}"))

// 接收 Qualify 结果
reqr.Relation(relation.Qualify("admin", "service:{path.id}"))
```

Enforce 时：
1. 构建 resolver 函数（从 context 中的 Params 做 dotpath 解析）
2. 调用 `Resolve(resolver)` 得到完整 `*Tuple`
3. Subject 为空 → 从 TokenContext 中的 AccessToken 推断
4. 调用 `Manager.Check()` 发起远程查询
5. Check 失败（网络错误/超时/5xx）→ 返回 `ErrForbidden`（fail-closed）

### 布尔组合

```go
reqr.AnyOf(
    reqr.Relation(relation.Expr("service:{path.id}#admin")),
    reqr.Relation(relation.Expr("service:{path.id}#editor")),
)

reqr.AllOf(
    reqr.AnyOf(
        reqr.Relation(relation.Expr("service:{path.id}#admin")),
        reqr.Relation(relation.Expr("service:{path.id}#editor")),
    ),
    reqr.Not(reqr.Relation(relation.Expr("service:{path.id}#banned"))),
)
```

`AnyOf`/`AllOf`/`Not` 是通用的 Requirement 组合器，可用于 `Relation`、`Factor`、`User` 等所有 Requirement 类型。

**并发实现：**

- **AnyOf**：goroutine 并发执行，任一成功即 cancel 剩余
- **AllOf**：`errgroup.WithContext` 并发执行，任一失败即 cancel 剩余
- **Not**：单个 Enforce 取反

### 其他 Requirement

```go
reqr.Factor(types ...string)   // 要求携带 ChallengeToken 且 type 匹配
reqr.User()                     // 要求 token 为已 Identified 的 UserAccessToken
```

## 参数绑定

`{key}` 占位符在运行时由 Enforce 层解析。Web 场景下，`Params` 是一个嵌套 `map[string]any`，按来源分为 `path`、`query`、`body` 三个 namespace，通过 dotpath 精确访问：

```go
// 路由：PATCH /services/:service_id
relation.Build("admin").On("service", "{path.service_id}")

// 运行时：PATCH /services/svc-123
// resolver("path.service_id") → "svc-123"
// → objectType=service, objectID=svc-123

// body 嵌套访问：POST /transfer  body: {"target": {"user_id": "u-456"}}
relation.QualifySubject("user:{body.target.user_id}", "receive", "account:{path.account_id}")
```

`Params` 由框架适配层（GinGuard）在认证时一次性构建并注入 context，Enforce 时构造 resolver 函数传给 `Resolve`。

非 web 场景的调用方自行实现 resolver 函数，`relation` 包不关心来源。

## 数据流

```
路由注册                        请求到达                         服务端
──────────                    ──────────                      ──────────
relation.Expr(...)            GinGuard.Require()              Schema 展开
  ↓ 预解析                      ↓ Authenticate                view = edit + viewer
*Expression                   TokenContext + Params            edit = manage + editor
  (持有占位符)                   ↓ Enforce                     manage = owner + admin
                               Resolve(resolver)                 ↓
                               → 完整 *Tuple                  关系图遍历
                               推断 Subject（如为空）             ↓
                                 ↓ Manager.Check              结果返回
                               HTTP POST /check
                                 {sub, rel, obj}

                        AnyOf/AllOf 场景：
                        ──────────────────
                        并发 goroutine × N
                        context cancel 短路
                        ≈ 单次 RTT 延迟
```

## 包结构

```
pkg/aegis/
├── utils/
│   └── relation/
│       ├── tuple.go          # Tuple 结构体 + ParseTuple + ParseEntity
│       ├── builder.go        # Expr / Build / Qualify / QualifySubject
│       │                     # Expression / Builder 类型
│       │                     # Resolve(func(string) string) → *Tuple
│       │                     # HasBinding
│       └── tuple_test.go
├── token/
│   └── manager.go            # Manager.Check(ctx, audience, sub, rel, obj) (bool, error)
└── web/
    ├── requirement/
    │   ├── requirement.go    # Requirement 接口
    │   ├── relation.go       # reqr.Relation() — 包装 relation 包产物为 Requirement
    │   │                     # enforceRelation — Resolve + Subject 推断 + Check
    │   ├── factor.go         # reqr.Factor()
    │   ├── user.go           # reqr.User()
    │   └── combinator.go     # AnyOf / AllOf / Not（并发组合器）
    ├── binding.go            # Params（嵌套 map + dotpath Get）+ resolver 构造
    ├── factory.go            # Factory / Middleware / Authenticate
    ├── manager.go            # 全局 Manager（InitManager / GetTokenManager）
    ├── context.go            # TokenContext
    └── guard/
        └── gin.go            # GinGuard + extractParams
```

`web` 包通过别名引用 requirement 子包：

```go
import reqr "github.com/heliannuuthus/helios/pkg/aegis/web/requirement"
```

## 使用示例

```go
import (
    "github.com/heliannuuthus/helios/pkg/aegis/utils/relation"
    "github.com/heliannuuthus/helios/pkg/aegis/web"
    reqr "github.com/heliannuuthus/helios/pkg/aegis/web/requirement"
    "github.com/heliannuuthus/helios/pkg/aegis/web/guard"
)

// 初始化
web.InitManager("http://auth.example.com", seedProvider)

// 路由注册
factory := web.NewFactory()
g := guard.NewGinGuard(factory.WithAudience("my-service"))

// 纯认证
r.Use(g.Require())

// 单 relation — Expr 一把写完
r.POST("/admin/config", g.Require(
    reqr.Relation(relation.Expr("service:my-service#manage")),
), handler)

// 链式构建 — path 参数绑定
r.PATCH("/services/:id", g.Require(
    reqr.Relation(relation.Build("admin").On("service", "{path.id}")),
), handler)

// Qualify 快捷方式
r.GET("/documents/:doc_id", g.Require(
    reqr.Relation(relation.Qualify("view", "document:{path.doc_id}")),
), handler)

// 多条件组合（并发查询 + 短路）
r.DELETE("/posts/:id", g.Require(
    reqr.AllOf(
        reqr.AnyOf(
            reqr.Relation(relation.Expr("post:{path.id}#admin")),
            reqr.Relation(relation.Expr("post:{path.id}#owner")),
        ),
        reqr.Not(reqr.Relation(relation.Expr("post:{path.id}#banned"))),
    ),
), handler)

// 完整三元组 — 显式 subject
r.POST("/devices/:did/zones/:zid", g.Require(
    reqr.Relation(relation.QualifySubject("device:{path.did}", "control", "zone:{path.zid}")),
), handler)

// 混合 Requirement 类型
r.PUT("/settings", g.Require(
    reqr.AllOf(
        reqr.User(),
        reqr.Relation(relation.Expr("service:my-service#admin")),
    ),
), handler)
```

### 非 web 场景（直接使用 relation + Manager）

```go
// 构造元组
expr := relation.Expr("document:doc-123#view@user:alice")
tuple := expr.Resolve(func(key string) string { return key })

// 直接调用 Check
allowed, err := manager.Check(ctx, "my-service",
    tuple.SubjectType, tuple.SubjectID,
    tuple.Relation,
    tuple.ObjectType, tuple.ObjectID,
)
```

## 设计决策

### 为什么 object 没有默认值（不支持通配符）

ReBAC 中每条关系绑定到具体资源实例。`service` 是 Aegis 平台侧定义的资源类型，业务方的关系图谱中有自己的资源类型（`document`、`workspace` 等），SDK 无法替业务方决定 object 是什么。不指定 object 的查询语义不完整，应在构造阶段强制要求。

### 为什么 relation 包是纯数据层

`relation` 包只负责元组的构造和占位符解析，不依赖 context、token、web 等运行时概念。占位符替换通过 `Resolve(func(string) string)` 注入，调用方决定值从哪来。这样 web 场景（从 HTTP 请求提取）和非 web 场景（gRPC、CLI 等）都能复用同一套元组构造逻辑。

### 为什么 SDK 的布尔组合用并发单查而非表达式树

1. 延迟接近：并发 N 次 HTTP ≈ 单次 RTT（受最慢请求制约）
2. 服务端简单：只需实现单 tuple 查询 + Schema 展开，不需要递归表达式求值器
3. SDK 简单：errgroup + context cancel，几行代码
4. Schema 覆盖主要场景：同资源的 relation 组合在服务端 Schema 里定义，SDK 不需要重复表达

### 为什么 Check 失败一律 403（fail-closed）

鉴权系统的安全原则：无法确认权限时拒绝访问。网络超时、服务端 5xx 等异常情况不应放行请求。对请求方来说，无论是"没有权限"还是"无法确认权限"，结果一样——被拒绝。

### 为什么 Relation 内不支持布尔表达式

1. 一个 tuple 对应一条关系，组合发生在 tuple 之间而非 tuple 内部
2. 符合 ReBAC 标准：Zanzibar / SpiceDB / OpenFGA 的 check 均为单 relation 查询
3. 同资源的 relation 组合交由服务端 Schema 处理

## TODO（待实现）

- [ ] `utils/relation/builder.go`: 新增 `Expr` / `Build` / `Qualify` / `QualifySubject` + `Resolve`
- [ ] `utils/relation/tuple.go`: 删除 `*` 通配符默认值，object 字段默认空
- [ ] `token/manager.go`: Check 签名简化为单 tuple `(bool, error)`，删除 subject 推断，删除旧 request/response 结构
- [ ] `web/requirement/requirement.go`: 定义 `Requirement` 接口
- [ ] `web/requirement/relation.go`: `reqr.Relation()` 包装函数 + `enforceRelation`（Resolve + Subject 推断 + Check）
- [ ] `web/requirement/factor.go`: `reqr.Factor()` 从现有 `web/requirement.go` 迁入
- [ ] `web/requirement/user.go`: `reqr.User()` 从现有 `web/requirement.go` 迁入
- [ ] `web/requirement/combinator.go`: `AnyOf` goroutine 并发 + context cancel 短路，`AllOf` errgroup 并发 + context cancel 短路，`Not` 取反
- [ ] `web/guard/gin.go`: `g.Require()` 参数类型改为 `reqr.Requirement`
- [ ] 服务端 Schema 设计（独立文档）

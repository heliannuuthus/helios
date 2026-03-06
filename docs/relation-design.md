# Aegis SDK — ReBAC 关系鉴权设计

## 概述

Aegis SDK 的关系鉴权遵循 ReBAC（Relationship-Based Access Control）模型，以 Zanzibar 风格的关系元组作为核心抽象。SDK 负责认证（token 验证）和鉴权请求的发起，权限图的存储与遍历由 Aegis 服务端完成。

布尔组合逻辑的职责划分：
- **同资源多 relation 推导**（如 `view = owner + editor + viewer`）→ 服务端 Schema 定义
- **跨资源/混合场景组合**（如 `Relation("admin") + Factor("sms")`）→ SDK 侧 `AnyOf`/`AllOf`/`Not` 并发查询

## 核心模型

### 关系元组（Relation Tuple）

每一条鉴权条件对应一个五元组：

```
subject_type:subject_id  #relation  object_type:object_id
```

| 字段 | 说明 | 默认值 |
|------|------|--------|
| SubjectType | 主体类型 | 从 token 推断（user/app） |
| SubjectID | 主体标识 | 从 token 推断（openID/clientID） |
| Relation | 关系名称 | 必填，单一标识符 |
| ObjectType | 资源类型 | `*`（通配） |
| ObjectID | 资源标识 | `*`（通配） |

所有字段均支持 `{source.key}` 参数绑定，运行时从请求参数中提取实际值。

来源前缀：
- `path` — 路由路径参数（如 `:id`）
- `query` — URL 查询参数
- `body` — 请求体字段，支持嵌套 dotpath（如 `body.user.id`）

### Subject 推断规则

Subject 推断在 SDK 的 Enforce 层完成（`enforceRelation`），不在 `Manager.Check` 中：

- SubjectType/SubjectID 为空时从 token 推断：
  - UserAccessToken（已 Identified）→ `subjectType=user, subjectID=openID`
  - ServiceAccessToken / ClientToken → `subjectType=app, subjectID=clientID`
- 业务方可通过 `.As()` 或 `QualifySubject()` 覆盖

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

### 服务端 Schema

服务端定义 relation 间的推导规则（Zanzibar namespace configuration 风格）：

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

SDK 只需查单个 permission/relation，服务端按 Schema 展开并遍历关系图。

### 并发查询策略

SDK 侧 `AnyOf`/`AllOf`/`Not` 通过 goroutine 并发 Enforce + context cancel 短路：

- **AnyOf**：并发执行，任一成功即 cancel 剩余，返回 nil
- **AllOf**：errgroup 并发执行，任一失败即 cancel 剩余，返回 error
- **Not**：单个 Enforce 取反，不涉及并发

## SDK API 设计

### 构造方式一：Relation（统一入口）

`Relation(s string)` 自动识别输入格式：

```go
// 纯 relation（等同于 *:*#admin，subject 从 token 推断）
Relation("admin")

// Zanzibar 元组格式
Relation("service:zwei#admin")
Relation("service:{path.service_id}#editor")
Relation("service:zwei#admin@user:alice")
Relation("zone:{path.zid}#control@device:{path.did}")

// 链式补充 object / subject
Relation("admin").On("service", "{path.service_id}")
Relation("admin").On("service", "zwei").As("device", "{path.device_id}")
```

解析规则：
- 含 `#` → `#` 左边为 `objectType:objectID`，右边为 relation 部分
- 含 `@` → `@` 右边为 `subjectType:subjectID`
- 无 `#` 无 `@` → 整体视为 relation，object 默认 `*:*`

### 构造方式二：Qualify / QualifySubject

字段式构造，参数为 `type:id` 格式的实体引用：

```go
// subject 从 token 推断
Qualify("admin", "service:zwei")
Qualify("editor", "document:{path.doc_id}")

// 完整三元组
QualifySubject("device:{path.did}", "control", "zone:{path.zid}")
QualifySubject("user:{body.open_id}", "admin", "service:zwei")
```

### 布尔组合

```go
// 任一满足（并发查询）
AnyOf(Relation("admin"), Relation("editor"))

// 全部满足（并发查询）
AllOf(Relation("admin"), Relation("active"))

// 取反
Not(Relation("banned"))

// 嵌套组合
AllOf(
    AnyOf(Relation("admin"), Relation("editor")),
    Not(Relation("banned")),
)
```

`AnyOf`/`AllOf`/`Not` 是通用的 Requirement 组合器，可用于 `Relation`、`Factor`、`User` 等所有 Requirement 类型。

### 设计决策

**为什么 SDK 的布尔组合用并发单查而非表达式树？**

1. 延迟接近：并发 N 次 HTTP ≈ 单次 RTT（受最慢请求制约）
2. 服务端简单：只需实现单 tuple 查询 + Schema 展开，不需要递归表达式求值器
3. SDK 简单：errgroup + context cancel，几行代码
4. Schema 覆盖主要场景：同资源的 relation 组合在服务端 Schema 里定义，SDK 不需要重复表达

**为什么 Relation 内不支持布尔表达式？**

1. 一个 tuple 对应一条关系，组合发生在 tuple 之间而非 tuple 内部
2. 符合 ReBAC 标准：Zanzibar / SpiceDB / OpenFGA 的 check 均为单 relation 查询
3. 同资源的 relation 组合交由服务端 Schema 处理

## 参数绑定

`{source.key}` 占位符在运行时由 `Params` 解析。`Params` 是一个嵌套 `map[string]any`，按来源分为 `path`、`query`、`body` 三个 namespace，通过 dotpath 精确访问：

```go
// 路由：PATCH /services/:service_id
Relation("admin").On("service", "{path.service_id}")

// 运行时：PATCH /services/svc-123
// → objectType=service, objectID=svc-123

// body 嵌套访问：POST /transfer  body: {"target": {"user_id": "u-456"}}
QualifySubject("user:{body.target.user_id}", "receive", "account:{path.account_id}")
```

`Params` 由框架适配层（GinGuard）在认证时一次性构建并注入 context，Enforce 时自动取用。

## 数据流

```
路由注册                        请求到达                         服务端
──────────                    ──────────                      ──────────
Relation("view")              GinGuard.Require()              Schema 展开
  ↓ ParseTuple                  ↓ Authenticate                view = edit + viewer
RelationBuilder               TokenContext + Params            edit = manage + editor
  (tuple 预解析)                 ↓ Enforce                     manage = owner + admin
                               ResolveBindings                   ↓
                               推断 Subject                   关系图遍历
                                 ↓ Manager.Check                 ↓
                               HTTP POST /check               结果返回
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
│   ├── relation/
│   │   ├── tuple.go          # RelationTuple + ParseTuple + ParseEntity
│   │   └── tuple_test.go
│   └── expr/
│       └── expr.go           # 布尔表达式解析（AnyOf/AllOf/Not 内部不依赖此包）
├── token/
│   └── manager.go            # Manager.Check(ctx, audience, sub, rel, obj) (bool, error)
└── web/
    ├── requirement.go         # Relation / Qualify / QualifySubject / AnyOf / AllOf / Not
    ├── binding.go             # Params（嵌套 map + dotpath Get）+ {source.key} 解析
    ├── factory.go             # Factory / Middleware / Authenticate
    ├── manager.go             # 全局 Manager（InitManager / GetTokenManager）
    ├── context.go             # TokenContext
    └── guard/
        └── gin.go             # GinGuard + extractParams
```

## 使用示例

```go
// 初始化
web.InitManager("http://auth.example.com", seedProvider)

// 路由注册
factory := web.NewFactory()
g := guard.NewGinGuard(factory.WithAudience("my-service"))

// 纯认证
r.Use(g.Require())

// 单 relation（服务端 Schema 可能展开为多个底层 relation 查询）
r.POST("/admin/config", g.Require(web.Relation("manage")), handler)

// 指定资源（path 参数绑定）
r.PATCH("/services/:id", g.Require(
    web.Relation("admin").On("service", "{path.id}"),
), handler)

// 多条件组合（并发查询 + 短路）
r.DELETE("/posts/:id", g.Require(
    web.AllOf(
        web.AnyOf(web.Relation("admin"), web.Relation("owner")),
        web.Not(web.Relation("banned")),
    ),
), handler)

// 完整三元组（path 参数绑定）
r.POST("/devices/:did/zones/:zid", g.Require(
    web.QualifySubject("device:{path.did}", "control", "zone:{path.zid}"),
), handler)
```

## TODO（待实现）

- [ ] `token/manager.go`: Check 签名简化为单 tuple `(bool, error)`，删除 subject 推断，删除旧 request/response 结构
- [ ] `requirement.go`: subject 推断上移到 `enforceRelation`，调用简化后的 Check
- [ ] `requirement.go`: `AnyOf` 改为 goroutine 并发 + context cancel 短路
- [ ] `requirement.go`: `AllOf` 改为 errgroup 并发 + context cancel 短路
- [ ] 新增 `golang.org/x/sync` 依赖（errgroup）
- [ ] 服务端 Schema 设计（独立文档）

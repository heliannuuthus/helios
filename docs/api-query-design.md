# API 查询设计文档

## 1. 概述

本文档定义系统 API 中列表查询、条件筛选、分页和部分更新的统一约定。所有模块的接口设计应遵守本文档的规范，确保前后端行为一致。

---

## 2. 列表查询

### 2.1 游标分页

系统采用 **游标分页（Cursor-based Pagination）** 作为唯一的列表分页方式。与 offset 分页相比，游标分页在大数据量下性能稳定，不会因插入/删除导致数据错位。

#### 请求参数

| 参数 | 类型 | 位置 | 必填 | 默认值 | 约束 | 说明 |
|------|------|------|------|--------|------|------|
| `token` | string | query | 否 | 空 | — | 游标令牌；首次请求不传，后续传上一页返回的 `next` |
| `size` | int | query | 否 | 20 | 1–100 | 每页条数 |
| `filter` | string | query | 否 | 空 | — | 条件筛选表达式，见 §2.2 |

#### 响应结构

```json
{
  "items": [ ... ],
  "next": "AQF4dkNb"
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `items` | `T[]` | 当前页数据列表，空页返回 `[]` |
| `next` | string \| 缺省 | 下一页游标；最后一页不返回此字段 |

判断是否有下一页：响应中存在 `next` 字段即有下一页，不存在则到末尾。

#### 游标编码

游标值对客户端**不透明**，禁止解析、构造或持久化缓存。内部实现：

1. 将最后一条记录的 `_id`（自增主键）编码为 varint
2. HMAC-SHA256 签名后截取 8 字节校验码
3. `varint + sig` 以 Base64 RawURL 编码

签名密钥进程启动时随机生成，重启后旧游标自然失效。

#### 设计约束

- 排序固定为 `_id ASC`，不支持自定义排序
- 仅支持顺序向后翻页，不支持跳页
- 游标不可跨进程持久化

### 2.2 条件筛选（filter）

#### 格式

所有列表接口使用统一的 `filter` query 参数传递筛选条件。多个条件以 `,` 分隔，整个值由客户端 URL encode。

```
GET /domains/{id}/services?filter=name~=auth,service_id=svc-1&size=10
GET /relationships?filter=service_id=svc-1,subject_type=user&token=AQF4dkNb
```

#### 操作符

| 符号 | 含义 | SQL 映射 | 示例 |
|------|------|----------|------|
| `=` | 等于 | `col = ?` | `service_id=abc` |
| `!=` | 不等于 | `col != ?` | `status!=disabled` |
| `>` | 大于 | `col > ?` | `priority>3` |
| `>=` | 大于等于 | `col >= ?` | `priority>=5` |
| `<` | 小于 | `col < ?` | `priority<10` |
| `<=` | 小于等于 | `col <= ?` | `priority<=8` |
| `~=` | 前缀匹配 | `col LIKE 'val%'` | `name~=auth` |
| `\|` | IN 多值 | `col IN (...)` | `type\|user\|group` |

操作符解析优先级：双字符（`~=`、`!=`、`>=`、`<=`）优先于单字符（`=`、`>`、`<`），`|` 作为 IN 语义最后匹配。

#### 规则

- 多个条件之间为 **AND** 关系
- 未传 `filter` 或传空值时不添加任何 WHERE 条件
- 无操作符前缀默认按所在列白名单的首选操作符处理

#### 白名单机制

后端为每个资源声明允许筛选的列及支持的操作符，不在白名单中的列或操作符会被**静默忽略**，防止任意列注入。

```go
var serviceFilters = filter.Whitelist{
    "service_id": {filter.Eq},
    "name":       {filter.Eq, filter.Pre},
}
```

列名校验仅允许 `[a-zA-Z0-9_]`，进一步防御 SQL 注入。

---

## 3. 部分更新（PATCH）

遵循 **JSON Merge Patch（RFC 7396）** 语义。

### 3.1 三态语义

| JSON 表现 | 含义 | 数据库行为 |
|-----------|------|------------|
| 字段缺失 | 不更新 | 不生成 UPDATE 子句 |
| 字段有值 | 更新为该值 | `SET column = value` |
| 字段为 `null` | 清空 | `SET column = NULL` |

### 3.2 实现方式

使用 `pkg/patch.Optional[T]` 表示可选更新字段：

```go
type ServiceUpdateRequest struct {
    Name        patch.Optional[string] `json:"name"`
    Description patch.Optional[string] `json:"description"`
    LogoURL     patch.Optional[string] `json:"logo_url"`
}
```

Service 层使用 `patch.Collect` + `patch.Field` 构建更新 map：

```go
updates := patch.Collect(
    patch.Field("name", req.Name),
    patch.Field("description", req.Description),
    patch.Field("logo_url", req.LogoURL),
)
db.Model(&service).Updates(updates)
```

### 3.3 约束

- 更新接口的 HTTP 方法必须为 `PATCH`
- 可选字段**禁止**使用 `*T`，统一使用 `patch.Optional[T]`
- Handler 注释中的方法与路由注册保持一致

---

## 4. 响应 DTO

API 响应统一使用 DTO 结构体，不直接返回数据库模型。

### 4.1 规范

- 不暴露内部 `_id`（自增主键），对外仅暴露业务 ID（如 `service_id`、`app_id`）
- 时间字段统一格式化为 ISO 8601（`time.RFC3339`，UTC）
- 每个资源类型定义 `NewXxxResponse` 构造函数，集中转换逻辑

### 4.2 分页响应的 DTO 转换

Handler 层使用 `pagination.Mapping` 将 `Items[Model]` 转为 `Items[DTO]`：

```go
c.JSON(http.StatusOK, pagination.Mapping(page, func(s *models.Service) dto.ServiceResponse {
    return dto.NewServiceResponse(s, domainID)
}))
```

---

## 5. 后端接入 Checklist

新增列表查询接口时，按以下步骤接入：

### 5.1 Model

实现 `pagination.Identifiable` 接口：

```go
func (s Service) PrimaryKey() uint { return s.ID }
```

### 5.2 白名单

在 Service 层为资源定义 filter 白名单：

```go
var serviceFilters = filter.Whitelist{
    "service_id": {filter.Eq},
    "name":       {filter.Eq, filter.Pre},
}
```

### 5.3 Service

接收 `*ListRequest`，对特殊字段（如 domain_id 需要 OR 逻辑）手动 WHERE，其余通过 `filter.Apply` 自动处理：

```go
func (s *Service) ListServices(ctx context.Context, domainID string, req *ListRequest) (*pagination.Items[models.Service], error) {
    query := s.db.WithContext(ctx).Model(&models.Service{})
    if domainID != "" {
        query = query.Where("domain_id = ? OR domain_id = ?", domainID, models.CrossDomainID)
    }
    query = filter.Apply(query, req.Filter, serviceFilters)
    return pagination.CursorPaginate[models.Service](query, req.Pagination)
}
```

### 5.4 Handler

绑定 query 参数（`ListRequest` 统一包含 `Pagination` + `Filter`）→ 调用 Service → Mapping 转 DTO：

```go
func (h *Handler) ListServices(c *gin.Context) {
    domainID := c.Param("domain_id")
    var req ListRequest
    if err := c.ShouldBindQuery(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    page, err := h.service.ListServices(c.Request.Context(), domainID, &req)
    if err != nil { ... }
    c.JSON(http.StatusOK, pagination.Mapping(page, func(s *models.Service) dto.ServiceResponse {
        return dto.NewServiceResponse(s, domainID)
    }))
}
```

### 5.5 前端

#### Filter 构建器（`@atlas/shared`）

前端提供类型安全的 filter 构建器，生成后端 `filter=col<op>val` 格式的 query string。

```typescript
import { eq, prefix, oneOf, buildFilter, listParams } from '@atlas/shared'
```

##### 辅助函数

| 函数 | 生成操作符 | 示例 |
|------|-----------|------|
| `eq(val)` | `=` | `eq('abc')` → `col=abc` |
| `neq(val)` | `!=` | `neq('disabled')` → `col!=disabled` |
| `gt(val)` | `>` | `gt('3')` → `col>3` |
| `gte(val)` | `>=` | `gte('5')` → `col>=5` |
| `lt(val)` | `<` | `lt('10')` → `col<10` |
| `lte(val)` | `<=` | `lte('8')` → `col<=8` |
| `prefix(val)` | `~=` | `prefix('auth')` → `col~=auth` |
| `oneOf([...])` | `\|` | `oneOf(['a','b'])` → `col\|a\|b` |

`undefined`、`null`、`''` 值会被自动跳过，不生成条件。

##### buildFilter

将 spec 对象转为 filter query string：

```typescript
buildFilter({ name: prefix('auth'), service_id: eq('svc-1') })
// => "name~=auth,service_id=svc-1"

buildFilter({ service_id: 'abc' })
// => "service_id=abc"  (plain string 默认 eq)

buildFilter({ name: prefix('') })
// => undefined  (空值跳过，无条件时返回 undefined)
```

##### listParams

一步构建 `{ filter, token, size }` params 对象，直接传给 axios：

```typescript
request.get('/services', { params: listParams({ name: prefix('auth') }, { size: 20 }) })
// => GET /services?filter=name~=auth&size=20
```

##### API 签名

所有 `getList` 方法签名统一为 `(routeParams..., filter?: FilterSpec, pagination?: { token, size })`：

```typescript
export const serviceApi = {
  getList: (domainId: string, filter?: FilterSpec, pagination?: { token?: string; size?: number }) =>
    request.get<Items<Service>>(`/domains/${domainId}/services`, { params: listParams(filter, pagination) }),
}
```

##### 调用示例

```typescript
// 无筛选
serviceApi.getList(domainId)

// 前缀搜索
serviceApi.getList(domainId, { name: prefix(keyword) })

// 精确匹配
serviceApi.getList(domainId, { service_id: eq(serviceId) })

// plain string 默认 eq
relationshipApi.getList({ service_id: currentServiceId, subject_type: 'user' })
```

---

## 6. 已接入接口

| 接口 | 可筛选列 | 支持的操作符 |
|------|----------|-------------|
| `GET /domains/:id/services` | `service_id` | `eq` |
|  | `name` | `eq`, `prefix` |
| `GET /domains/:id/applications` | `name` | `eq`, `prefix` |
| `GET /relationships` | `service_id` | `eq` |
|  | `subject_type` | `eq` |
|  | `subject_id` | `eq` |
| `GET /applications/:aid/services/:sid/relationships` | `subject_type` | `eq` |
|  | `subject_id` | `eq` |
| `GET /groups` | `service_id` | `eq` |
|  | `name` | `eq`, `prefix` |

> 注：`domain_id` 不走 filter，由路径参数决定，在 Service 层手动 WHERE。

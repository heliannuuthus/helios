# API 查询设计文档

## 1. 概述

本文档定义系统 API 中列表查询、筛选、分页和部分更新的统一约定。所有模块的接口设计应遵守本文档的规范，确保前后端行为一致。

---

## 2. 列表查询

### 2.1 游标分页

系统采用 **游标分页（Cursor-based Pagination）** 作为唯一的列表分页方式。与 offset 分页相比，游标分页在大数据量下性能稳定，不会因插入/删除导致数据错位。

#### 请求参数

| 参数 | 类型 | 位置 | 必填 | 默认值 | 约束 | 说明 |
|------|------|------|------|--------|------|------|
| `token` | string | query | 否 | 空 | — | 游标令牌；首次请求不传，后续传上一页返回的 `next` |
| `size` | int | query | 否 | 20 | 1–100 | 每页条数 |

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

### 2.2 筛选

筛选参数通过 query string 传递，与分页参数并列。筛选字段随资源类型而定，在各自的 `XxxListRequest` 结构体中声明。

```
GET /domains/{domain_id}/services?name=auth&size=10
GET /relationships?service_id=svc-1&subject_type=user&token=AQF4dkNb
```

筛选规则：

- 字符串筛选为**精确匹配**（需模糊搜索时单独约定）
- 多个筛选条件为 **AND** 关系
- 未传的筛选参数不参与过滤

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

### 5.2 Request

定义 `XxxListRequest`，嵌入 `pagination.Pagination` 并声明筛选字段：

```go
type ServiceListRequest struct {
    pagination.Pagination
    DomainID  string `form:"domain_id"`
    Name      string `form:"name"`
}
```

### 5.3 Service

接收 Request 结构体，构建 GORM 查询后调用 `CursorPaginate`：

```go
func (s *HermesService) ListServices(req *ServiceListRequest) (*pagination.Items[models.Service], error) {
    query := s.db.Model(&models.Service{})
    if req.Name != "" {
        query = query.Where("name = ?", req.Name)
    }
    return pagination.CursorPaginate[models.Service](query, req.Pagination)
}
```

### 5.4 Handler

绑定 query 参数 → 调用 Service → Mapping 转 DTO：

```go
func (h *Handler) ListServices(c *gin.Context) {
    var req ServiceListRequest
    if err := c.ShouldBindQuery(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    page, err := h.svc.ListServices(&req)
    if err != nil { ... }
    c.JSON(http.StatusOK, pagination.Mapping(page, func(s *models.Service) dto.ServiceResponse {
        return dto.NewServiceResponse(s, domainID)
    }))
}
```

### 5.5 前端

TypeScript 类型与 API 调用：

```typescript
interface Items<T> {
  items: T[]
  next?: string
}

const serviceApi = {
  getList: (domainId: string, params?: { name?: string; token?: string; size?: number }) =>
    request.get<Items<Service>>(`/domains/${domainId}/services`, { params }),
}
```

---

## 6. 已接入接口

| 接口 | Request 结构体 | 筛选字段 |
|------|----------------|----------|
| `GET /domains/:id/services` | `ServiceListRequest` | `service_id`, `name` |
| `GET /domains/:id/applications` | `ApplicationListRequest` | — |
| `GET /relationships` | `RelationshipListRequest` | `service_id`, `subject_type`, `subject_id` |
| `GET /domains/:id/services/:sid/relationships` | `AppServiceRelationshipListRequest` | `subject_type`, `subject_id` |
| `GET /groups` | `GroupListRequest` | — |

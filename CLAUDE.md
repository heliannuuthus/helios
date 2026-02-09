# Helios Claude 规则

本文件包含项目的编码规范和约定，供 AI Agent 和开发者参考。

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

- `internal/hermes/` — 服务、应用、关系、组的更新
- `internal/iris/` — 用户信息更新
- `internal/zwei/recipe/` — 菜谱更新

### 新增更新 API 的 checklist

1. 请求类型中的可选字段使用 `patch.Optional[T]`，而非 `*T`
2. Service 层使用 `patch.Collect` + `patch.Field` 构建更新 map
3. 路由注册使用 `.PATCH()` 方法
4. Handler 注释标注 `PATCH /path`
5. Create 请求体仍可使用 `*T` 指针（创建时不需要三态语义）

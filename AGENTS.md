# Helios AGENTS（提炼版）

本文件是 Helios 的高优先级协作约束，面向 AI Agent 与开发者。

## 一眼就要记住的规则

1. 不要改 `/auth/authorize` 的方法和路径：必须是 `POST /auth/authorize`。
2. 所有 PATCH 更新字段必须用 `patch.Optional[T]`，禁止用 `*T` 表示可选更新。
3. Aegis 不直接访问数据库，数据统一通过 Hermes 服务层获取。
4. API 调用走 services 层，不要在组件或 handler 中绕过服务层直接拼底层调用。
5. 改完代码必须执行：`golangci-lint run --fix ./...`。

## 模块边界与依赖

- `aegis/`：认证授权（OAuth2/OIDC 流程、Token、认证链路）。
- `hermes/`：身份与访问管理数据层（用户、应用、服务、关系等）。
- `iris/`：用户 Profile/MFA/Identity 相关能力。
- `zwei/`：业务侧能力模块（独立于 Hermes 数据域）。
- `pkg/`：公共基础能力（配置、日志、patch、数据库工具等）。

关键约束：

- `aegis -> hermes`：Aegis 依赖 Hermes 获取数据，不直连 DB。
- `hermes/models` 为公共模型包，可被 `aegis`、`iris` 依赖。
- `zwei/internal/models` 仅 zwei 内部使用，不对外暴露。
- 各模块配置在各自 `config/` 包；全局配置基础在 `pkg/config/`。

## PATCH 语义（强约束）

项目统一使用 JSON Merge Patch（RFC 7396）语义：

- 字段缺失：不更新
- 字段有值：更新为该值
- 字段为 `null`：更新为数据库 `NULL`

标准写法：

```go
type ServiceUpdateRequest struct {
    Name        patch.Optional[string] `json:"name"`
    Description patch.Optional[string] `json:"description"`
}
```

```go
updates := patch.Collect(
    patch.Field("name", req.Name),
    patch.Field("description", req.Description),
)
```

新增更新接口 checklist：

1. 请求体可选字段使用 `patch.Optional[T]`
2. Service 层使用 `patch.Collect + patch.Field`
3. 路由使用 `.PATCH()`
4. Handler 注释与实际路由方法保持一致

## 路由与网关约定（不要破坏）

- 前端/SDK 认证调用统一走 `/api/*`，由网关转换到后端真实路径（如 `/auth/*`）。
- 不要在前端/SDK 里改成直接请求 `/auth/*`。
- `/auth/authorize` 必须是 `POST` + `application/x-www-form-urlencoded`。
- 禁止把 `ShouldBind` 改为 `ShouldBindQuery`。

## 代码与提交流程

- 每次功能改动后执行并通过：`golangci-lint run --fix ./...`
- 确保 import 分组正确：标准库 / 第三方 / 项目内部
- 不要硬编码密钥、token，不要提交 `.env`

---

如果和历史文档冲突，以本文件和当前代码实现为准；变更该规则时请同步更新 `CLAUDE.md`。

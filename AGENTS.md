# Helios AGENTS

本文件是 Helios 的高优先级协作约束，面向 AI Agent 与开发者。

## 一眼就要记住的规则

1. 不要改 `/auth/authorize` 的方法和路径：必须是 `POST /auth/authorize`。
2. 所有 PATCH 更新字段必须用 `patch.Optional[T]`，禁止用 `*T` 表示可选更新。
3. Aegis 不直接访问数据库，数据统一通过 Hermes 服务层获取。
4. API 调用走 service/client 封装，不要绕过既有层级直接拼底层调用。
5. 改完代码必须执行：`make lint`（各 module 分别 lint）。

## 模块边界与依赖

本仓库为 **Go Workspace 多 module**，各 module 可独立拆仓库，module path **无 `helios` 前缀**：

| Module | 路径 | 说明 |
|--------|------|------|
| `github.com/heliannuuthus/proto` | `proto/` | proto 定义 + 生成 gRPC 代码 |
| `github.com/heliannuuthus/pkg` | `pkg/` | 公共基础设施（config/logger/patch/database 等） |
| `github.com/heliannuuthus/hermes` | `hermes/` | IAM 数据层；入口 `hermes/main.go` |
| `github.com/heliannuuthus/aegis` | `aegis/` | 认证 + 用户中心；入口 `aegis/main.go` |
| `github.com/heliannuuthus/zwei` | `zwei/` | 业务 API；入口 `zwei/main.go` |
| `github.com/heliannuuthus/chaos` | `chaos/` | 运维 API；入口 `chaos/main.go`，独立 DB |

- `aegis/profile/`：用户中心/Profile 能力，与 Aegis 同进程，不是独立服务。
- 服务间 **禁止** import 其他服务的 Go 包；共享只通过 `proto`、`pkg`。
- `aegis -> hermes`：仅通过 gRPC（`aegis/rpc/hermes` + `proto` 生成代码）。

启动命令：`make run <service>`（如 `make run aegis`、`make run hermes`）。

关键约束：

- `aegis -> hermes`：gRPC 调用，不直连 DB、不 import `hermes/*`。
- `aegis/models`：Aegis 侧独立数据模型，与 `hermes/internal/models` 完全隔离。
- `hermes/internal/models`：仅 Hermes 内部使用（`internal` 保护）。
- `chaos/config.InitDB()`：连 chaos 独立库，禁止 import `hermes/config`。
- 每个服务只在自己的项目根目录使用 `config.toml`，并提交不含密钥的 `example.toml`；加载封装在 `pkg/config` 与各服务 `config/`。

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

- 前端/SDK 认证调用统一走既有服务封装，由网关转换到后端真实路径（如 `/auth/*`）。
- 不要在前端/SDK 里改成直接请求 `/auth/*`。
- `/auth/authorize` 必须是 `POST` + `application/x-www-form-urlencoded`。
- 禁止把 `ShouldBind` 改为 `ShouldBindQuery`。

## 代码与提交流程

- 每次功能改动后执行并通过：`golangci-lint run --fix ./...`
- 确保 import 分组正确：标准库 / 第三方 / 项目内部
- 不要硬编码密钥、token，不要提交 `.env`

---

如果和历史文档冲突，以本文件和当前代码实现为准；变更该规则时请同步更新 `CLAUDE.md`。

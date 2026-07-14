# Helios

Helios 是 Go 多服务后端工作区，包含认证、IAM 数据层、业务 API、运维 API、proto 与公共基础库。各服务是独立进程，仓库根没有统一 `main.go`。

## 项目结构

| 路径 | Module | 说明 |
|------|--------|------|
| `proto/` | `github.com/heliannuuthus/proto` | Buf / gRPC 定义与生成代码 |
| `pkg/` | `github.com/heliannuuthus/pkg` | 公共基础设施：config、logger、patch、database、redis、mail 等 |
| `hermes/` | `github.com/heliannuuthus/hermes` | IAM 数据层，HTTP 管理 API + gRPC |
| `aegis/` | `github.com/heliannuuthus/aegis` | 认证 + 用户中心 API，入口 `aegis/main.go` |
| `zwei/` | `github.com/heliannuuthus/zwei` | 业务 API，入口 `zwei/main.go` |
| `chaos/` | `github.com/heliannuuthus/chaos` | 运维/管理 API，入口 `chaos/main.go` |
| `environments/` | - | DB、Redis、gateway、https-proxy、本地证书 |
| `scripts/` | - | 辅助脚本 |

## 服务边界

- `aegis -> hermes`：只通过 gRPC 与 proto 交互，不直连 Hermes DB。
- `hermes/internal` 仅 Hermes 内部使用，其他服务不能 import。
- `zwei/internal` 仅 Zwei 内部使用。
- `chaos` 使用自己的 config/DB 初始化逻辑，不要 import `hermes/config`。
- 跨服务共享只放 `proto/` 和 `pkg/`，不要让服务互相 import 业务包。

## 常用命令

```bash
# 本地依赖检查、证书和 hosts
make dev-check

# 启动基础组件 + 本地服务进程
make dev-up
make dev-down
make dev-ps

# 启动/停止生产容器（不含 HTTPS Proxy）
make up
make down

# 构建/运行
make build
make build aegis
make run aegis

# 验证
make test
make lint
make fmt
make tidy

# 代码生成
make proto
make generate
```

## PATCH 语义

项目统一使用 JSON Merge Patch（RFC 7396）语义处理部分更新：

- 字段缺失：不更新
- 字段有值：更新为该值
- 字段为 `null`：更新为数据库 `NULL`

请求体可选更新字段必须使用 `pkg/patch.Optional[T]`，不要用 `*T` 表达 PATCH 可选字段。

```go
type ServiceUpdateRequest struct {
    Name        patch.Optional[string] `json:"name"`
    Description patch.Optional[string] `json:"description"`
}
```

Service 层使用 `patch.Collect` + `patch.Field` 构建更新 map。

## 认证与路由禁区

- 不要破坏 `/auth/authorize` 的方法和语义；它必须保持后端期望的 OAuth 授权入口。
- 不要把前端/SDK 改成绕过网关或服务层的临时路径。
- Challenge、MFA、WebAuthn、Passkey 相关改动要同时考虑 Aegis、Hermes、Pallas、aegis-ts 的契约。
- 不提交本地 `config.toml`、secret、token、私钥、数据库数据。
- 每个服务的项目根目录只保留本地 `config.toml` 和可提交的 `example.toml`，不使用 Helios 根目录共享配置。

## 验证 Checklist

1. Go 代码改动：运行 `make test`，必要时运行 `make lint`。
2. Proto 改动：运行 `make proto` 或 `make generate`，检查生成代码。
3. 服务边界改动：确认没有跨服务 import `internal` 或直接访问其他服务 DB。
4. 认证流程改动：同步检查 `pallas/` 和 `aegis-ts/` 的调用契约。

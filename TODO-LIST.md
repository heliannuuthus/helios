# TODO List

## ConnectionsMap delegate 分类逻辑重构

**位置**: `internal/aegis/authenticate/service.go` - `GetAvailableConnections`

**现状**: `delegate` 里的 connection 标识符被硬编码归入 `ConnectionsMap.MFA`，假设 delegate 全部是 MFA 类型。

```go
for _, m := range cfg.Delegate {
    mfaSet[m] = true  // ← 写死了
}
```

**问题**: `delegate` 的语义是"可以替代主认证的独立验证方式"，不限于 MFA 类型。如果未来出现新的 auth 类型（生物识别、硬件 token、第三方认证服务等），也应该能作为 delegate，但当前逻辑会把它们错误地归入 MFA 类别。

**方案**: 从 Registry 获取 delegate 对应的 Authenticator，根据其实际类型动态归类，而不是硬编码为 MFA。或者重新考虑 `ConnectionsMap` 是否还需要按 IDP / VChan / MFA 三分类。

**涉及文件**:
- `internal/aegis/authenticate/service.go` - `GetAvailableConnections`、`resolveMFAConfigs`
- `internal/aegis/types/authflow.go` - `ConnectionsMap` 结构定义

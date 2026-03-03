# pkg/aegis/web Review 问题清单

## Critical

### C1. NewTokenContext 静默丢数据

`NewTokenContext` 的 `switch` 没有 `default` 分支。如果传入 SSOToken 等不匹配的类型，返回空 `TokenContext`，认证"通过"但身份全为 nil。

**位置**: `pkg/aegis/web/context.go:31-42`

**修复方案**: 签名改为 `(*TokenContext, error)`，`default` 分支返回 error。

---

## Major

### M1. Interpret 中 audience 从未验签的 token 提取

`Interpret()` 先 `UnsafeParseToken` 提取 `audience`，后 `Verify` 验签。虽然 `pasetoToken` 被重新赋值，但 `audience` 变量仍是旧值。应从验签后的 `t.GetAudience()` 获取。

**位置**: `pkg/aegis/web/interpreter.go:46,66`

**修复方案**: 删除 L46 的 audience 提取，L66 改为 `i.decryptUserSub(ctx, encryptedSub, t.GetAudience())`。

### M2. WithAudience 每次创建新 Interpreter — 缓存不共享

每次 `WithAudience` 都 `NewInterpreter`，多 audience 场景下 verifier/decryptor 缓存完全独立，浪费内存。

**位置**: `pkg/aegis/web/middleware.go:60-67`

**修复方案**: 在 `Factory` 层持有一个共享的 `Interpreter` 实例，`WithAudience` 复用它。

### M3. X-Challenge-Token 应用 Verify 而非 Interpret

ChallengeToken 不含加密的 sub，调用 `Interpret` 多余。且类型断言失败（非 ChallengeToken 放进 header）时被静默忽略。

**位置**: `pkg/aegis/web/middleware.go:179-186`

**修复方案**: 改为 `m.interpreter.Verify()`；类型断言失败时 warn。

### M4. RequireToken 与 web 包的 Bearer 提取逻辑不一致

`aegis/middleware/auth.go` 的 `RequireToken` 接受裸 token（不带 `Bearer ` 前缀），`web/middleware.go` 的 `extractBearerToken` 则不接受。

**位置**: `aegis/middleware/auth.go:31-34` vs `pkg/aegis/web/middleware.go:259-268`

**修复方案**: `RequireToken` 对齐 web 包行为，不带 `Bearer ` 前缀时返回 401。

---

## Minor

### m1. ContextKeyUser 已成死代码

`aegis/consts.go` 中 `ContextKeyUser = "aegis:user"` 不再被任何代码引用，所有中间件已改用 `web.ClaimsKey`。

**位置**: `aegis/consts.go:15`

**修复方案**: 删除该常量。

### m2. iris/handler.go 中 `_ = openid` 死代码

`UpdateEmail`、`UpdatePhone`、`BindIdentity`、`UnbindIdentity` 四个 TODO 方法中取了 `openid` 然后 `_ = openid` 丢弃。

**位置**: `iris/handler.go` 多处

**修复方案**: 改为 `if web.OpenIDFromGin(c) == "" { ... return }` 模式，不赋值。

### m3. WithChallenge 命名暗示不可变模式

Go 惯例中 `WithXxx` 常用于返回新对象，但这里直接修改 receiver。

**位置**: `pkg/aegis/web/context.go:44-47`

**修复方案**: 改名为 `SetChallengeToken`。

### m4. errForbidden 使用自定义类型

`errForbidden` 用了 `&forbiddenError{}` 指针，`errors.New("forbidden")` 更简洁且语义更清晰。

**位置**: `pkg/aegis/web/middleware.go:155-159`

**修复方案**: 改为 `var errForbidden = errors.New("forbidden")`。

### m5. extractBearerToken 大小写敏感

RFC 7235 规定 auth-scheme 是 case-insensitive，`"bearer "` 或 `"BEARER "` 应被接受。

**位置**: `pkg/aegis/web/middleware.go:265`

**修复方案**: 用 `strings.EqualFold` 或 `strings.ToLower` 比较前缀。

---

## Suggestion

### S1. 新增 RequireFactor() 中间件

需要二次验证的路由应通过 `RequireFactor()` 中间件强制要求 `tc.ChallengeToken() != nil`。

### S2. net/http 层缺少 TokenContextFromRequest 辅助函数

Gin 层有 `TokenContextFromGin`，标准 http 层没有对应的取值函数。

### S3. Gin 层和 net/http 层大量重复代码

4 个方法各写两遍（Gin + net/http），可提取共享逻辑减少重复。

### S4. iris/handler.go 的 getOpenID wrapper 多余

只是 `web.OpenIDFromGin` 的代理，建议直接调用以保持与 zwei handler 的一致性。

# Passkey Welcome Back 遮盖层设计

> 状态：Ready for Implementation | 更新：2026-02-10

## 1. 目标

在登录页提供一个品牌化的 Passkey 快速入口（"头盔盖下来"式遮盖层），在不启用 Conditional UI 的前提下：

1. 用户可看到熟悉的欢迎信息（昵称/头像）
2. 用户可一键触发安全验证（指纹/面容/PIN）
3. 用户可随时切换到其他登录方式

## 2. 设计结论（已定）

### 2.1 不依赖 Conditional UI

本方案采用自定义遮盖层，不依赖浏览器输入框联想的 Conditional UI。

### 2.2 不新增后端协议字段

`user_hints` 不是 WebAuthn 协议标准字段，本方案不要求后端新增该字段。  
用户信息来源为前端已登录态页面（个人信息页）中的现有数据。

### 2.3 本地缓存采用单用户覆盖策略

当前策略：同一浏览器同一站点仅缓存最近一次设置 Passkey 的用户提示信息。  
后续如业务明确要求多用户列表，可在同一 key 上扩展为数组结构。

## 3. WebAuthn 域配置规范

当认证入口可能来自 `heliannuuthus.com` 及其子域（例如 `app.heliannuuthus.com`、`aegis.heliannuuthus.com`）时：

- `rpId`: `heliannuuthus.com`
- `RPOrigins`: 明确列出所有实际发起 WebAuthn 的页面 origin（精确匹配）

示例：

```toml
[aegis.mfa.webauthn]
rp-id = "heliannuuthus.com"
rp-display-name = "Helios Auth"
rp-origins = [
  "https://heliannuuthus.com",
  "https://app.heliannuuthus.com",
  "https://aegis.heliannuuthus.com"
]
```

说明：
- `rp-display-name` 仅用于用户可见展示，不参与安全校验
- `rp-origins` 校验的是前端页面 origin，不是 API 服务地址

## 4. 本地存储设计

### 4.1 Key 命名

统一采用带命名空间前缀的 key：

```text
heliannuuthus@aegis:passkey_user
```

### 4.2 Value 结构（单用户）

```json
{
  "uid": "u_xxx",
  "nickname": "heliannuuthus",
  "picture": "https://cdn.xxx/avatar.png",
  "updated_at": 1739100000000
}
```

字段说明：
- `uid`: 用户稳定标识（用于校验与清理）
- `nickname`: 遮盖层展示名称
- `picture`: 头像 URL（可空）
- `updated_at`: 最后更新时间戳（用于调试与过期策略）

## 5. 前端流程

### 5.1 写入时机（个人信息页）

用户完成 Passkey 注册后：
1. 从当前页面状态读取 `uid/nickname/picture`
2. 覆盖写入 `heliannuuthus@aegis:passkey_user`

用户删除最后一个 Passkey 后：
1. 删除该 key

### 5.2 展示判断（登录页）

登录页加载时依次判断：

1. 本地是否有 `passkey_user` 缓存
2. 设备是否支持平台认证器（`isUserVerifyingPlatformAuthenticatorAvailable()`）
3. 当前应用配置中是否存在 `passkey` connection

全部满足才显示 Welcome Back 遮盖层，否则显示普通登录表单。

### 5.3 交互

- 主按钮：`使用安全验证登录`
  - 触发现有 Passkey 登录流程（challenge + assertion + `/auth/login`）
- 次按钮：`使用其他账号登录`
  - 仅关闭遮盖层（可选是否清缓存，建议默认不清）

## 6. 失败与降级策略

1. **用户取消系统验证弹窗**  
   仅提示"已取消"，保持遮盖层，不清缓存。

2. **凭证不存在/已删除（服务端明确返回）**  
   清除 `passkey_user` 缓存，切回普通登录。

3. **设备不支持平台认证器**  
   不展示遮盖层，走普通登录。

4. **配置中移除 passkey connection**  
   不展示遮盖层，走普通登录。

## 7. UI 文案建议

- 标题：`欢迎回来`
- 副标题：`通过安全验证快速登录`
- 主按钮：`使用安全验证登录`
- 次按钮：`使用其他账号登录`
- 错误提示：
  - `未检测到可用的安全凭证，请使用其他方式登录`
  - `本次验证已取消`

## 8. 实施清单

1. 登录页新增 Welcome Back 遮盖层组件
2. 接入三条件判断逻辑（缓存/设备能力/connections）
3. 个人信息页 Passkey 注册成功后写入缓存
4. Passkey 删除后清理缓存
5. 补充端到端测试：
   - 首次无缓存
   - 有缓存且验证成功
   - 有缓存但凭证已删除
   - 用户取消验证

## 9. 兼容性与安全说明

- 本地缓存仅用于 UI 提示，不作为认证依据
- 实际身份仍由 WebAuthn 验签与后端流程确认
- 避免在缓存中写入邮箱、手机号等高敏字段
- 建议在登出时保留缓存（提升回访体验），但可提供用户可控开关

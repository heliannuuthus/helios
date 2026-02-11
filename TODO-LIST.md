# TODO List

## ~~ConnectionsMap delegate 分类逻辑重构~~ ✅ 已完成

**变更摘要**: 将 `ConnectionsMap` 从按 connection 自身类型分类（IDP / VChan / MFA）改为按关系角色分类（IDP / Required / Delegated）。

**改动**:
- `ConnectionsMap.VChan` → `ConnectionsMap.Required`（被 IDP.Require 引用的前置条件配置）
- `ConnectionsMap.MFA` → `ConnectionsMap.Delegated`（被 IDP.Delegate 引用的替代路径配置）
- `resolveVChanConfigs` + `resolveMFAConfigs` 合并为统一的 `resolveConnectionConfigs`
- 前端类型同步更新：`VChanConfig` → `RequiredConfig`，`MFAConfig` → `DelegatedConfig`
- JSON 字段：`vchan` → `required`，`mfa` → `delegated`

---

## SFA 三层模型重构

**设计文档**: [`docs/sfa-design.md`](docs/sfa-design.md)

Challenge 重命名为 SFA（Single-Factor Authentication），引入三层请求模型：

- **Type**：业务场景（login / forget_password / bind_phone），由业务 Service 定义，用于限流和模板选择
- **Channel Type**：验证方式（email_otp / sms_otp / totp / webauthn / captcha / wechat-mp），由系统定义
- **Channel**：验证目标（邮箱 / 手机号 / code），由前端提供

**待办**:
- [ ] 重命名 Challenge → SFA（types、service、handler）
- [ ] CreateRequest 增加 type / channel_type / channel 三层字段
- [ ] 区分验证类和交换类的处理逻辑
- [ ] 交换类（wechat-mp、alipay-mp）Create 直接签发 SFA Token
- [ ] 验证类支持 Type 关联的限流和模板策略
- [ ] SFA Token claims 增加 channel_type 和 type 字段
- [ ] 前端适配新 API 结构

---

## MFA 编排层

**设计文档**: [`docs/mfa-orchestration-design.md`](docs/mfa-orchestration-design.md)

MFA 作为运行时编排层，在主认证 + 授权后、Token 签发前动态触发：

- 风险评估引擎根据设备、IP、行为等维度判断是否需要 MFA
- 触发后返回 `mfa_required` + `allowed_channels` 给前端
- 前端条件渲染可选的 SFA 验证方式
- MFA 复用 SFA 能力，通过 `/auth/mfa/complete` 提交 SFA Token 完成

**待办**:
- [ ] AuthFlow 增加 MFA 阶段（mfa_required / mfa_allowed_channels / mfa_completed_at）
- [ ] 实现风险评估引擎（RiskContext → RiskAssessment）
- [ ] 实现 `/auth/mfa/complete` 接口
- [ ] MFA 因子类别校验（主认证因子 ≠ MFA 因子）
- [ ] 可信设备记忆（TrustedDevice）
- [ ] MFA 超时和尝试次数限制
- [ ] 前端 MFA 页面 / 弹层实现

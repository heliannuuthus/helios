# Aegis 密钥设计文档

## 1. 概述

Aegis 采用 **Seed-based KDF** 密钥架构，所有密钥材料统一存储为 48 字节的 Seed，运行时通过 Argon2id 派生出签名密钥和加密密钥。

### 1.1 设计目标

| 目标 | 说明 |
|------|------|
| 单一存储 | 每个实体只存储一个 Seed，派生多种用途密钥 |
| 密钥隔离 | 签名密钥和加密密钥相互独立，泄露一个不影响另一个 |
| 安全派生 | 使用内置随机 salt + Argon2id，抵抗暴力破解 |
| 密钥轮换 | 支持多 Seed 共存，平滑过渡 |

### 1.2 密钥层次

```
┌─────────────────────────────────────────────────────────────┐
│                        Seed (48 bytes)                       │
│  ┌─────────────────┬───────────────────────────────────────┐ │
│  │  Salt (16 B)    │         Key Material (32 B)           │ │
│  └─────────────────┴───────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ Argon2id KDF
              ┌───────────────┴───────────────┐
              ▼                               ▼
     ┌─────────────────┐             ┌─────────────────┐
     │  Signing Key    │             │  Encryption Key │
     │  (Ed25519 32B)  │             │  (Symmetric 32B)│
     └─────────────────┘             └─────────────────┘
```

---

## 2. Seed 结构

### 2.1 格式定义

| 偏移 | 长度 | 字段 | 用途 |
|------|------|------|------|
| 0 | 16 | Salt | KDF 的随机盐值 |
| 16 | 32 | Key | 主密钥材料 |

**总长度**：48 字节

### 2.2 生成规范

```
Seed = CSPRNG(48)
```

- 使用密码学安全随机数生成器（CSPRNG）
- Salt 和 Key 一次性生成，不可分离存储

### 2.3 存储格式

| 场景 | 格式 |
|------|------|
| 数据库 | `BINARY(48)` 或 `BYTEA` |
| 配置文件 | Base64 Standard Encoding |
| 环境变量 | Base64 Standard Encoding |

---

## 3. 密钥派生 (KDF)

### 3.1 算法选择

**Argon2id** — 当前最推荐的密码哈希/密钥派生算法，兼具抗 GPU 和抗侧信道攻击能力。

### 3.2 参数配置

| 参数 | 值 | 说明 |
|------|-----|------|
| Algorithm | Argon2id | 推荐变体 |
| Time | 1 | 迭代次数 |
| Memory | 64 MB | 内存开销 |
| Parallelism | 4 | 并行度 |
| Output Length | 32 bytes | 派生密钥长度 |

### 3.3 派生公式

```
derived_key = Argon2id(
    password = Seed.Key,           // 32 bytes
    salt     = Seed.Salt + Purpose, // 16 bytes + purpose string
    time     = 1,
    memory   = 64 MB,
    threads  = 4,
    keyLen   = 32
)
```

### 3.4 Purpose 标识

| Purpose | 值 | 派生结果 |
|---------|-----|----------|
| 签名 | `"sign"` | Ed25519 Seed (32B) → 私钥 (64B) |
| 加密 | `"encrypt"` | PASETO v4 对称密钥 (32B) |

### 3.5 派生流程

**签名密钥派生**：

```
1. salt = Seed.Salt + "sign"
2. ed25519_seed = Argon2id(Seed.Key, salt, ...)
3. private_key = Ed25519.NewKeyFromSeed(ed25519_seed)
4. public_key = private_key.Public()
```

**加密密钥派生**：

```
1. salt = Seed.Salt + "encrypt"
2. symmetric_key = Argon2id(Seed.Key, salt, ...)
```

---

## 4. 密钥实体模型

### 4.1 Domain（域）

域是 Aegis 的租户隔离单元，每个域拥有独立的主密钥。

| 字段 | 类型 | 说明 |
|------|------|------|
| `domain_id` | string | 域唯一标识 |
| `main` | bytes(48) | 主 Seed |
| `keys` | []bytes(48) | 历史 Seed（密钥轮换） |

**用途**：

| 操作 | 使用的密钥 |
|------|------------|
| 签发 UAT/SAT/XAT | `main` → 签名私钥 |
| 验证 UAT/SAT/XAT | `main` 或 `keys` → 公钥（支持轮换） |

### 4.2 Application（应用）

应用是域下的客户端实体，用于签发 CAT。

| 字段 | 类型 | 说明 |
|------|------|------|
| `app_id` | string | 应用唯一标识（client_id） |
| `domain_id` | string | 所属域 |
| `key` | bytes(48) | 应用 Seed |

**用途**：

| 操作 | 使用的密钥 |
|------|------------|
| 签发 CAT | `key` → 签名私钥 |
| 验证 CAT | `key` → 公钥 |

**注意**：纯前端应用（SPA、移动端）不应持有密钥，使用 PKCE 流程。

### 4.3 Service（服务）

服务是受保护的资源 API，用于加密 Token Footer。

| 字段 | 类型 | 说明 |
|------|------|------|
| `service_id` | string | 服务唯一标识（audience） |
| `domain_id` | string | 所属域 |
| `key` | bytes(48) | 服务 Seed |

**用途**：

| 操作 | 使用的密钥 |
|------|------------|
| 加密 UAT Footer | `key` → 对称密钥 |
| 解密 UAT Footer | `key` → 对称密钥 |

### 4.4 SSO（单点登录）

SSO 使用全局配置的主密钥，不关联具体域。

| 字段 | 类型 | 说明 |
|------|------|------|
| `master_key` | bytes(48) | SSO 主 Seed |

**用途**：

| 操作 | 使用的密钥 |
|------|------------|
| 签发 SSO Token | `master_key` → 签名私钥 |
| 验证 SSO Token | `master_key` → 公钥 |
| 加密 SSO Footer | `master_key` → 对称密钥 |
| 解密 SSO Footer | `master_key` → 对称密钥 |

---

## 5. 密钥使用矩阵

| Token 类型 | 签发方 | 签名密钥来源 | 验证方 | 验签密钥来源 | Footer 加密 |
|------------|--------|--------------|--------|--------------|-------------|
| CAT | 应用 | `app.key` | Aegis | `app.key` | — |
| UAT | Aegis | `domain.main` | 服务 | `domain.main` | `service.key` |
| SAT | Aegis | `domain.main` | 服务 | `domain.main` | — |
| XAT | Aegis | `domain.main` | Aegis | `domain.main` | — |
| SSO | Aegis | `sso.master_key` | Aegis | `sso.master_key` | `sso.master_key` |

---

## 6. 密钥管理架构

### 6.1 接口层次

```
┌─────────────────────────────────────────────────────────────┐
│  Fetcher (接口)                                              │
│  └── Fetch(ctx, id) → [][]byte                              │
├─────────────────────────────────────────────────────────────┤
│  Watcher (接口)                                              │
│  └── Subscribe(id, callback)                                │
│  └── Notify(id, keys)                                       │
├─────────────────────────────────────────────────────────────┤
│  Provider (接口)                                             │
│  └── OneOfKey(ctx, id) → []byte                             │
│  └── AllOfKey(ctx, id) → [][]byte                           │
├─────────────────────────────────────────────────────────────┤
│  Store (实现 Provider)                                       │
│  └── fetcher: Fetcher                                       │
│  └── watcher: Watcher                                       │
│  └── cache: map[id]keys                                     │
│  └── Subscribe() / Refresh() / Invalidate()                 │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Fetcher 实现

| 类型 | 说明 |
|------|------|
| FetcherFunc | 函数式，自定义获取逻辑 |
| StaticFetcher | 静态密钥，忽略 id |

### 6.3 密钥操作组件

| 组件 | 职责 | 持有密钥类型 |
|------|------|--------------|
| Verifier | 签名验证 | []PublicKey |
| Signer | Token 签名 | SecretKey |
| Cryptor | 加解密 | SymmetricKey |

### 6.4 派生时机

派生发生在 Verifier/Signer/Cryptor **构造时**：
1. 从 Store 获取原始 Key (48B)
2. 派生为 PASETO 密钥对象
3. 缓存在组件内部

密钥更新时，Store 通过 Watcher 通知，组件调用 `UpdateKey(s)` 重新派生。

### 6.5 ID 语义

| Store | id 含义 | 返回值 |
|-------|---------|--------|
| domainKeyStore | client_id | domain.main |
| serviceKeyStore | audience | service.key |
| appKeyStore | client_id | app.key |
| ssoKeyStore | — (忽略) | sso.master_key |

### 6.6 密钥轮换支持

`AllOfKey` 返回所有可用密钥：

```
AllOfKey(client_id) → [domain.main, domain.keys[0], ...]
```

Verifier 内部持有多个 PublicKey，依次尝试验证。

---

## 7. 密钥轮换

### 7.1 轮换流程

```
┌─────────────────────────────────────────────────────────────┐
│  1. 生成新 Seed                                              │
│  2. 将旧 main 追加到 keys 数组                               │
│  3. 将新 Seed 设置为 main                                    │
│  4. 新签发使用新密钥，验证同时支持新旧密钥                    │
│  5. 过渡期后（所有旧 Token 过期），移除旧密钥                 │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 轮换策略

| 策略 | 说明 |
|------|------|
| 保留数量 | 建议保留最近 2-3 个历史密钥 |
| 清理时机 | 旧 Token 最大有效期过后 |
| 紧急轮换 | 密钥泄露时，立即轮换并清空历史 |

---

## 8. 公钥暴露

### 8.1 公钥端点

Aegis 提供公钥查询接口，供外部服务获取验签公钥。

**接口**：`GET /api/v1/keys/{client_id}`

**响应**：

```json
{
  "keys": [
    {
      "kid": "key-1",
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<base64url-encoded-public-key>"
    }
  ]
}
```

### 8.2 缓存策略

| 配置项 | 建议值 | 说明 |
|--------|--------|------|
| TTL | 5-15 分钟 | 本地缓存时间 |
| 刷新阈值 | TTL * 90% | 提前刷新避免过期 |
| 失败降级 | 使用缓存 | 查询失败时使用旧缓存 |

---

## 9. 安全考量

### 9.1 Seed 保护

| 措施 | 说明 |
|------|------|
| 加密存储 | 数据库字段加密（AES-256-GCM） |
| 传输加密 | 仅通过 TLS 传输 |
| 内存保护 | 使用后清零敏感内存 |
| 访问控制 | 最小权限原则 |

### 9.2 KDF 参数选择

| 参数 | 安全考量 |
|------|----------|
| Time=1 | 服务端场景，优先吞吐量 |
| Memory=64MB | 抵抗 GPU 暴力破解 |
| Parallelism=4 | 利用多核，平衡性能 |

### 9.3 Purpose 分离

签名和加密使用不同 Purpose 派生，即使 Seed 相同：

- 泄露签名私钥不影响加密安全
- 泄露对称密钥不影响签名安全

---

## 10. 附录

### 10.1 Seed 生成示例

```
# 使用 OpenSSL 生成 48 字节随机数
openssl rand -base64 48

# 输出示例
Abc123Def456Ghi789Jkl012Mno345Pqr678Stu901Vwx234Yza567Bcd890Efg==
```

### 10.2 密钥关系图

```
                    ┌─────────────┐
                    │   Domain    │
                    │             │
                    │  main (48B) │──────┬───────────────────────┐
                    │  keys []    │      │                       │
                    └──────┬──────┘      │                       │
                           │             ▼                       ▼
              ┌────────────┴────────────┐      ┌─────────────────────┐
              │                         │      │  签名密钥派生        │
              ▼                         ▼      │  (UAT/SAT/XAT)       │
       ┌─────────────┐           ┌─────────────┐└─────────────────────┘
       │ Application │           │   Service   │
       │             │           │             │
       │  key (48B)  │           │  key (48B)  │──────┐
       └──────┬──────┘           └─────────────┘      │
              │                                       ▼
              ▼                               ┌─────────────────────┐
       ┌─────────────────────┐                │  加密密钥派生        │
       │  签名密钥派生        │                │  (UAT Footer)       │
       │  (CAT)              │                └─────────────────────┘
       └─────────────────────┘
```

### 10.3 术语表

| 术语 | 说明 |
|------|------|
| Seed | 48 字节原始密钥材料，包含 Salt 和 Key |
| Salt | 16 字节随机值，用于 KDF |
| Key Material | 32 字节主密钥，作为 KDF 输入 |
| KDF | Key Derivation Function，密钥派生函数 |
| Purpose | 派生用途标识，区分签名/加密 |
| KeyProvider | 密钥提供者抽象，按 ID 获取 Seed |

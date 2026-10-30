# 为什么需要 x509-trust

## 从“JWT 签名正确”到“我凭什么相信这把钥匙”

FHIR UDAP 的工作流表面上围绕 OAuth 和 JWT：客户端把签名后的 Authentication Token 发到 token endpoint，服务端验证 JWT，签发访问令牌。很多实现会重点检查 `alg`、`exp`、`jti`、`iss`、`aud`，却把最基础的一步留给了“某个 JWT 库”或“系统默认 CA”：

> JWT 的 `x5c` 里那张证书，真的能链到本信任社区批准的 anchor 吗？链上每张证书都有效吗？它们没有被吊销吗？

UDAP IG 对这一步的要求是明确的。所有 JWT **SHALL** 在 `x5c` 头中携带签名者证书或证书链，leaf 在第一位；JWT 消费者必须从签名者证书构建到本地信任 anchor 的有效路径，并确认链上证书未过期、未被吊销。UDAP 的 Trust Community Checklist 也把 PKI 政策、证书签发与分发、证书吊销检查列为信任社区必须定义的内容。参见 [FHIR UDAP Security IG](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/)、[JWT validation](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/general.html#jwt-validation) 和 [Trust Community Checklist](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/#trust-community-checklist)。

这意味着 UDAP 的安全性并不只取决于 JWT 签名算法。真正的信任问题是：

```text
JWT 签名者证书
  → 中间 CA
    → 本社区批准的 trust anchor
      并且每张非锚证书都未过期、未被吊销
```

如果这一步做错，后面的 `iss`、`aud`、scope、授权判断都建立在不可靠的证书身份上。

## UDAP 把 X.509 重新放回中心

UDAP 的设计选择很值得注意：

- 基线要求通过 `x5c` 随 JWT 一起分发公钥和证书链；IG 另有一个可选的 `jku` 实验性替代；
- 客户端和服务器可能属于不同信任社区；
- 同一个服务器可能在不同社区持有不同证书；
- 吊销检查策略由信任社区定义，而不是由库随意决定；
- 多个信任社区可以共存，客户端需要选择正确的社区上下文。

IG 甚至专门定义了 `community` 查询参数，用于让服务器在选择签名证书时考虑客户端信任的社区；同一服务器在不同社区可能返回不同元数据。参见 [Multiple Trust Communities](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/discovery.html#multiple-trust-communities)。

这说明“证书验证”不是 UDAP 的外围工作，而是它的身份基础。一个可复用的实现必须回答：

1. 信任哪些 anchor？
2. 每个社区/租户使用哪套 anchor 和验证规则？
3. 需要 CRL、OCSP，还是两者都要？
4. 证据是否必须新鲜？
5. 哪些证书扩展和业务规则必须满足？
6. 验证结果如何审计，而不把诊断信息误当成信任结论？

## 现有实现的断层

Node.js 生态里当然有 PKI.js、JWT 库和各类 X.509 工具。问题不是“没有库”，而是这些库通常只覆盖其中一段：

- JWT 库负责签名和 claims，不负责构建和验证 `x5c` 的证书路径；
- PKI.js 能解析证书、构建路径、验证 CRL/OCSP，但默认行为、错误处理和资源边界需要宿主自己补齐；
- 系统 CA 或自动 AIA 下载会把“信任谁”交给运行环境或证书里的 URL，而不是本地批准的策略；
- 很多实现只验证 leaf，不验证 intermediate；
- 很多实现把“没有吊销信息”当成“未吊销”；
- 很多实现没有明确的 profile 版本、anchor 集版本和审计输出。

在普通 Web PKI 中，这些缺口可能被浏览器或平台兜底。在 UDAP 中，信任社区、anchor 集和吊销政策都是本地治理问题，不能依赖系统默认值。

这就是 `x509-trust` 的起点：**把证书链和吊销验证做成一个显式配置、失败关闭、可审计的组件，而不是散落在业务代码里的若干次调用。**

## 设计原则

### 1. Trust anchor 必须显式配置

库不会自动使用系统 roots，也不会从证书的 AIA 下载 anchor。`createTrustValidator()` 和 `createValidationProfileRegistry()` 都要求宿主提供 `trustAnchors`。

这是安全边界，不是便利性缺失：

- 信任谁是本地治理决定；
- 请求不能提供 anchor；
- anchor 的轮换、撤销和批准由宿主负责；
- 验证时只判断“这条链是否到达已批准的 anchor”，不重新争论 anchor 是否值得信任。

`anchorSetId` 是 profile 上的逻辑标签，用来把 profile 和宿主维护的 anchor bundle 版本对应起来；库本身不解析它，也不声称它等于 RFC 5280 的 `initial-policy-set`。

### 2. Profile 是验证语义，不是证书

`ValidationProfileInput` 把验证语义集中到一个不可变对象中：

- `id` / `version` / `versionOrder`；
- `source`：profile 来源和版本信息；
- `anchorSetId`：预期的 anchor bundle；
- `revocation.requiredEvidence`：`any`、`crl`、`ocsp` 或 `both`；
- `revocation.sourceOrder`：先尝试哪个机制；
- `rules`：叶证书 KU/EKU、certificate policy OID、路径深度、自定义规则。

profile 在 validator 创建时编译、校验、深拷贝并冻结（实现见 [src/profile/profile.ts](../src/profile/profile.ts)）。它回答的是：

> 对每一条进来的证书链，应该用什么证据和规则判断它是否可信？

它不是每个证书一份配置；通常是一个部署、租户或用途一份 profile。

### 3. Registry 负责“选配置”，不负责“信任证书”

多信任社区、多租户、多版本场景下，registry 持有多份 profile（实现见 [src/profile/registry.ts](../src/profile/registry.ts)）：

```ts
registry.register({
  trustAnchors: approvedRoots,
  profile: strictProfile
});

await registry.verify({
  profileId: "udap:example",
  certificateChain: [leaf, intermediate]
});
```

registry 的关键设计是：

- `profile.id` 是注册 key；
- 同一 profile 可以有多个版本；
- `versionOrder` 决定 latest；
- 请求只能选择已注册的 profile/version；
- 注册时固定 anchors、compiled profile 和 rules；
- 选中的 snapshot 在 await 之前确定，后续注册不会改变在途请求；
- 未知 profile/version 直接返回 `UNKNOWN_PROFILE` / `UNKNOWN_PROFILE_VERSION`，不会退回到默认配置。

这样，多社区共存的复杂度被限制在“选择本地 profile”这一层，而不是扩散到每次证书验证。

### 4. 吊销验证必须失败关闭

库支持：

- 由证书 issuer 直接签名的完整 CRL；
- 由证书 issuer 直接签名的 OCSP BasicResponse。

具体验证入口在 [src/engine/crl.ts](../src/engine/crl.ts) 和 [src/engine/ocsp.ts](../src/engine/ocsp.ts)。

当前明确不支持：

- delegated OCSP responder；
- delta CRL；
- indirect/scoped CRL；
- 没有 `nextUpdate` 的 OCSP 响应。

这些限制不是“以后再说”的模糊地带，而是当前能力边界。原因很直接：

- 不支持的特性不能靠猜测变成支持；
- 无 `nextUpdate` 的 OCSP 没有明确新鲜度边界；
- delegated responder 需要独立的授权链和策略判断；
- delta/indirect CRL 需要与 base CRL、scope 和 issuer 组合处理；
- 把“未知”当成“未吊销”是最危险的错误。

`sourceOrder` 控制尝试顺序，`requiredEvidence` 决定哪种证据必须成功。一个机制返回 unknown，不会阻止另一个机制提供可用证据；但所有可用证据都无法建立状态时，结果是 `REVOCATION_STATUS_UNKNOWN`，不是成功。

### 5. 证据和 findings 分离

结果里的 `evidence` 是**实际建立状态**的认证、新鲜证据；`findings` 是实际尝试过的 CRL/OCSP 记录，包括 unknown。

这个区分很重要：

- `evidence` 参与最终判断；
- `findings` 用于审计、诊断、测试；
- findings 不能反过来覆盖验证结果；
- unknown 证据不会因为出现在 findings 里就变成有效证据。

这避免了常见的“把调试信息误当信任结论”的问题。

### 6. 资源和取消是协议的一部分

证书验证不是纯 CPU 函数。它可能访问网络、等待慢响应、被调用方取消，或者在一个证书已确认 revoked 后继续浪费时间。

当前实现提供（调度与 single-flight 见 [src/evidence/evidence-provider.ts](../src/evidence/evidence-provider.ts)，整体编排见 [src/validator/trust-validator.ts](../src/validator/trust-validator.ts)）：

- 有界的共享 evidence provider；
- 全局和按 origin 的并发限制；
- 同一 provider 内部的 in-flight 请求合并；
- 每个 waiting request 独立的取消；
- 认证 revoked 后提前返回并中止其他流水线；
- 可选 worker，把 CPU 重的 path/CRL/OCSP 工作移出主线程。

`AbortSignal` 是协作式取消：内置 HTTP loader 能真正中止请求，自定义 loader 必须自己遵守 `options.signal`。同步 CPU 计算不能在中间被抢占；需要真正抢占时，应使用 worker。

### 7. 缓存的是证据，不是“这张证书已通过”

raw DER evidence cache 存储的是可重新验证的证据，并按 `nextUpdate` / 最大缓存年龄失效。缓存命中仍然要重新检查证书、issuer、时间和适用范围。

库不会把“某张证书曾经 good”当成跨证书、跨时间的信任结论。CRL 可以被同一 issuer 下的多个证书共享，但每个证书的状态仍然单独计算。

## 为什么不做更多

有些能力看起来“顺手就能加”，但当前选择不做：

- **完整 RFC 5280 policy tree**：当前只读取叶证书的 certificate policy OID 做显式规则检查，不声称完成 policy mapping / constraints / policy tree 处理。
- **自动 anchor 刷新**：anchor 是治理配置，不是每次请求下载的证据。轮换应由宿主以版本化 anchor bundle 完成。
- **系统 roots 兜底**：会让“信任谁”脱离应用控制。
- **AIA 自动补链**：会引入请求驱动的网络访问和 SSRF 面；当前路径输入必须显式提供。
- **delegated OCSP / delta CRL / indirect CRL**：在没有完整实现和测试前不声称支持。
- **把 findings 当安全判断**：findings 是诊断数据，不是信任输入。

这些“不做”与“做”同样重要。一个安全组件的能力边界越清楚，集成方越不容易误用。

这些原则也不是本项目独创：显式 trust store、路径验证、unknown 不视为 good、限制请求驱动的网络访问，都是 PKI 和安全工程中的常见做法。UDAP Trust Community Checklist 进一步把这些决定放回信任社区的治理范围，而不是交给库的默认值。

## UDAP 中怎么接

核心库不包含 UDAP 或社区词汇。UDAP 宿主扮演 adapter：

```text
外部 UDAP 信任框架标识
        ↓ 映射
本地 profileId
        ↓
ValidationProfile + approved trust anchors
        ↓
registry.verify(certificateChain)
        ↓
JWT iss/aud/jti、OAuth、业务授权
```

一个典型的 UDAP 验证顺序是：

1. 从可信应用上下文选择 `profileId`，不能直接信任请求体里的任意值；
2. 用 registry 选择本地 profile 和 anchor bundle；
3. 验证 JWT `x5c` 的证书链和吊销状态；
4. 验证 JWT 签名、`iss`、`aud`、`exp`、`jti`；
5. 验证 `iss` 与证书 URI SAN 的匹配；
6. 最后做 scope 和业务授权。

`x509-trust` 只负责第 3 步。第 4–6 步属于 JWT/OAuth/FHIR 业务层，不能因为证书验证成功就跳过。

示例见 [examples/udap/README.md](../examples/udap/README.md)。

### 多个社区共享 anchor 时的空白

UDAP registration 要求修改注册时使用“same trust community”的证书、相同的 `iss`，并且不得覆盖其他 community 下的注册。参见 [Modifying and Cancelling Registrations](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/registration.html#modifying-and-cancelling-registrations)。

但当前 IG **没有在 software statement 中定义 `community` claim**，也没有规定 registration request 必须携带 community 参数。`community` 这个显式参数只定义在 discovery metadata 请求中。

这留下一个真实问题：

```text
community A 和 community B 信任同一个 root
software_statement.x5c 能链到这个 root
  → 用 A 的 anchors 验证成功
  → 用 B 的 anchors 也验证成功
```

此时证书链只能证明“可达共同 root”，不能证明“属于 A 而不是 B”。这不是密码学能单独解决的问题，而是治理映射问题。可能的宿主侧信号包括：

- registration endpoint / tenant / deployment context；
- 已存在的注册记录，按 `(community, iss)` 隔离；
- 可选的、非标准的 community hint；
- 证书里的 community 约定 policy OID；
- 人工审批或社区目录。

这里有一个容易走错的方向：遍历所有已注册 profile，把第一个验证成功的结果当成 community。这个做法不可靠：

- 顺序依赖，结果取决于 profile 遍历顺序；
- 多个 profile 可能同时通过；
- 共享 anchor 时，所有相关 profile 都可能通过，无法区分；
- 验证通过只说明满足某个 profile，不等于该 client 被授权使用这个 community。

正确做法是先把 community 作为**显式上下文**确定下来，再调用 registry；如果没有上下文，应返回明确的“需要 community”或“无法确定”错误，而不是猜一个。对于标准 UDAP 客户端，可靠上下文通常来自 registration endpoint、tenant/deployment 配置或已有注册记录；如果单 endpoint 服务多个 community，则需要非标准 hint 或预先绑定。

`x509-trust` 不尝试从证书推断 community。它只验证“这条链是否到达当前 profile 配置的 anchor”；`profileId` 的选择和 `(community, iss)` 注册命名空间属于 UDAP adapter。

### 两个 root 是否“同一个”

判断“同一个 root”时，要先定义“同一个”指什么：

| 比较方式 | 能证明什么 | 注意 |
| --- | --- | --- |
| 原始 DER 字节 / SHA-256 fingerprint | 是同一张证书 | 最严格；适合判断两个 anchor bundle 是否包含完全相同的证书 |
| SubjectPublicKeyInfo (SPKI) SHA-256 | 使用同一把公钥 | 可能是重新签发、cross-sign 或不同有效期的证书 |
| Subject/Issuer DN | 名称相同 | 不能作为安全相等判断，名称不唯一 |
| 证书链验证 | 能到达某个 anchor | 不能区分共享同一 anchor 的多个 community |

```ts
import { createHash, X509Certificate } from "node:crypto";

function certificateFingerprint(der: Uint8Array): string {
  return createHash("sha256").update(der).digest("hex");
}

function publicKeyFingerprint(der: Uint8Array): string {
  const certificate = new X509Certificate(der);
  const spki = certificate.publicKey.export({
    type: "spki",
    format: "der"
  });
  return createHash("sha256").update(spki).digest("hex");
}
```

如果两个社区的 anchor bundle 包含完全相同的 DER 证书，它们就是证书级共享；如果只是 SPKI 相同，则是密钥级共享，anchor 证书的有效期和约束仍可能不同。两种情况都可能让“证书链验证”无法区分 community。

### 从探索到落地：registration endpoint 携带 community

上面的探索可以收敛为一个明确结论：

> 单凭证书无法确定 community；在 multi-community 部署中，community 必须作为注册入口的显式上下文，而不是从 `x5c` 猜测。

本文建议的落地约定是：**让 discovery 返回的每个 community 的 `registration_endpoint` 都携带完整的 `community` query 参数。**

```http
GET /.well-known/udap?community=https%3A%2F%2Fcommunity-a.example.org
```

返回：

```json
{
  "registration_endpoint": "https://as.example.org/register?community=https%3A%2F%2Fcommunity-a.example.org"
}
```

客户端不需要理解 query 的语义；它只是使用 discovery 返回的完整 URL。software statement 的 `aud` 使用同一个完整 URL：

```json
{
  "aud": "https://as.example.org/register?community=https%3A%2F%2Fcommunity-a.example.org"
}
```

服务端可以用一个 handler 处理所有 community，但必须按以下顺序 fail closed：

```text
1. query 中是否带有 community？
   缺失 → 4xx，不进入证书验证
2. community 是否在本地允许列表？
   不认识 → 4xx，不进入证书验证
3. community 是否与 aud / 实际 endpoint 一致？
   不一致 → 4xx
4. 用该 community 对应的 profileId 调用 registry
5. registry 使用已注册的 anchors 验证 x5c
6. 验证失败 → 4xx，不尝试其他 community
```

这套约定的边界要写清楚：

- `community` query 是本文的实现约定，不是当前 IG 定义的标准 claim；
- 但 query 是 `registration_endpoint` URL 的一部分，合规客户端按 discovery 使用完整 URL，因此不需要额外理解这个参数；
- 客户端若忽略 discovery、丢掉 query、使用旧 endpoint，就应注册失败；
- 共享 anchor 时，query 只完成“选择哪个 profile”，不能证明治理归属；仍需 `(community, iss)` 注册记录、tenant 或社区策略；
- 存在性和 allowlist 校验必须发生在任何证书 I/O 之前。

这与 `x509-trust` 的边界正好对齐：

```text
UDAP adapter：endpoint query → community → profileId
x509-trust：profileId → 已注册 anchors + profile → 验证证书链
```

库不需要知道 community，也不需要从证书推断 community。它只要求调用方先选定 profile，而 profile 在注册时已经绑定了 anchors 和规则。

### Trust anchor 必须提前存在

无论 anchor 存在文件、配置还是数据库，**它必须在验证前已经由宿主加载并绑定到 profile**。库不会：

- 从请求中接收 anchors；
- 从系统 roots 隐式补足；
- 从 AIA 自动下载 anchor；
- 在 `verify()` 时按 community 动态查找 anchor。

路径是：

```text
部署/启动时加载 approved anchors
  → registry.register({ trustAnchors, profile })
  → 运行时 verify({ profileId, certificateChain })
```

`verify()` 不接受 anchors，因为 anchors 是配置，不是请求输入。没有预置 anchors，就没有信任起点，也就无法验证。

## 代码对应关系

| 设计 | 主要实现 |
| --- | --- |
| 不可变 profile、版本、规则 | [src/profile/profile.ts](../src/profile/profile.ts) |
| profile registry、版本快照 | [src/profile/registry.ts](../src/profile/registry.ts) |
| 验证编排、并发、取消、deadline | [src/validator/trust-validator.ts](../src/validator/trust-validator.ts) |
| CRL / OCSP 验证 | [src/engine/crl.ts](../src/engine/crl.ts)、[src/engine/ocsp.ts](../src/engine/ocsp.ts) |
| evidence、findings、决策 | [src/evidence/evidence.ts](../src/evidence/evidence.ts) |
| provider、限流、single-flight | [src/evidence/evidence-provider.ts](../src/evidence/evidence-provider.ts) |
| 可选 worker engine | [src/workers/pki-worker-engine.ts](../src/workers/pki-worker-engine.ts) |

## 这不是一个 UDAP SDK

必须明确：

- 它不是 OAuth 服务器；
- 它不实现 UDAP discovery、registration 或 token endpoint；
- 它不验证 JWT claims；
- 它不做 SMART scope 授权；
- 它不宣称对某个真实信任社区“合规”。

它是一个**证书信任组件**：把“这条证书链是否到达本地批准的 anchor，并且满足本地吊销和 profile 规则”做成可配置、可审计、失败关闭的实现。

## 结论

FHIR UDAP 的安全性建立在一个朴素但容易被跳过的判断上：

> 我是否真的信任 JWT 签名者的证书链？

`x509-trust` 的设计围绕这个问题展开：

- anchor 显式配置，不由请求或系统隐式决定；
- profile 表达验证语义，registry 负责多社区/多版本选择；
- 吊销失败关闭，能力边界明确；
- evidence 与 findings 分离；
- 资源、取消和缓存都有边界；
- 不把证书验证和 UDAP/JWT/业务授权混为一谈。

这不是为了增加抽象层，而是为了让一个高风险、容易做错、难以审计的判断，变成一个边界清楚、可以测试和复用的组件。

## 参考资料

- [FHIR UDAP Security IG](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/)
- [JWT validation](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/general.html#jwt-validation)
- [Multiple Trust Communities](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/discovery.html#multiple-trust-communities)
- [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280)
- [RFC 6960: Online Certificate Status Protocol](https://datatracker.ietf.org/doc/html/rfc6960)
- [RFC 7515: JSON Web Signature](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 7519: JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)

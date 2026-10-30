# 在 FHIR UDAP 中使用 x509-trust

## UDAP 需要验证什么

UDAP 的 JWT 在 `x5c` 头中携带签名者证书链。消费者必须：

1. 从签名者证书构建到本地 trust anchor 的路径；
2. 验证链上证书未过期；
3. 验证链上证书未被吊销；
4. 再验证 JWT 的 `iss`、`aud`、`exp`、`jti` 等 claims。

参见 [FHIR UDAP Security IG](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/)、[JWT validation](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/general.html#jwt-validation) 和 [UDAP Dynamic Client Registration](https://www.udap.org/udap-dynamic-client-registration-stu1.html)。

`x509-trust` 只负责第 1–3 步；JWT/OAuth/FHIR 业务逻辑仍在应用层。

## 公开 API 的固定形状

UDAP adapter 的核心映射是：

```text
community URI
  → profileId
  → ValidationProfile + approved trust anchors
  → registry.verify(certificateChain)
```

```ts
const registry = createValidationProfileRegistry();

registry.register({
  trustAnchors: communityA.anchors,
  profile: {
    id: "https://community-a.example.org",
    version: "2026-01",
    source: { uri: "https://community-a.example.org/policy" },
    anchorSetId: "community-a:roots:2026-01",
    revocation: {
      requiredEvidence: "both",
      sourceOrder: ["crl", "ocsp"]
    }
  }
});

const result = await registry.verify({
  profileId: "https://community-a.example.org",
  certificateChain: x5cCertificates
});
```

固定边界：

```text
trustAnchors / profile = 部署配置
certificateChain       = 请求输入
```

`verify()` 不接收 trust anchors。请求不能提供或替换信任根。

## Discovery：选择 community 的元数据

Discovery 是匿名请求。客户端用 `community` 选择服务器元数据：

```http
GET /.well-known/udap?community=https%3A%2F%2Fcommunity-a.example.org
```

服务器返回该社区的 registration endpoint：

```json
{
  "registration_endpoint": "https://as.example.org/register?community=https%3A%2F%2Fcommunity-a.example.org"
}
```

公共 handler 可以用 query 区分社区：

```ts
const endpoint =
  `${baseUrl}/register?community=${encodeURIComponent(community.uri)}`;
```

客户端不需要理解 query；它使用 discovery 返回的完整 URL。

参见 [Multiple Trust Communities](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/discovery.html#multiple-trust-communities)。

## Registration：先确定 community，再验证证书

```text
1. community 是否存在？       否 → 4xx
2. community 是否被认识？     否 → 4xx
3. 是否匹配 aud / endpoint？ 否 → 4xx
4. 用 profileId 调用 registry
5. 验证 software_statement.x5c
6. 失败 → 4xx，不尝试其他 community
7. 成功 → 保存 (community, iss) 注册记录
```

```ts
const communityUri = url.searchParams.get("community");
if (!communityUri) return badRequest("community is required");

const profileId = communityAllowlist.get(communityUri);
if (!profileId) return badRequest("unknown community");

const expectedAud =
  `https://as.example.org/register?community=${encodeURIComponent(communityUri)}`;

if (!softwareStatement.aud.includes(expectedAud)) {
  return badRequest("aud does not match registration endpoint");
}

const result = await registry.verify({
  profileId,
  certificateChain: softwareStatement.x5c
});

if (!result.valid) {
  return badRequest("certificate does not belong to this community");
}

saveRegistration({
  community: communityUri,
  profileId,
  iss: softwareStatement.iss,
  clientId
});
```

注册 key 是：

```text
(community, iss)
```

不是单独的 `iss`。同一 app 可以注册到多个 community；修改注册时不得覆盖其他 community 的记录。参见 [Modifying and Cancelling Registrations](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/registration.html#modifying-and-cancelling-registrations)。

## 为什么不能从证书猜 community

如果 A、B 共享同一个 anchor：

```text
x5c 能到共同 root
  → 用 A 的 anchors 验证成功
  → 用 B 的 anchors 也验证成功
```

证书无法证明“属于 A 而不是 B”。

也不能遍历 profile 取第一个成功：

- 结果依赖遍历顺序；
- 多个 profile 可能同时通过；
- 可能注册到错误 community；
- 无法审计为什么选中它。

因此 community 必须由 UDAP adapter 显式确定，再作为 `profileId` 传给 registry。共享 anchor 时，还需要 `(community, iss)` 注册记录、tenant 或社区策略补足治理归属。

## Token：用注册记录选 profile

Token 阶段不需要重新从请求选择 community：

```text
client_id
  → 注册记录
  → profileId
  → registry.verify(x5c)
```

```ts
const registration = findRegistrationByClientId(clientId);
if (!registration) return reject("unknown client");

const result = await registry.verify({
  profileId: registration.profileId,
  certificateChain: authenticationJwt.x5c
});
```

## Trust anchor 必须提前存在

Anchors 必须在验证前由服务端加载，并绑定到 profile：

```ts
registry.register({
  trustAnchors: approvedAnchors,
  profile
});
```

它们可以来自文件、配置或数据库，但必须是本地批准的信任配置。

`verify()` 不接受 anchors，也不会使用系统 roots 或按请求动态查找 anchor。没有预置 anchors，就没有信任起点。

## 为什么这样设计 API

| API | UDAP 中的含义 |
| --- | --- |
| `profile.id` | community 的本地 profile 标识 |
| `profile.version` | 社区政策/配置版本 |
| `anchorSetId` | 该 profile 预期的 anchor bundle 版本 |
| `registry.register({ trustAnchors, profile })` | 部署时绑定 anchors 和验证规则 |
| `registry.verify({ profileId, certificateChain })` | 运行时按已选 community 验证证书链 |

固定不变的是：

- community 选择是显式输入，不从证书推断；
- anchors 是部署配置，不是请求数据；
- profile 是版本化配置，不是请求时临时拼装；
- 验证只接收证书链，调用方不能在请求时改变信任根；
- registration 按 `(community, iss)` 隔离。

## 边界

`x509-trust` 不实现 UDAP discovery、registration、token endpoint，也不验证 JWT claims 或 OAuth 授权。

它只负责：

```text
给定 profileId
  → 使用该 profile 的 anchors
  → 验证证书链
  → 返回结果
```

UDAP adapter 负责：

```text
endpoint/query + registration record
  → community
  → profileId
  → registry.verify
```

## 结论

UDAP 中稳定的用法是：

```text
1. 部署时加载每个 community 的 anchors 和 profile
2. discovery 返回带 community 的 registration endpoint
3. registration 先严格校验 community 存在且被认识
4. 用 profileId 调用 registry
5. token 阶段按 client_id 找到注册记录中的 profileId
6. 任何时候都不让请求提供 anchors
```

## 参考资料

- [FHIR UDAP Security IG](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/)
- [JWT validation](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/general.html#jwt-validation)
- [Multiple Trust Communities](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/discovery.html#multiple-trust-communities)
- [Modifying and Cancelling Registrations](https://build.fhir.org/ig/HL7/fhir-udap-security-ig/registration.html#modifying-and-cancelling-registrations)
- [UDAP Dynamic Client Registration](https://www.udap.org/udap-dynamic-client-registration-stu1.html)
- [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)
- [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960)

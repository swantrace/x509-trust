# x509-trust

Validate X.509 certificate chains and certificate revocation status in Node.js.
Requires Node.js 24 or later.

## Quick start

```sh
npm install x509-trust
```

```typescript
import { createTrustValidator } from "x509-trust";

const validator = createTrustValidator({
  trustAnchors: [rootCertificate]
});

const result = await validator.verify({
  certificateChain: [clientCertificate, intermediateCertificate]
});

if (result.valid) {
  console.log("Certificate is trusted and revocation checks passed");
} else {
  console.error(result.code, result.message);
}
```

Create a validator once and reuse it across requests. Certificates can be PEM
strings or DER byte arrays. Supply the leaf certificate first, followed by its
intermediates; the root can be omitted. Only configured `trustAnchors` establish
trust: including a root in the supplied chain does not make it trusted.

## API

These types describe the public API and can be imported from `x509-trust`.
The package also exports `createTrustValidator()`, `createTrustRegistry()`,
`createEvidenceProvider()`, `createMemoryCache()`,
`getUriSubjectAlternativeNames()`, `compileTrustPolicy()`, `PolicyError`,
`ResourceLimitError`, `createWorkerPkiEngine`, and the
policy/capability/provider/worker types.

```typescript
type CertificateInput = string | Uint8Array;

interface TrustValidatorOptions {
  trustAnchors: readonly CertificateInput[];
  policy?: TrustPolicyInput;
  rules?: readonly TrustRuleRegistration[];
  communityId?: string;
  loadCrl?: ((url: string, options?: CrlLoadOptions) => Promise<Uint8Array>) | false;
  loadOcsp?: ((options: OcspLoadOptions) => Promise<Uint8Array>) | false;
  provider?: EvidenceProvider;
  engine?: PkiEngine;
  crlIndexCache?: CrlIndexCacheOptions | false;
  http?: HttpOptions;
  deadlineMs?: number;
  cache?: CacheStore;
  maxCacheAgeMs?: number;
  cacheKeyPrefix?: string;
  now?: () => number;
  onDiagnostic?: DiagnosticCallback;
}

interface CrlIndexCacheOptions {
  maxEntries?: number;
  maxBytes?: number;
}

interface CrlLoadOptions {
  signal?: AbortSignal;
  issuerCertificate?: Uint8Array;
}

interface OcspLoadOptions {
  url: string;
  certificate: Uint8Array;
  issuerCertificate: Uint8Array;
  signal?: AbortSignal;
  requestDer?: Uint8Array;
}

interface HttpOptions {
  timeoutMs?: number;
  maxResponseBytes?: number;
  allowedOrigins?: readonly string[];
  allowPrivateAddresses?: boolean;
}

interface CacheStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlMs: number): Promise<void>;
  delete(key: string): Promise<void>;
}

interface VerifyOptions {
  certificateChain: readonly CertificateInput[];
  checkDate?: Date;
  signal?: AbortSignal;
}

interface TrustValidator {
  verify(options: VerifyOptions): Promise<ValidationResult>;
}

function createTrustValidator(options: TrustValidatorOptions): TrustValidator;

function getUriSubjectAlternativeNames(certificate: CertificateInput): string[];

function createMemoryCache(options?: {
  maxEntries?: number;
  now?: () => number;
}): CacheStore;
```

| Option                             | Default                        | Purpose                                                                                |
| ---------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------- |
| `trustAnchors`                   | Required                       | Nonempty set of explicitly trusted certificates, copied when the validator is created. |
| `loadCrl`                        | Built-in HTTP loader           | Override CRL retrieval, or set `false` to disable CRL checks.                        |
| `loadOcsp`                       | Built-in HTTP loader           | Override OCSP retrieval, or set `false` to disable OCSP checks.                      |
| `http.timeoutMs`                 | `5000`                       | Deadline for each HTTP request, including reading its body.                            |
| `http.maxResponseBytes`          | `5242880` (5 MiB)            | Maximum response body size per request.                                                |
| `http.allowedOrigins`            | No origin allowlist            | Restrict retrieval to the listed origins; public-address restrictions still apply.     |
| `http.allowPrivateAddresses`     | `false`                      | Allow private or loopback destinations for internal PKI or local use.                  |
| `cache`                          | In-memory, 256 entries         | Storage for verified CRL and OCSP evidence.                                            |
| `maxCacheAgeMs`                  | `3600000` (1 hour)           | Maximum evidence cache age, also bounded by `nextUpdate`.                            |
| `cacheKeyPrefix`                 | `"x509-trust:revocation:v1"` | Namespace for cache entries.                                                           |
| `now`                            | `Date.now`                   | Clock returning epoch milliseconds.                                                    |
| `onDiagnostic` | No callback | Receive detailed revocation and cache diagnostics using your application's logger. |
| `verify().certificateChain`      | Required                       | Leaf certificate followed by intermediates.                                            |
| `verify().checkDate`             | Current time from `now`      | Date at which to validate the path and revocation evidence.                            |
| `verify().signal`                | None                         | AbortSignal that cancels this verification; rejection is an `AbortError`.              |
| `provider`                       | Per-validator provider       | Shared `EvidenceProvider` that applies app-wide request bounds and single-flight.      |
| `deadlineMs`                     | `60000` (60 seconds)         | Overall evidence-phase deadline; exceeding it returns `RESOURCE_LIMIT_EXCEEDED`.       |
| `createMemoryCache().maxEntries` | `256`                        | Maximum entries; the oldest inserted entry is evicted when full.                       |
| `createMemoryCache().now`        | `Date.now`                   | Clock used to expire entries in that memory store.                                     |

### Results and failure codes

```typescript
type ValidationFailureCode =
  | "INVALID_CERTIFICATE"
  | "INVALID_CERTIFICATE_PATH"
  | "CERTIFICATE_REVOKED"
  | "REVOCATION_STATUS_UNKNOWN"
  | "POLICY_REJECTED"
  | "UNKNOWN_COMMUNITY"
  | "UNKNOWN_POLICY_VERSION"
  | "RESOURCE_LIMIT_EXCEEDED";

type KeyUsageName =
  | "digitalSignature"
  | "nonRepudiation"
  | "keyEncipherment"
  | "dataEncipherment"
  | "keyAgreement"
  | "keyCertSign"
  | "cRLSign"
  | "encipherOnly"
  | "decipherOnly";

interface ValidatedLeafCertificate {
  publicKeySpkiDer: Uint8Array;
  uriSubjectAlternativeNames: string[];
  fingerprint256: string;
  serialNumber: string;
  notBeforeMs: number;
  notAfterMs: number;
  subject: string;
  issuer: string;
  keyUsages?: KeyUsageName[];
  extendedKeyUsageOids?: string[];
  certificatePolicyOids?: string[];
  der: Uint8Array;
}

interface EvidenceSummary {
  certificateIndex: number;
  mechanism: "crl" | "ocsp";
  status: "good" | "revoked";
  authenticated: true;
  fresh: true;
  thisUpdateMs: number;
  nextUpdateMs: number;
  checkedAtMs: number;
}

type ValidationResult =
  | {
      valid: true;
      certificatePath: Uint8Array[];
      trustAnchorFingerprint256: string;
      leafCertificate: ValidatedLeafCertificate;
      evidence: EvidenceSummary[];
    }
  | {
      valid: false;
      code: ValidationFailureCode;
      message: string;
      certificateIndex?: number;
      evidence?: EvidenceSummary[];
    };
```

On success, `certificatePath` contains the validated path as DER bytes, leaf
first and including the selected trust anchor. `trustAnchorFingerprint256` is
that anchor's SHA-256 fingerprint. These fields let applications inspect the
selected path or record which anchor established trust.

`leafCertificate` is returned only after the path and every required revocation
check succeed. It contains identity and key metadata, not policy or transport
state. All byte fields are independent snapshots: changing them does not change
the validator, its trust anchors, its cache, or a later result.

- `publicKeySpkiDer` is the DER `SubjectPublicKeyInfo`; it imports directly with
  Node.js `createPublicKey({ key, format: "der", type: "spki" })`.
- `uriSubjectAlternativeNames` preserves URI SAN strings exactly, in certificate
  order, without case or trailing-slash normalization.
- `fingerprint256` is uppercase colon-separated SHA-256. `serialNumber` is
  uppercase hex without colons or DER sign padding.
- `notBeforeMs` and `notAfterMs` are Unix epoch milliseconds.
- `subject` and `issuer` are display strings for diagnostics. Never compare
  them for security decisions; path matching uses structured distinguished
  names inside the validation engine.
- `keyUsages` is a named BIT STRING set, not a list of OIDs. `keyUsages`,
  `extendedKeyUsageOids`, and `certificatePolicyOids` are `undefined` when the
  extension is absent. Present but malformed or duplicate extensions are
  rejected rather than reported as absent.

`evidence` lists the authenticated, fresh evidence that established each
non-anchor certificate's status. It includes the certificate index, mechanism,
status, the evidence `thisUpdate`/`nextUpdate`, and the time at which it was
checked. A revoked failure includes the revoked evidence summary; failures that
cannot authenticate evidence expose no positive evidence claim.

### Migrating from the top-level SAN field

Earlier versions returned `result.leafUriSubjectAlternativeNames`. That duplicate
field has been removed; use:

```typescript
const uris = result.leafCertificate.uriSubjectAlternativeNames;
```

The standalone `getUriSubjectAlternativeNames()` helper is unchanged and remains
useful for parsing a certificate before validation.

| Failure code                  | Meaning                                                                               |
| ----------------------------- | ------------------------------------------------------------------------------------- |
| `INVALID_CERTIFICATE`       | A supplied certificate could not be parsed.                                           |
| `INVALID_CERTIFICATE_PATH`  | No valid path to a configured anchor was found, including signature or date failures. |
| `CERTIFICATE_REVOKED`       | Authenticated evidence reports that a path certificate is revoked.                    |
| `REVOCATION_STATUS_UNKNOWN` | Revocation status could not be established for a path certificate.                    |
| `POLICY_REJECTED`           | A registered policy rule rejected an otherwise valid result.                          |
| `UNKNOWN_COMMUNITY`         | A registry request named a community that is not locally registered.                  |
| `UNKNOWN_POLICY_VERSION`    | The community exists but the requested policy version is not registered.              |
| `RESOURCE_LIMIT_EXCEEDED`   | The evidence request queue, queue wait, or overall verification deadline was exceeded. |

Revocation failures include `certificateIndex`, the zero-based position in the
validated path (`0` is the leaf). Use `code` for application decisions and
`message` for diagnostic detail.

Configuration errors are thrown rather than returned:

- `PolicyError` with `INVALID_POLICY` for malformed policy, registry,
  registration, or loader configuration.
- `PolicyError` with `UNSUPPORTED_POLICY` for a mandatory capability or rule
  name that has no implementation.
- `TypeError` for invalid option values such as an invalid `checkDate`, an empty
  anchor set, or a non-positive deadline.
- Cancellation rejects with a `DOMException` whose name is `AbortError`.

None of these thrown errors, and none of the failure codes above, can enter the
success path.

## Trust policies

`createTrustValidator({ trustAnchors, policy })` accepts an optional local policy
object. Omitting it selects the built-in strict default. The policy is compiled,
validated, deep-copied, and frozen when the validator is created; mutating the
caller's object afterwards has no effect.

```typescript
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  policy: {
    id: "example:strict",
    version: 1,
    source: "https://example.org/pki/policy/1.0",
    anchorSetId: "example:root-2026",
    revocation: {
      requiredEvidence: "both",
      sourceOrder: ["crl", "ocsp"]
    }
  }
});
```

The compiled policy has these defaults:

| Field                              | Default        | Meaning |
| ---------------------------------- | -------------- | ------- |
| `revocation.requiredEvidence`      | `"any"`        | `any`, `crl`, `ocsp`, or `both` must establish status. |
| `revocation.sourceOrder`           | `["ocsp","crl"]` | Order in which advertised mechanisms are tried. |
| `revocation.onUnknown`             | `"reject"`     | Unknown never becomes success. |
| `revocation.scope`                 | `"non-anchor-chain"` | Every non-anchor certificate is checked. |
| `revocation.requireNextUpdate`     | `true`         | Evidence must have a freshness boundary. |
| `revocation.clockSkewMs`           | `0`            | No clock-skew allowance. |

`sourceOrder` controls collection order; `requiredEvidence` independently decides
which mechanisms must produce a good result:

- `any`: the first authenticated, current good or revoked result establishes
  status. Revoked always rejects.
- `crl` / `ocsp`: only that mechanism can satisfy the requirement. The other
  mechanism may still be queried in `sourceOrder` and an authenticated revoked
  result from it still rejects, but its good status is not sufficient.
- `both`: both mechanisms must produce good results. Revoked from either
  mechanism rejects immediately.

Source URLs for each mechanism are tried in advertised order. Collection stops
as soon as the requirement is satisfied, so this library does not claim that
unqueried sources agree with the returned result. Unknown, unavailable,
unauthenticated, expired, and unsupported evidence never establish good.

Invalid policy objects throw a `PolicyError` with code `INVALID_POLICY`; a
mandatory capability that is not implemented throws code `UNSUPPORTED_POLICY`.
Disabling a loader that the policy requires is rejected at configuration time.

### Policy rules

Policies can require declarative checks on the validated result:

```typescript
policy.rules = {
  leafKeyUsage: ["digitalSignature"],
  leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
  requiredLeafPolicyOids: ["1.2.3.4"],
  maxPathDepth: 3 // total certificates, including leaf and anchor
};
```

`requiredLeafPolicyOids` checks only the leaf certificate's policy extension. It
does not claim or perform full RFC 5280 policy-tree processing. `maxPathDepth`
counts the leaf and the selected trust anchor. All requirements are ANDed and
empty arrays are rejected.

Hosts can also register named rule functions as trusted program code:

```typescript
const rules = [
  {
    name: "application-check",
    check(context: TrustRuleContext) {
      return context.leaf.extendedKeyUsageOids?.includes(
        "1.3.6.1.5.5.7.3.2"
      )
        ? { ok: true as const }
        : { ok: false as const, message: "clientAuth usage is required" };
    }
  }
];
```

Rules run only after the path and all required revocation evidence succeed. A
rule can reject a result, but cannot turn a path, signature, time, revoked, or
unknown evidence failure into success. Exceptions and unrecognized rule results
are failures. Rule facts are frozen copies derived from the validated path.

## Community registry

Use `createTrustRegistry()` when trust anchors and policies are selected by a
locally registered community identifier instead of by request input:

```typescript
const registry = createTrustRegistry({
  loadCrl: readCrlFromStorage,
  loadOcsp: false
});

registry.register({
  communityId: "community-a",
  trustAnchors: [communityARoot],
  policy: communityAPolicy,
  rules: communityARules
});

registry.register({
  communityId: "community-b",
  trustAnchors: [communityBRoot],
  policy: {
    ...communityBPolicy,
    version: 2
  }
});

const result = await registry.verify({
  communityId: "community-a",
  policyVersion: 2, // optional; the highest registered version otherwise
  certificateChain: [clientCertificate, intermediateCertificate]
});
```

Communities are independent. The same certificate SAN can appear in two
communities whose trust anchors differ, and each community can register several
policy versions. The registry stores immutable anchors, compiled policies, and trusted rules.
`verify()` input can select only a registered community and optional version; it
cannot supply anchors, policies, or rules. Unknown communities return
`UNKNOWN_COMMUNITY` and do not fall back to another community or to a default
validator. Unknown versions return `UNKNOWN_POLICY_VERSION`.

Registering the same community and policy version twice throws
`INVALID_POLICY`; a failed registration is not partially stored. Each request
selects its snapshot before awaiting validation, so registering a new version
does not change an in-flight request. Successful registry results include
`communityId`, `policyId`, and `policyVersion`.

## Validation policy and supported PKI

The validator first builds and validates a path to a configured trust anchor,
then checks revocation for the leaf and every intermediate. The configured
anchor itself is not checked for revocation; applications control trust in it
by adding or removing it from `trustAnchors` when creating a validator.

For each certificate, the compiled policy selects mechanisms from
`sourceOrder` and determines whether any, CRL, OCSP, or both must establish a
good status. A later certificate's success cannot compensate for an earlier
certificate's unknown or revoked status. This is a fail-closed policy:
unavailable endpoints, missing endpoints, disabled mechanisms, invalid
signatures, expired evidence, or unsupported evidence never count as proof that
a certificate is not revoked. Disabling both CRL and OCSP does not bypass
revocation validation for non-anchor certificates.

| Evidence                                                 | Current support                                                                                |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Complete CRLs signed directly by the certificate issuer  | Supported, without scope restrictions.                                                         |
| OCSP responses signed directly by the certificate issuer | Supported.                                                                                     |
| Delegated OCSP responders                                | Not supported; a separate authorized responder certificate cannot currently establish status.  |
| Delta CRLs                                               | Not supported; changes cannot currently be combined with a base CRL.                           |
| Scoped or indirect CRLs                                  | Not supported; restricted coverage or a separate CRL issuer cannot currently establish status. |
| OCSP responses without `nextUpdate`                    | Not accepted; treated as unknown, allowing CRL fallback.                                       |

OCSP permits omitting `nextUpdate`, but this verifier requires it to set an
explicit freshness boundary. This is a library restriction, not an OCSP
requirement. Both CRL and OCSP evidence must have a usable `nextUpdate`.

Before using the library with a trust community or CA, confirm that its PKI
publishes evidence within this supported scope. Rejecting unsupported evidence
avoids accepting an unverified status, but can also reject otherwise valid
certificates.

## Shared evidence provider

By default each validator creates its own evidence provider and downloads with
conservative finite limits. To enforce application-wide limits across several
validators or communities, create one provider explicitly and pass it to each
validator or to the registry:

```typescript
import {
  createEvidenceProvider,
  createTrustValidator
} from "x509-trust";

const provider = createEvidenceProvider({
  loadCrl: readCrlFromStorage,
  loadOcsp: false,
  maxActiveRequests: 8,
  maxQueuedRequests: 32,
  maxActivePerOrigin: 4,
  queueTimeoutMs: 30000
});

const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  provider,
  deadlineMs: 60000
});
```

| Provider option      | Default | Meaning |
| -------------------- | ------- | ------- |
| `maxActiveRequests`  | `8`     | Maximum simultaneous evidence downloads across the provider. |
| `maxQueuedRequests`  | `32`    | Maximum requests waiting for a slot; excess is rejected. |
| `maxActivePerOrigin` | `4`     | Maximum simultaneous downloads per URL origin. |
| `queueTimeoutMs`     | `30000` | Maximum time a request may wait for a slot. |

Queue-full, queue-timeout, and verification-deadline conditions return
`RESOURCE_LIMIT_EXCEEDED`. They never become a good or unknown status.

The provider runs single-flight only for raw downloads. A CRL flight is keyed by
URL, issuer, and the provider instance; an OCSP flight also includes the target
certificate and the request DER. Different provider instances, even with the
same URL, do not share work, which keeps separate loader, origin, credential, or
SSRF configurations isolated. Function source text is never used as identity.

Each waiting verification can cancel independently. A cancel removes only that
waiter; when the last waiter leaves, the underlying request aborts. Successful
and failed flights are always removed so a later request can retry. A shared CRL
download is still evaluated separately for each certificate; a `good` result
for one certificate never becomes another certificate's status.

## Optional worker execution

PKI.js path, CRL, and OCSP computation runs inline by default. When a host needs
to keep CPU-heavy evidence validation off the main thread, create a bounded,
reusable Piscina pool and pass its engine to one or more validators or to a
registry:

```typescript
import {
  createTrustValidator,
  createWorkerPkiEngine
} from "x509-trust";

const engine = createWorkerPkiEngine({
  maxThreads: 2,
  maxQueue: 16,
  taskTimeoutMs: 5000
});

const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  provider,
  engine
});

// The caller owns the pool and must release it.
await engine.close({ force: true });
```

| Worker option   | Default | Meaning |
| --------------- | ------- | ------- |
| `maxThreads`    | `min(4, availableParallelism - 1)` | Maximum worker threads. |
| `minThreads`    | `0`     | Threads kept ready at all times. |
| `maxQueue`      | `maxThreads * 4` | Maximum tasks waiting for a worker. |
| `idleTimeout`   | `30000` | Idle worker shutdown delay. |
| `taskTimeoutMs` | `10000` | Per-task deadline; expiry aborts that worker task. |
| `crlIndexCache` | enabled, 8 entries / 64 MiB | Worker-local parsed CRL index cache; `false` disables it. |
| `filename`      | packaged worker | Override only when embedding the worker file yourself. |

Only DER bytes and JSON-compatible DTOs cross the thread boundary. HTTP,
bounded request scheduling, single-flight, caching, diagnostics, registered
rules, and cancellation remain on the main thread. The pool is long-lived and
can be shared by validators and registry communities; it is not created per
verification or per community.

Worker queue overflow and task timeouts return `RESOURCE_LIMIT_EXCEEDED`.
Aborting a task terminates its worker; the pool replaces it, and subsequent
tasks are unaffected. Aborting a queued task rejects it without terminating a
running task. Inline and worker modes produce the same success and failure
results for the same inputs.

Worker execution is optional and not the default. `docs/benchmark.md` records
the local inline/worker comparison: the worker path clearly reduces main-thread
event-loop delay for CPU-heavy path work, while small CRL/OCSP tasks can be
slightly slower because of task dispatch overhead. Choose it from measurements
on the target deployment, not from a blanket default.

## Parsed CRL index cache

In addition to the raw DER cache, the inline engine keeps a bounded parsed CRL
index cache by default. It stores the parsed CRL object, a serial-number `Set`,
and the unsupported-extension result, keyed by SHA-256 of the CRL DER.

This cache is only an acceleration structure:

- Every use still checks issuer, `thisUpdate`/`nextUpdate`, signature, and
  certificate applicability.
- The per-certificate `good`/`revoked` result is computed from the cached serial
  set; it is never stored as a certificate status conclusion.
- A changed CRL DER has a different key and is parsed separately.
- Entries are bounded by both count and approximate bytes (defaults: 8 entries,
  64 MiB) with LRU eviction; there is no independent trust TTL.
- The raw DER cache remains the source for reauthentication and auditing.

The cache is enabled by default for inline validators and for each worker-local
engine. Disable or size it per validator/registry/worker engine:

```typescript
createTrustValidator({
  trustAnchors: [rootCertificate],
  provider,
  crlIndexCache: { maxEntries: 16, maxBytes: 128 * 1024 * 1024 }
});
// or
createTrustValidator({ trustAnchors: [rootCertificate], crlIndexCache: false });
```

Worker caches are per worker thread and are not shared between workers; the raw
DER cache and HTTP single-flight remain on the main thread. The benchmark in
[docs/benchmark.md](docs/benchmark.md) separates isolated CRL validation from
full path plus evidence validation, because path validation can dominate the
full-validator totals.

In the latest local run, isolated validation of a 3,000-entry CRL improved from
about 390 ms p50 without the index to about 2.3 ms p50 with it. Worker mode
measured about 395 ms without the index and 8.7 ms with it; it kept event-loop
p99 near 2 ms while inline indexed validation stayed tens of milliseconds. The
index cache is therefore the first optimization for large repeated CRLs; worker
mode remains a responsiveness tradeoff, not a throughput default.

## Concurrency, early rejection, and cancellation

After the path validates, the leaf and every intermediate start revocation
pipelines concurrently. Within each certificate, mechanisms and their URLs keep
the policy's ordered, sequential fallback; there is no cross-certificate barrier
before validating a response or trying the next source.

Overall success still requires every non-anchor certificate to satisfy the
policy. The validator races only an authenticated `revoked` result against
completion of all pipelines:

- Once an authenticated revoked result is confirmed, `verify()` returns it
  without waiting for stalled loaders or cache writes from other certificates.
- A slow or signal-ignoring custom loader cannot delay that confirmed failure.
- Results that arrive after the failure has been returned cannot override it.
- Revoked cache writes run in the background with their rejections observed;
  good cache writes keep the existing behavior.

Pass an `AbortSignal` to `verify()` to cancel the whole verification. Built-in
HTTP loaders combine it with their request deadline; custom loaders receive it
as `options.signal` (CRL) or `options.signal` (OCSP) and should honor it. An
external cancellation rejects with an `AbortError`; it never becomes a
successful result.

The library validates certificate trust and revocation. Applications remain
responsible for their protocol rules, such as matching a JWT issuer to a
certificate SAN, verifying the JWT signature and claims, and deciding what the
authenticated party may access. A successful certificate result alone does not
establish UDAP compliance.

## Reading URI subject alternative names

Use `getUriSubjectAlternativeNames()` to extract URI entries from a certificate's
Subject Alternative Name extension:

```typescript
import { getUriSubjectAlternativeNames } from "x509-trust";

const uris = getUriSubjectAlternativeNames(clientCertificate);
```

The function accepts a PEM string or DER bytes and returns URI entries in their
original order, without normalization. Other name types are excluded. A missing
SAN extension or one with no URI entries returns `[]`; invalid certificates or
malformed SAN extensions throw errors. Parsing the structured extension preserves
commas within URI values.

Extraction does not validate trust, revocation, or JWT claims. Applications must
validate the certificate and apply their protocol's issuer matching rules. When
using Node.js `X509Certificate` objects, pass `certificate.raw`.

## Retrieving revocation evidence

By default, the validator downloads CRLs with HTTP GET and sends unsigned DER
OCSP requests with HTTP POST. CRL downloads may be DER or PEM. OCSP requests omit
the optional nonce; response signatures and freshness are verified before use.

Because retrieval URLs come from supplied certificates, built-in retrieval
restricts destinations to reduce SSRF exposure. Redirects and HTTP(S) URLs with
embedded credentials or fragments are rejected. Only public IPv4 and
global-unicast IPv6 destinations are permitted by default, with resolved
addresses checked when establishing each connection.

Use an origin allowlist when the CA endpoints are known:

```typescript
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  http: {
    allowedOrigins: ["https://ca.example.org", "http://ocsp.example.org"],
    timeoutMs: 5000,
    maxResponseBytes: 5 * 1024 * 1024
  }
});
```

For internal PKI or local endpoints, set `http.allowPrivateAddresses: true`,
preferably with an origin allowlist. HTTPS endpoints must also pass Node.js TLS
verification.

### Custom loaders and disabled mechanisms

Supply `loadCrl` or `loadOcsp` to retrieve evidence through your own transport or
from offline storage. Callbacks return DER bytes; OCSP callbacks receive the
target certificate and its issuer as DER bytes. The library still validates
the returned evidence.

```typescript
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  loadCrl: async (url) => readCrlFromStorage(url),
  loadOcsp: false
});
```

Here, `readCrlFromStorage` is an application-provided function. This example
permits CRL checks only. Setting a loader to `false` disables that mechanism for
the entire validator, even when certificates advertise its URLs. Omitting a
loader uses the built-in HTTP implementation.

The `http` settings apply only to built-in loaders. Custom loaders own their
network restrictions, timeouts, and size limits. For historical validation,
`checkDate` changes the validation date but does not retrieve historical evidence;
provide suitable evidence through custom loaders.

## Diagnostics

Pass `onDiagnostic` to send detailed revocation and cache events to your existing
logger or monitoring system. The library does not log automatically or require
a logging dependency.

```typescript
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  onDiagnostic(event) {
    logger.debug(event);
  }
});
```

`logger` is supplied by the application. The exported diagnostic types are:

```typescript
interface DiagnosticEvent {
  event:
    | "cache_hit"
    | "cache_miss"
    | "cache_discarded"
    | "cache_error"
    | "revocation_result"
    | "revocation_error";
  mechanism: "crl" | "ocsp";
  certificateIndex?: number;
  code?: string;
  status?: "good" | "revoked" | "unknown";
  message: string;
}

type DiagnosticCallback = (event: DiagnosticEvent) => void | Promise<void>;
```

For example, a `revocation_result` event may report `status: "unknown"` and
`code: "OCSP_MISSING_NEXT_UPDATE"`, followed by a CRL attempt. These internal
codes explain individual attempts; `verify()` still returns the public failure
codes documented above. `revocation_error` reports a loading or validation
exception without forwarding its raw error message. Cache events distinguish
reuse, misses, discarded evidence, and storage failures.

Events include the mechanism and certificate index but exclude certificate
contents, evidence bytes, cache keys, and source URLs. Callbacks are invoked in
check order; returned promises are not awaited. Synchronous exceptions and
promise rejections from callbacks are ignored so diagnostics cannot change the
validation result. Diagnostics describe evidence attempts and cache activity,
not every validation outcome; a path failure or missing endpoints may produce
no diagnostic events.

## Caching

The default cache holds up to 256 entries in memory. Reusing the validator lets
repeated requests avoid downloading the same evidence. CRLs can be shared across
certificates with the same issuer and CRL URL; OCSP entries also identify the
individual certificate.

Only evidence that establishes `good` or `revoked` status is cached. Its expiry
is the earlier of `nextUpdate` and the time it was cached plus `maxCacheAgeMs`
(one hour by default). A cache hit does not extend that expiry. For example,
evidence cached at 10:00 with `nextUpdate` at 12:00 expires at 11:00 under the
default limit, even if used again at 10:30.

Cached evidence is revalidated for the certificate, issuer, and validation date
on each use. Certificate paths are also validated on every request. Unknown
results are not cached. Cache failures trigger fresh retrieval and validation;
expired evidence is never used as a fallback. Caching introduces a delay before
newly published revocation information is observed, so choose `maxCacheAgeMs`
according to your deployment's freshness requirements.

To change the memory limit, pass `createMemoryCache({ maxEntries: 1024 })` as
`cache`. For shared storage, adapt an existing client to `CacheStore`. For example,
with a connected Node Redis client:

```typescript
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  cacheKeyPrefix: "sahara:x509-trust:revocation:v1",
  cache: {
    get: (key) => redisClient.get(key),
    async set(key, value, ttlMs) {
      await redisClient.set(key, value, { PX: ttlMs });
    },
    async delete(key) {
      await redisClient.del(key);
    }
  }
});
```

The application owns the Redis connection. Cache values are strings and TTLs
are expressed in milliseconds.


## Benchmark

`npm run benchmark` generates `docs/benchmark.md` from synthetic certificates,
signed CRL/OCSP evidence, and a local HTTP server. It reports cold and warm
validation, slow sources, early revocation, OCSP-to-CRL fallback, a shared
single-flight burst, a large cached CRL, and inline/worker CPU path work. It is a
measurement tool, not a unit-test gate.

`npm run benchmark:concurrency` generates `docs/concurrency-benchmark.md`. It
runs closed-loop concurrent validations while a separate health endpoint is
polled in the same process, reporting validation throughput, health latency,
event-loop delay, CPU, RSS, and worker queue depth. Use it to compare inline and
worker modes under application-like load; results are local measurements, not a
production SLA.

## Migration from the native/Rust branch

This release is the pure TypeScript/Node implementation. It does not ship a
native addon, `native/` directory, Cargo files, napi-rs bindings, `.node`
binaries, or `@napi-rs/*` runtime dependency. Artifacts from the Rust branch are
not used or packed.

| Rust-branch export | This package |
| ------------------ | ------------ |
| `nativeValidateCertificatePath()` | `createTrustValidator().verify()` or `createTrustRegistry().verify()` |
| `nativeValidateCrl()` / `nativeValidateOcsp()` | Internal DER engine steps; callers use `verify()` |
| `nativeCreateOcspRequest()` | Internal engine step; custom OCSP loaders receive `requestDer` context from the provider |
| `nativeCertificateDer()` | Not public; pass PEM or DER `CertificateInput` to the validator |
| `nativeUriSubjectAlternativeNames()` | `getUriSubjectAlternativeNames()` or `result.leafCertificate.uriSubjectAlternativeNames` |
| `nativeRevocationEndpoints()` | Not public; the validator reads AIA/CRL distribution points during path preparation |

For applications that persist or compare validation output, keep these formats
in mind:

- `fingerprint256` is uppercase colon-separated SHA-256.
- `serialNumber` is uppercase hex without colons or DER sign padding.
- Validity and evidence times are Unix epoch milliseconds.
- `leafCertificate` nests identity/key metadata; the old top-level
  `leafUriSubjectAlternativeNames` field is removed.
- Failures are `ValidationResult` objects with the documented `code` union, not
  mixed native result shapes.
- Revocation summaries use `evidence[]` entries with `certificateIndex`,
  `mechanism`, status, authentication/freshness facts, and epoch-millisecond
  timestamps.

Sahara and its databases were not modified by this work. Its Rust branch and
credentials remain outside this repository.

## Package and deployment contract

- Node.js 24 or later; ESM only.
- Public entry point: `x509-trust` via `./dist/index.js` and `./dist/index.d.ts`.
- Runtime dependencies: `asn1js`, `pkijs`, and `piscina` (only for the optional
  worker engine). The worker file is included in `dist` and resolved relative to
  the installed package, including when the package is installed from a tarball.
- `npm pack` contains `dist`, `package.json`, and `README.md`; it excludes
  `.dsh`, PDFs, tests, benchmark sources, fixtures, native artifacts, private
  keys, and stale build output. Builds remove `dist` first so stale files cannot
  be packed.
- No database, UI framework, or web server is part of this package.

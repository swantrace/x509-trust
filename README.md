# x509-trust

Validate X.509 certificate chains and certificate revocation status in Node.js.
Requires Node.js 24 or later.

The validator builds a path to an explicitly configured trust anchor, checks
signatures, validity periods, CA constraints, name constraints, and revocation
evidence, then applies a local validation profile. Unknown or unusable
revocation evidence never becomes success.

- DER or PEM certificate input.
- CRL and OCSP verification signed by the certificate issuer.
- Fail-closed revocation requirements with explicit evidence choices.
- Immutable validation profiles with declarative rules.
- Concurrent per-certificate evidence collection with authenticated-revoked
  early exit and `AbortSignal` cancellation.
- Bounded evidence provider with per-origin limits and shared downloads.
- Raw DER evidence cache.
- Optional Piscina worker engine on a separate entry point.
- Structured `findings` for diagnostics and audit.

## Quick start

```sh
npm install x509-trust
```

Worker execution is optional and requires `piscina`:

```sh
npm install piscina
```

```typescript
import { createValidationProfileRegistry } from "x509-trust";

const registry = createValidationProfileRegistry();

registry.register({
  trustAnchors: [rootCertificate],
  profile: {
    id: "example:strict",
    version: 1,
    source: "local-config",
    anchorSetId: "example:root-2026",
    revocation: {
      requiredEvidence: "any",
    },
  },
});

const result = await registry.verify({
  profileId: "example:strict",
  certificateChain: [clientCertificate, intermediateCertificate],
});

if (result.valid) {
  console.log("Certificate is trusted and revocation checks passed");
} else {
  console.error(result.code, result.message);
}
```

Create the registry once and reuse it across requests. Each registered profile
owns its trust anchors and validation rules; `verify()` selects a locally
registered `profileId`. The `profileId` must come from trusted application
context, never directly from an untrusted request body.

Certificates may be PEM strings or DER byte arrays. Supply the leaf first,
followed by intermediates; the trust anchor may be omitted from the chain. Only
configured `trustAnchors` establish trust: including a root in the supplied
chain does not make it trusted.

When a deployment has exactly one fixed profile and anchor set,
`createTrustValidator({ trustAnchors, profile })` is the simpler direct API.
Both paths run the same validation.

## API

Public entry points:

- `x509-trust` — validator, profiles, registry, evidence provider, diagnostics.
- `x509-trust/worker` — optional Piscina-backed PKI engine.

```typescript
type CertificateInput = string | Uint8Array;

interface TrustValidatorOptions {
  trustAnchors: readonly CertificateInput[];
  profile?: ValidationProfileInput;
  rules?: readonly TrustRuleRegistration[];
  loadCrl?:
    | ((url: string, options?: CrlLoadOptions) => Promise<Uint8Array>)
    | false;
  loadOcsp?: ((options: OcspLoadOptions) => Promise<Uint8Array>) | false;
  provider?: EvidenceProvider;
  engine?: PkiEngine;
  http?: HttpOptions;
  deadlineMs?: number;
  cache?: CacheStore;
  maxCacheAgeMs?: number;
  cacheKeyPrefix?: string;
  now?: () => number;
  onDiagnostic?: DiagnosticCallback;
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

| Option                         | Default                        | Purpose                                                                  |
| ------------------------------ | ------------------------------ | ------------------------------------------------------------------------ |
| `trustAnchors`               | Required                       | Nonempty set of explicitly trusted certificates, copied at construction. |
| `profile`                    | Built-in strict profile        | Local validation profile; compiled and frozen at construction.           |
| `rules`                      | None                           | Trusted custom rule functions.                                           |
| `loadCrl`                    | Built-in HTTP loader           | Override CRL retrieval, or `false` to disable CRL checks.              |
| `loadOcsp`                   | Built-in HTTP loader           | Override OCSP retrieval, or `false` to disable OCSP checks.            |
| `provider`                   | Per-validator provider         | Shared provider for request limits and shared downloads.                 |
| `engine`                     | Inline engine                  | Worker-backed engine from `x509-trust/worker`.                         |
| `http.timeoutMs`             | `5000`                       | Deadline for each HTTP request, including reading its body.              |
| `http.maxResponseBytes`      | `5242880` (5 MiB)            | Maximum response body size per request.                                  |
| `http.allowedOrigins`        | No allowlist                   | Restrict retrieval to the listed origins.                                |
| `http.allowPrivateAddresses` | `false`                      | Allow private or loopback destinations.                                  |
| `deadlineMs`                 | `60000`                      | Overall evidence-phase deadline.                                         |
| `cache`                      | In-memory, 256 entries         | Storage for verified CRL and OCSP evidence.                              |
| `maxCacheAgeMs`              | `3600000` (1 hour)           | Maximum evidence cache age, also bounded by `nextUpdate`.              |
| `cacheKeyPrefix`             | `"x509-trust:revocation:v1"` | Cache namespace.                                                         |
| `now`                        | `Date.now`                   | Clock returning epoch milliseconds.                                      |
| `onDiagnostic`               | None                           | Receive cache and revocation diagnostics.                                |
| `verify().certificateChain`  | Required                       | Leaf certificate followed by intermediates.                              |
| `verify().checkDate`         | `now()`                      | Date at which to validate the path and evidence.                         |
| `verify().signal`            | None                           | Cancels verification; rejection is an `AbortError`.                    |

### Validation profiles

```typescript
type ProfileVersion = string | number;

interface ProfileSource {
  uri: string;
  version?: string;
  effectiveDate?: string;
}

interface ValidationProfileInput {
  id: string;
  version: ProfileVersion;
  /** Explicit ordering for latest-version selection. */
  versionOrder?: number;
  source: string | ProfileSource;
  anchorSetId: string;
  revocation?: {
    requiredEvidence?: "any" | "crl" | "ocsp" | "both";
    sourceOrder?: readonly ("crl" | "ocsp")[];
    onUnknown?: "reject";
    scope?: "non-anchor-chain";
    requireNextUpdate?: true;
    clockSkewMs?: 0;
  };
  rules?: {
    leafKeyUsage?: readonly KeyUsageName[];
    leafExtendedKeyUsage?: readonly string[];
    requiredCertificatePolicyOids?: readonly string[];
    maxPathDepth?: number;
    requiredRuleNames?: readonly string[];
  };
}
```

The profile is compiled, validated, deep-copied, and frozen when the validator is
created. Mutating the caller's object afterwards has no effect.

- `version` accepts a positive number or a non-empty string.
- Numeric versions default `versionOrder` to the version number.
- String versions require a positive integer `versionOrder`.
- `source` accepts a URI string or `{ uri, version?, effectiveDate? }`.

```typescript
import { createTrustValidator } from "x509-trust";

const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  profile: {
    id: "example:strict",
    version: "2026-01",
    versionOrder: 1,
    source: {
      uri: "https://example.org/pki/profile",
      version: "3.1",
      effectiveDate: "2026-01-01",
    },
    anchorSetId: "example:root-2026",
    revocation: {
      requiredEvidence: "both",
      sourceOrder: ["crl", "ocsp"],
    },
  },
});
```

Defaults:

| Field                            | Default                | Meaning                                                        |
| -------------------------------- | ---------------------- | -------------------------------------------------------------- |
| `revocation.requiredEvidence`  | `"any"`              | `any`, `crl`, `ocsp`, or `both` must establish status. |
| `revocation.sourceOrder`       | `["ocsp", "crl"]`    | Order in which advertised mechanisms are tried.                |
| `revocation.onUnknown`         | `"reject"`           | Unknown never becomes success.                                 |
| `revocation.scope`             | `"non-anchor-chain"` | Every non-anchor certificate is checked.                       |
| `revocation.requireNextUpdate` | `true`               | Evidence must have a freshness boundary.                       |
| `revocation.clockSkewMs`       | `0`                  | No clock-skew allowance.                                       |

`sourceOrder` controls collection order. `requiredEvidence` decides which
mechanisms must produce a good result:

- `any`: the first authenticated, current good or revoked result establishes
  status. Revoked always rejects.
- `crl` / `ocsp`: only that mechanism satisfies the requirement. The other may
  still be queried, and an authenticated revoked result from it still rejects.
- `both`: both mechanisms must produce good results.

Source URLs are tried in advertised order. Collection stops as soon as the
requirement is satisfied; the library does not claim that unqueried sources agree
with the returned result. Unknown, unavailable, unauthenticated, expired, and
unsupported evidence never establish good status.

Invalid profiles throw `ProfileError` with `INVALID_PROFILE`. Unsupported
configuration values or rule names throw `UNSUPPORTED_PROFILE`. Disabling a
loader that the profile requires is rejected at configuration time.

### Profile files

Profiles are local, reviewed, versioned data under `profiles/<profile-id>/`:

```text
profiles/
├── default/
│   └── profile.json
└── example/
    ├── profile.json
    └── anchors/          # optional public trust bundle
```

`profiles/default/profile.json` mirrors the built-in strict default; the code
constant `DEFAULT_VALIDATION_PROFILE` is authoritative. The library never
downloads a profile from a request-supplied URI. `anchors/` may contain only
public, host-approved certificates, never private keys. See
[profiles/README.md](profiles/README.md).

### Profile rules

Declarative checks run after the path and all required revocation evidence
succeed:

```typescript
profile.rules = {
  leafKeyUsage: ["digitalSignature"],
  leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
  requiredCertificatePolicyOids: ["1.2.3.4"],
  maxPathDepth: 3, // total certificates, including leaf and anchor
};
```

`requiredCertificatePolicyOids` checks only the leaf certificate's policy
extension. It does not perform full RFC 5280 policy-tree processing.
`maxPathDepth` counts the leaf and the selected trust anchor. Requirements are
ANDed; empty arrays are rejected.

Hosts can register named rule functions as trusted program code:

```typescript
const rules = [
  {
    name: "application-check",
    check(context: TrustRuleContext) {
      return context.leaf.extendedKeyUsageOids?.includes("1.3.6.1.5.5.7.3.2")
        ? { ok: true as const }
        : { ok: false as const, message: "clientAuth usage is required" };
    },
  },
];
```

A rule can reject a result but cannot turn a path, signature, time, revoked, or
unknown evidence failure into success. Exceptions and unrecognized results are
failures. Rule facts are frozen copies derived from the validated path.

## Validation profile registry

Use `createValidationProfileRegistry()` when trust anchors and profiles are
selected by a locally registered `profileId` instead of by request input:

```typescript
import { createValidationProfileRegistry } from "x509-trust";

const registry = createValidationProfileRegistry({
  loadCrl: readCrlFromStorage,
  loadOcsp: false,
});

registry.register({
  trustAnchors: [profileARoot],
  profile: profileA,
  rules: profileARules,
});

registry.register({
  trustAnchors: [profileBRoot],
  profile: {
    ...profileB,
    version: 2,
  },
});

const result = await registry.verify({
  profileId: "profile-a",
  profileVersion: 2, // optional; highest registered version otherwise
  certificateChain: [clientCertificate, intermediateCertificate],
});
```

- `profile.id` is the registry key.
- Each profile may register several versions.
- `versionOrder` selects the latest version when `profileVersion` is omitted.
- Duplicate profile version or duplicate `versionOrder` is rejected.
- Registration stores immutable anchors, compiled profiles, and trusted rules.
- `verify()` can select only a registered profile and version; it cannot supply
  anchors, profiles, or rules.
- Unknown profiles return `UNKNOWN_PROFILE`; unknown versions return
  `UNKNOWN_PROFILE_VERSION`.
- Each request selects its snapshot before awaiting validation, so registering a
  new version does not change a request already in progress.
- Successful registry results include `profileId` and `profileVersion`.

Profiles are independent. The same certificate SAN can appear in two profiles
whose trust anchors differ.

### FHIR UDAP hosts

The core package has no built-in UDAP vocabulary. A UDAP host maps
its external framework identifier to a local `profileId` and registers approved
anchors itself:

```typescript
const profileId = `udap:${frameworkIdentifier}`;

registry.register({
  trustAnchors: approvedUdapAnchors,
  profile: { ...udapProfile, id: profileId },
});

await registry.verify({ profileId, certificateChain });
```

JWT `x5c`, `iss`/`aud`, OAuth, replay protection, and framework requirements
remain application responsibilities. See
[examples/udap/README.md](examples/udap/README.md).

## Results and failure codes

```typescript
type ValidationFailureCode =
  | "INVALID_CERTIFICATE"
  | "INVALID_CERTIFICATE_PATH"
  | "CERTIFICATE_REVOKED"
  | "REVOCATION_STATUS_UNKNOWN"
  | "PROFILE_REJECTED"
  | "UNKNOWN_PROFILE"
  | "UNKNOWN_PROFILE_VERSION"
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

interface EvidenceFinding {
  certificateIndex: number;
  mechanism: "crl" | "ocsp";
  status: "good" | "revoked" | "unknown";
  authenticated: boolean;
  fresh: boolean;
  code?: string;
  message: string;
  thisUpdateMs?: number;
  nextUpdateMs?: number;
  checkedAtMs?: number;
}

interface CertificateFindings {
  certificateIndex: number;
  pathValid: true;
  revocation: {
    crl: EvidenceFinding[];
    ocsp: EvidenceFinding[];
  };
}

type ValidationResult =
  | {
      valid: true;
      certificatePath: Uint8Array[];
      trustAnchorFingerprint256: string;
      leafCertificate: ValidatedLeafCertificate;
      evidence: EvidenceSummary[];
      findings: CertificateFindings[];
      profileId: string;
      profileVersion: ProfileVersion;
    }
  | {
      valid: false;
      code: ValidationFailureCode;
      message: string;
      certificateIndex?: number;
      evidence?: EvidenceSummary[];
      findings?: CertificateFindings[];
      profileId?: string;
      profileVersion?: ProfileVersion;
    };
```

| Failure code                  | Meaning                                                                               |
| ----------------------------- | ------------------------------------------------------------------------------------- |
| `INVALID_CERTIFICATE`       | A supplied certificate could not be parsed.                                           |
| `INVALID_CERTIFICATE_PATH`  | No valid path to a configured anchor was found, including signature or date failures. |
| `CERTIFICATE_REVOKED`       | Authenticated evidence reports that a path certificate is revoked.                    |
| `REVOCATION_STATUS_UNKNOWN` | Revocation status could not be established.                                           |
| `PROFILE_REJECTED`          | A profile rule rejected an otherwise valid result.                                    |
| `UNKNOWN_PROFILE`           | A registry request named a profile that is not registered.                            |
| `UNKNOWN_PROFILE_VERSION`   | The profile exists but the requested version is not registered.                       |
| `RESOURCE_LIMIT_EXCEEDED`   | The request queue, queue wait, or overall deadline was exceeded.                      |

Revocation failures include `certificateIndex`, the zero-based position in the
validated path (`0` is the leaf). Use `code` for application decisions and
`message` for diagnostic detail.

Configuration errors are thrown:

- `ProfileError` with `INVALID_PROFILE` for malformed profiles, registration, or
  loader configuration.
- `ProfileError` with `UNSUPPORTED_PROFILE` for an unsupported configuration
  value or rule name that has no implementation.
- `TypeError` for invalid option values.
- Cancellation rejects with a `DOMException` named `AbortError`.

None of these errors or failure codes can enter the success path.

On success, `certificatePath` contains the validated path as DER bytes, leaf
first and including the selected anchor. `trustAnchorFingerprint256` is that
anchor's SHA-256 fingerprint.

`leafCertificate` is returned only after the path and every required revocation
check succeed. It contains identity and key metadata, not profile or transport
state. Byte fields are independent snapshots.

- `publicKeySpkiDer` imports with
  `createPublicKey({ key, format: "der", type: "spki" })`.
- `uriSubjectAlternativeNames` preserves URI SAN strings in certificate order.
- `fingerprint256` is uppercase colon-separated SHA-256; `serialNumber` is
  uppercase hex without separators.
- `notBeforeMs` and `notAfterMs` are Unix epoch milliseconds.
- `subject` and `issuer` are display strings. Never use them for security
  decisions; path matching uses structured names inside the engine.
- `keyUsages` is a named BIT STRING set. Optional extensions are `undefined`
  when absent; malformed or duplicate extensions are rejected.

`evidence` lists the authenticated, fresh evidence that established each
non-anchor certificate's status. `findings` records the CRL and OCSP attempts
that were actually made, including `unknown` attempts. An authenticated-revoked
early result may include only the revoked certificate's findings. Findings are
for audit, diagnostics, and tests; they are not a trust decision.

## Supported PKI and evidence

The validator builds and validates a path to a configured trust anchor, then
checks revocation for the leaf and every intermediate. The configured anchor
itself is not checked for revocation; applications control trust in it through
`trustAnchors`.

| Evidence                                                 | Support                           |
| -------------------------------------------------------- | --------------------------------- |
| Complete CRLs signed directly by the certificate issuer  | Supported.                        |
| OCSP responses signed directly by the certificate issuer | Supported.                        |
| Delegated OCSP responders                                | Not supported.                    |
| Delta CRLs                                               | Not supported.                    |
| Scoped or indirect CRLs                                  | Not supported.                    |
| OCSP responses without `nextUpdate`                    | Not accepted; treated as unknown. |

Both CRL and OCSP evidence must have a usable `nextUpdate`. This is a library
freshness requirement. Before using the library with a CA, confirm that its PKI
publishes evidence within this supported scope.

## Shared evidence provider

By default each validator creates its own evidence provider with finite limits.
Repeated `verify()` calls on the same validator share that provider. To share
limits and pending downloads across multiple validators or profiles in the
same process, create one provider during application setup and pass the same
object to each validator:

```typescript
import { createEvidenceProvider, createTrustValidator } from "x509-trust";

const provider = createEvidenceProvider({
  loadCrl: readCrlFromStorage,
  loadOcsp: false,
  maxActiveRequests: 8,
  maxQueuedRequests: 32,
  maxActivePerOrigin: 4,
  queueTimeoutMs: 30000,
});

const validatorA = createTrustValidator({
  trustAnchors: [rootCertificateA],
  provider,
  deadlineMs: 60000,
});

const validatorB = createTrustValidator({
  trustAnchors: [rootCertificateB],
  provider,
  deadlineMs: 60000,
});
```

Here `validatorA` and `validatorB` together can run at most eight downloads. With
separate providers, each would have its own eight-download limit and could
download the same evidence independently. The same provider can also be passed
to `createValidationProfileRegistry({ provider })` to share it across registered
profiles. Validation still uses each validator's own trust anchors and profile;
the `cache` option controls evidence caching separately. Separate processes or
application replicas have independent provider instances and limits.

| Provider option        | Default   | Meaning                                              |
| ---------------------- | --------- | ---------------------------------------------------- |
| `maxActiveRequests`  | `8`     | Simultaneous evidence downloads across the provider. |
| `maxQueuedRequests`  | `32`    | Requests waiting for a slot; excess is rejected.     |
| `maxActivePerOrigin` | `4`     | Simultaneous downloads per URL origin.               |
| `queueTimeoutMs`     | `30000` | Maximum time waiting for a slot.                     |

Queue-full, queue-timeout, and verification-deadline conditions return
`RESOURCE_LIMIT_EXCEEDED`.

The provider shares matching downloads while they are pending. CRL downloads
are matched by URL and issuer within the same provider instance; OCSP downloads
also require the same target certificate and request DER. Different provider
instances do not share downloads, so separate loader, origin, or SSRF
configurations stay isolated.

Each caller can cancel independently. A cancel removes only that caller; when
the last caller cancels, the download is aborted. Sharing ends when a download
succeeds or fails, so later requests can start a new download. A shared CRL
download is evaluated separately for each certificate; a good result for one
certificate never becomes another certificate's status.

## Optional worker execution

PKI.js path, CRL, and OCSP computation runs inline by default. To move CPU-heavy
work off the main thread, create a bounded, reusable Piscina pool and pass its
engine to validators or a registry:

```typescript
import { createTrustValidator } from "x509-trust";
import { createWorkerPkiEngine } from "x509-trust/worker";

const engine = createWorkerPkiEngine({
  maxThreads: 2,
  maxQueue: 16,
  taskTimeoutMs: 5000,
});

const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  provider,
  engine,
});

// The caller owns the pool and must release it.
await engine.close({ force: true });
```

| Worker option     | Default                              | Meaning                                       |
| ----------------- | ------------------------------------ | --------------------------------------------- |
| `maxThreads`    | `min(4, availableParallelism - 1)` | Maximum worker threads.                       |
| `minThreads`    | `0`                                | Threads kept ready.                           |
| `maxQueue`      | `maxThreads * 4`                   | Tasks waiting for a worker.                   |
| `idleTimeout`   | `30000`                            | Idle worker shutdown delay.                   |
| `taskTimeoutMs` | `10000`                            | Per-task deadline.                            |
| `filename`      | Packaged worker                      | Override only when embedding the worker file. |

Only DER bytes and JSON-compatible DTOs cross the thread boundary. HTTP, request
scheduling, shared downloads, caching, diagnostics, registered rules, and
cancellation remain on the main thread. The pool is long-lived and can be shared
by validators and registry profiles.

Worker queue overflow and task timeouts return `RESOURCE_LIMIT_EXCEEDED`.
Aborting a task terminates its worker; the pool replaces it. Aborting a queued
task rejects it without terminating a running task. Inline and worker modes
produce the same success and failure results for the same inputs.

Worker execution is optional and not the default. Choose it based on
measurements for the target deployment, not as a throughput default.

## Concurrency, early rejection, and cancellation

After the path validates, leaf and intermediate revocation pipelines start
concurrently. Within each certificate, mechanisms and URLs keep the profile's
ordered, sequential fallback; there is no cross-certificate barrier.

Overall success requires every non-anchor certificate to satisfy the profile.
The validator races only an authenticated `revoked` result against completion:

- Once an authenticated revoked result is confirmed, `verify()` returns without
  waiting for stalled loaders or cache writes from other certificates.
- A slow or signal-ignoring custom loader cannot delay that confirmed failure.
- Late results cannot override the returned failure.
- Revoked cache writes run in the background with rejections observed.

Pass an `AbortSignal` to `verify()` to cancel the whole verification. Built-in
HTTP loaders combine it with their request deadline; custom loaders receive it
as `options.signal` and should honor it. External cancellation rejects with an
`AbortError`.

The library validates certificate trust and revocation. Applications remain
responsible for protocol rules such as matching a JWT issuer to a certificate
SAN, verifying JWT signatures and claims, and deciding authorization.

## Reading URI subject alternative names

`getUriSubjectAlternativeNames()` extracts URI entries from a certificate's
Subject Alternative Name extension:

```typescript
import { getUriSubjectAlternativeNames } from "x509-trust";

const uris = getUriSubjectAlternativeNames(clientCertificate);
```

It accepts PEM or DER and returns URI entries in original order without
normalization. Other name types are excluded. A missing SAN or one with no URI
entries returns `[]`; invalid certificates or malformed SAN extensions throw.
Extraction does not validate trust, revocation, or JWT claims. When using a
Node.js `X509Certificate` object, pass `certificate.raw`.

## Retrieving revocation evidence

By default, the validator downloads CRLs with HTTP GET and sends unsigned DER
OCSP requests with HTTP POST. CRL downloads may be DER or PEM. OCSP requests omit
the optional nonce; response signatures and freshness are verified before use.

Because retrieval URLs come from supplied certificates, built-in retrieval
restricts destinations to reduce SSRF exposure. Redirects and HTTP(S) URLs with
embedded credentials or fragments are rejected. Only public IPv4 and
global-unicast IPv6 destinations are permitted by default, with resolved
addresses checked when establishing each connection.

```typescript
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  http: {
    allowedOrigins: ["https://ca.example.org", "http://ocsp.example.org"],
    timeoutMs: 5000,
    maxResponseBytes: 5 * 1024 * 1024,
  },
});
```

For internal PKI or local endpoints, set `http.allowPrivateAddresses: true`,
preferably with an origin allowlist. HTTPS endpoints must also pass Node.js TLS
verification.

### Custom loaders and disabled mechanisms

Supply `loadCrl` or `loadOcsp` to retrieve evidence through another transport or
from offline storage. Callbacks return DER bytes; OCSP callbacks receive the
target certificate and issuer as DER bytes. The library still validates the
returned evidence.

```typescript
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  loadCrl: async (url) => readCrlFromStorage(url),
  loadOcsp: false,
});
```

Here, `readCrlFromStorage` is application-provided. This example permits CRL
checks only. Setting a loader to `false` disables that mechanism for the entire
validator, even when certificates advertise its URLs. Omitting a loader uses the
built-in HTTP implementation.

`http` settings apply only to built-in loaders. Custom loaders own their network
restrictions, timeouts, and size limits. `checkDate` changes the validation date
but does not retrieve historical evidence; provide suitable evidence through
custom loaders when validating at a past date.

## Diagnostics

Pass `onDiagnostic` to send revocation and cache events to an existing logger:

```typescript
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  onDiagnostic(event) {
    logger.debug(event);
  },
});
```

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
codes. `revocation_error` reports a loading or validation exception without
forwarding raw error text. Cache events distinguish reuse, misses, discarded
evidence, and storage failures.

Events include mechanism and certificate index but exclude certificate contents,
evidence bytes, cache keys, and source URLs. Callbacks run in check order;
returned promises are not awaited. Exceptions and rejections from callbacks are
ignored so diagnostics cannot change validation. Diagnostics describe evidence
attempts and cache activity, not every validation outcome.

## Caching

The default evidence cache holds up to 256 entries in memory. Reusing the
validator lets repeated requests avoid downloading the same evidence. CRLs can
be shared across certificates with the same issuer and CRL URL; OCSP entries
also identify the individual certificate.

Only evidence that establishes `good` or `revoked` status is cached. Expiry is
the earlier of `nextUpdate` and the time cached plus `maxCacheAgeMs` (one hour by
default). A cache hit does not extend expiry. Evidence cached at 10:00 with
`nextUpdate` at 12:00 expires at 11:00 under the default limit, even if used
again at 10:30.

Cached evidence is revalidated for the certificate, issuer, and validation date
on each use. Certificate paths are validated on every request. Unknown results
are not cached. Cache failures trigger fresh retrieval; expired evidence is
never used as fallback. Caching introduces a delay before newly published
revocation information is observed, so choose `maxCacheAgeMs` according to the
deployment's freshness requirements.

To change the memory limit, pass `createMemoryCache({ maxEntries: 1024 })` as
`cache`. For shared storage, adapt an existing client to `CacheStore`:

```typescript
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  cacheKeyPrefix: "app:x509-trust:revocation:v1",
  cache: {
    get: (key) => redisClient.get(key),
    async set(key, value, ttlMs) {
      await redisClient.set(key, value, { PX: ttlMs });
    },
    async delete(key) {
      await redisClient.del(key);
    },
  },
});
```

The application owns the Redis connection. Cache values are strings and TTLs
are milliseconds.

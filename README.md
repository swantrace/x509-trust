# x509-trust

Validate X.509 certificate chains and CRL/OCSP revocation status in Node.js.
Requires Node.js 24 or later and ECMAScript modules.

## Install

```sh
npm install x509-trust
```

Import the main API from `x509-trust`. Optional worker execution is available
from `x509-trust/worker`.

## Validate a certificate chain

Load your root, intermediate, and leaf certificates from application-approved
files. The paths below are examples; replace them with your own certificate
files.

```typescript
import { readFile } from "node:fs/promises";
import { createTrustValidator } from "x509-trust";

const [rootCertificate, intermediateCertificate, leafCertificate] =
  await Promise.all([
    readFile("./certificates/root.pem"),
    readFile("./certificates/intermediate.pem"),
    readFile("./certificates/leaf.pem"),
  ]);

const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
});

const result = await validator.verify({
  certificateChain: [leafCertificate, intermediateCertificate],
});

if (result.valid) {
  console.log(result.leafCertificate.fingerprint256);
} else {
  console.error(result.code, result.message);
}
```

Reuse the validator across requests. Certificates may be PEM strings, PEM byte
arrays, or DER byte arrays (`CertificateInput` is `string | Uint8Array`). Supply
the leaf first, followed by its intermediates. The root may be omitted from
`certificateChain`; only configured `trustAnchors` establish trust.

The examples below reuse these certificate variables.

### Validator options

Pass these options to `createTrustValidator()`:

| Option             | Default                                | Usage                                                                     |
| ------------------ | -------------------------------------- | ------------------------------------------------------------------------- |
| `trustAnchors`   | Required                               | Nonempty array of trusted root certificates.                              |
| `profile`        | `DEFAULT_VALIDATION_PROFILE`         | Select validation requirements.                                           |
| `rules`          | None                                   | Register named application checks.                                        |
| `crlLoader`      | HTTP retrieval                         | Supply a CRL callback, or `false` to disable CRL retrieval.             |
| `ocspLoader`     | HTTP retrieval                         | Supply an OCSP callback, or `false` to disable OCSP retrieval.          |
| `provider`       | A separate provider for this validator | Share downloads and concurrency limits across validators.                 |
| `http`           | See [HTTP options](#http-options)       | Configure built-in HTTP retrieval.                                        |
| `deadlineMs`     | `60000`                              | Limit the revocation phase, including time waiting to download.           |
| `cache`          | In-memory cache, 256 entries           | Supply a `CacheStore`.                                                  |
| `maxCacheAgeMs`  | `3600000`                            | Limit cached response age, also bounded by the response's `nextUpdate`. |
| `cacheKeyPrefix` | `"x509-trust:revocation:v1"`         | Set a namespace for shared cache storage.                                 |
| `engine`         | Default execution                      | Use an engine returned by `createWorkerPkiEngine()`.                    |
| `now`            | `Date.now`                           | Supply a clock returning Unix epoch milliseconds.                         |
| `onDiagnostic`   | None                                   | Receive revocation and cache events.                                      |

`validator.verify()` accepts:

| Option               | Required | Usage                                                        |
| -------------------- | -------- | ------------------------------------------------------------ |
| `certificateChain` | Yes      | Leaf certificate followed by intermediates.                  |
| `checkDate`        | No       | Validate at this `Date`; defaults to the configured clock. |
| `signal`           | No       | Cancel verification with an `AbortSignal`.                 |

`checkDate` does not retrieve historical revocation responses. Supply suitable
responses through custom loaders when verifying at a past date.

## Read the result

`verify()` returns a `ValidationResult`. Check `result.valid` before using
success-only fields.

| Field                             | Availability           | Meaning                                                                 |
| --------------------------------- | ---------------------- | ----------------------------------------------------------------------- |
| `valid`                         | Always                 | Whether all required checks passed.                                     |
| `certificatePath`               | Success                | Validated DER certificates, leaf first and including the selected root. |
| `trustAnchorFingerprint256`     | Success                | SHA-256 fingerprint of the selected root.                               |
| `leafCertificate`               | Success                | Validated leaf identity and public-key information.                     |
| `code`, `message`             | Failure                | Failure category and diagnostic explanation.                            |
| `certificateIndex`              | Some failures          | Zero-based certificate position in the validated path.                  |
| `evidence`                      | Success; some failures | Authenticated, current CRL/OCSP summaries that established status.      |
| `findings`                      | Success; some failures | CRL/OCSP attempt details for each certificate.                          |
| `profileId`, `profileVersion` | Success; some failures | The selected validation profile.                                        |

`leafCertificate` includes:

- `der` and `publicKeySpkiDer`: DER byte arrays for the certificate and public key.
- `fingerprint256` and `serialNumber`: certificate identifiers.
- `subject`, `issuer`, and `uriSubjectAlternativeNames`: identity information.
- `notBeforeMs` and `notAfterMs`: validity dates as Unix epoch milliseconds.
- `keyUsages`, `extendedKeyUsageOids`, and `certificatePolicyOids`: optional
  certificate-extension values.

Use `findings` to inspect what happened before a failure:

```typescript
for (const certificate of result.findings ?? []) {
  for (const attempt of [
    ...certificate.revocation.crl,
    ...certificate.revocation.ocsp,
  ]) {
    console.log({
      certificateIndex: certificate.certificateIndex,
      source: attempt.source,
      status: attempt.status,
      code: attempt.code,
      message: attempt.message,
      durationMs: attempt.durationMs,
    });
  }
}
```

Findings describe attempts that were made; they are not a complete list of all
possible sources. A revoked result may include only the revoked certificate's
findings. A deadline failure may include unfinished attempts marked
`EVIDENCE_DEADLINE_EXCEEDED`.

### Failures and thrown errors

| Failure code                  | Meaning                                                         |
| ----------------------------- | --------------------------------------------------------------- |
| `INVALID_CERTIFICATE`       | A certificate could not be parsed or has invalid metadata.      |
| `INVALID_CERTIFICATE_PATH`  | No valid path to a configured trust anchor was established.     |
| `CERTIFICATE_REVOKED`       | An authenticated response reports revocation.                   |
| `REVOCATION_STATUS_UNKNOWN` | The required revocation status could not be established.        |
| `PROFILE_REJECTED`          | A configured profile rule rejected the certificate.             |
| `UNKNOWN_PROFILE`           | The requested profile is not registered.                        |
| `UNKNOWN_PROFILE_VERSION`   | The requested version is not registered.                        |
| `RESOURCE_LIMIT_EXCEEDED`   | A revocation deadline or execution resource limit was exceeded. |

Invalid configuration throws `ProfileError` with `INVALID_PROFILE` or
`UNSUPPORTED_PROFILE`, or `TypeError` for invalid option values. Worker resource
failures can throw `ResourceLimitError`. These classes are exported from
`x509-trust`. Cancellation rejects with an error named `AbortError`.
Use error types and codes for decisions; messages provide diagnostic detail.

## Choose a validation profile

Pass a `ValidationProfileInput` as `profile`:

```typescript
import {
  createTrustValidator,
  type ValidationProfileInput,
} from "x509-trust";

const profile: ValidationProfileInput = {
  id: "app:client-certificates",
  version: "2026-01",
  versionOrder: 1,
  source: "application configuration",
  anchorSetId: "app:approved-roots",
  revocation: {
    requiredEvidence: "both",
    sourceOrder: ["ocsp", "crl"],
  },
  rules: {
    leafKeyUsage: ["digitalSignature"],
    leafExtendedKeyUsage: ["1.3.6.1.5.5.7.3.2"],
    requiredCertificatePolicyOids: ["1.2.3.4"],
    maxPathDepth: 3,
  },
};

const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  profile,
});
```

`id`, `version`, `source`, and `anchorSetId` are required. `source` may also be
`{ uri, version?, effectiveDate? }`. These source fields describe your policy's
provenance; they do not cause a profile download.

Numeric versions must be positive integers and default `versionOrder` to their
value. String versions require a positive integer `versionOrder`. Existing
validators retain their original configuration when the caller's objects change.

### Revocation requirements

| `requiredEvidence` | Requirement for each non-anchor certificate              |
| -------------------- | -------------------------------------------------------- |
| `"any"` (default)  | Either CRL or OCSP must establish a current good status. |
| `"crl"`            | CRL must establish a current good status.                |
| `"ocsp"`           | OCSP must establish a current good status.               |
| `"both"`           | Both mechanisms must establish a current good status.    |

`sourceOrder` defaults to `["ocsp", "crl"]`. It must contain each specifically
required mechanism. Any authenticated revoked response rejects verification,
including one from a mechanism that is not required by the profile.

The supported values for the remaining revocation options are `onUnknown: "reject"`, `scope: "non-anchor-chain"`, `requireNextUpdate: true`, and
`clockSkewMs: 0`. These are also their defaults.

### Certificate requirements

Set optional requirements in `profile.rules`:

| Field                             | Requirement                                                  |
| --------------------------------- | ------------------------------------------------------------ |
| `leafKeyUsage`                  | The leaf must contain every listed `KeyUsageName`.         |
| `leafExtendedKeyUsage`          | The leaf must contain every listed extended key usage OID.   |
| `requiredCertificatePolicyOids` | The leaf must contain every listed certificate policy OID.   |
| `maxPathDepth`                  | Maximum total certificates, including leaf and trust anchor. |
| `requiredRuleNames`             | Names of application rules that must pass.                   |

List requirements must be nonempty and contain no duplicates. All configured
requirements must pass. Certificate policy OID matching applies to the leaf;
it does not establish compliance with a complete RFC 5280 policy tree.

Use `compileValidationProfile(profile, { registeredRuleNames })` to validate a
profile before creating a validator. It returns a normalized, read-only
`CompiledValidationProfile`. Omitting the profile selects
`DEFAULT_VALIDATION_PROFILE`; omit `registeredRuleNames` when no named rules
are required.

## Register multiple profiles

Use `createValidationProfileRegistry()` when the application selects between
approved profiles or anchor sets:

```typescript
import { createValidationProfileRegistry } from "x509-trust";

const registry = createValidationProfileRegistry();

registry.register({
  profile,
  trustAnchors: [rootCertificate],
});

registry.register({
  profile: { ...profile, version: "2026-06", versionOrder: 2 },
  trustAnchors: [rootCertificate],
});

const result = await registry.verify({
  profileId: profile.id,
  profileVersion: "2026-01",
  certificateChain: [leafCertificate, intermediateCertificate],
});
```

Omit `profileVersion` to select the highest registered `versionOrder`. Duplicate
versions or duplicate ordering values within a profile are rejected. Choose
`profileId` from application-approved context.

`register()` accepts `{ profile, trustAnchors, rules? }`. `verify()` accepts
`{ profileId, profileVersion?, certificateChain, checkDate? }`.

Registry construction accepts the validator's loader, provider, HTTP, deadline,
cache, clock, diagnostics, and engine options. Configure anchors, profiles, and
named rules separately for each registration.

## Add application rules

Register a named callback and include its name in `profile.rules.requiredRuleNames`:

```typescript
import {
  createTrustValidator,
  type TrustRuleRegistration,
} from "x509-trust";

const rules: TrustRuleRegistration[] = [{
  name: "approved-client-uri",
  check({ leaf }) {
    return leaf.uriSubjectAlternativeNames.includes("https://client.example.org/app")
      ? { ok: true }
      : { ok: false, message: "The client URI is not approved" };
  },
}];

const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  profile: {
    ...profile,
    rules: { ...profile.rules, requiredRuleNames: ["approved-client-uri"] },
  },
  rules,
});
```

Callbacks receive a `TrustRuleContext` containing `profileId`, `profile`, `leaf`,
and `certificatePath`. Return `{ ok: true }` or `{ ok: false, message }`, directly
or through a promise. Exceptions and unrecognized results produce
`PROFILE_REJECTED`.
Rules run after certificate and required revocation checks pass.

## Supply CRL and OCSP responses

Use custom loaders for responses obtained from application storage or another
service. Both callbacks receive one request object and return DER bytes:

```typescript
import { readFile } from "node:fs/promises";
import { createTrustValidator } from "x509-trust";

const crlFiles = new Map([
  ["https://ca.example.org/intermediate.crl", "./responses/intermediate.crl.der"],
  ["https://ca.example.org/root.crl", "./responses/root.crl.der"],
]);

const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  profile: {
    ...profile,
    revocation: { requiredEvidence: "crl", sourceOrder: ["crl"] },
  },
  crlLoader({ url, signal }) {
    const file = crlFiles.get(url);
    if (!file) throw new Error(`No local CRL configured for ${url}`);
    return readFile(file, { signal });
  },
  ocspLoader: false,
});
```

Replace the example URLs with those advertised by your certificates, and supply
a CRL for each checked certificate's issuer. Callbacks can select responses by
`url` and `issuerCertificate`. Returned bytes still undergo signature, issuer,
and freshness validation.

```typescript
interface CrlRequest {
  url: string;
  issuerCertificate: Uint8Array;
  signal?: AbortSignal;
}

interface OcspRequest extends CrlRequest {
  certificate: Uint8Array;
  requestDer: Uint8Array;
}
```

Certificate fields and the OCSP `requestDer` contain DER bytes. For OCSP, return
the response to that request. Custom loaders should honor `signal`.

Omitting a loader uses HTTP retrieval. Setting it to `false` disables the
mechanism. A disabled mechanism cannot satisfy a profile that requires it.

### HTTP options

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

| Option                    | Default                     | Usage                                                            |
| ------------------------- | --------------------------- | ---------------------------------------------------------------- |
| `timeoutMs`             | `5000`                    | Limit each request, including its response body.                 |
| `maxResponseBytes`      | `5242880`                 | Limit response size in bytes.                                    |
| `allowedOrigins`        | Unrestricted public origins | Allow retrieval only from listed origins.                        |
| `allowPrivateAddresses` | `false`                   | Permit private or loopback destinations when explicitly enabled. |

Built-in retrieval uses GET for CRLs and POST for OCSP. It rejects redirects,
credentials or fragments in URLs, and private destinations by default. For
internal PKI, enable `allowPrivateAddresses` with an appropriate origin list.
HTTP options apply only to built-in loaders; custom loaders control their own
transport restrictions, request deadlines, and response sizes.

## Share downloads between validators

Create one `RevocationProvider` and pass it to each validator or registry:

```typescript
import { createRevocationProvider, createTrustValidator } from "x509-trust";

const provider = createRevocationProvider({ maxActiveRequests: 8 });

const validatorA = createTrustValidator({
  trustAnchors: [rootCertificate],
  provider,
});
const validatorB = createTrustValidator({
  trustAnchors: [rootCertificate],
  provider,
});

console.log(provider.stats()); // { active, queued }
```

`maxActiveRequests` defaults to `DEFAULT_MAX_ACTIVE_REQUESTS` (`8`). Providers
also accept `crlLoader`, `ocspLoader`, and `http`. Configure loaders on the
provider when sharing it; a validator cannot combine `provider` with loader
callbacks.

Matching requests through the same provider share a pending download. Each
validator still returns its own verification result. Cancelling one caller does
not cancel a download another caller still needs.

For direct retrieval, call `provider.loadCrl(options)` or
`provider.loadOcsp(options)` with the request objects above. Check that the method
exists first: a disabled mechanism has no loading method. These methods return
response bytes; use `verify()` to establish certificate trust.

Standalone provider calls have no verification deadline. Pass `options.signal`
when their waiting time must be bounded.

## Configure caching

```typescript
import { createMemoryCache, createTrustValidator } from "x509-trust";

const cache = createMemoryCache({ maxEntries: 1024 });
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  cache,
  maxCacheAgeMs: 30 * 60 * 1000,
});
```

`createMemoryCache()` defaults to 256 entries. Its optional `now` clock returns
Unix epoch milliseconds. Reuse a cache object to share storage across
validators. Cached responses remain subject to certificate, issuer, and date
checks; their lifetime cannot exceed `nextUpdate` or `maxCacheAgeMs`.

To use another storage service, pass a `CacheStore` with this contract:

```typescript
interface CacheStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlMs: number): Promise<void>;
  delete(key: string): Promise<void>;
}
```

Treat keys and values as opaque strings. Return `null` for a missing or expired
entry, and honor the millisecond TTL supplied to `set()`.

## Cancel verification

```typescript
const controller = new AbortController();

const pending = validator.verify({
  certificateChain: [leafCertificate, intermediateCertificate],
  signal: controller.signal,
});

// Call this when the application no longer needs the result.
controller.abort();

try {
  await pending;
} catch (error) {
  if (!(error instanceof Error) || error.name !== "AbortError") throw error;
}
```

Use a separate controller for independent requests, or one shared signal to
cancel related requests together. `deadlineMs` returns a
`RESOURCE_LIMIT_EXCEEDED` failure when the revocation phase exceeds its limit;
caller cancellation rejects the promise.

## Read URI subject alternative names

```typescript
import { getUriSubjectAlternativeNames } from "x509-trust";

const uris = getUriSubjectAlternativeNames(leafCertificate);
```

This function accepts PEM, DER, or a parsed PKI.js `Certificate`. It returns URI
SAN strings in certificate order, or `[]` when no URI SAN is present. It throws
for invalid certificates or malformed SAN extensions. Extraction alone does not
establish certificate trust.

## Use optional worker execution

Install the optional peer dependency:

```sh
npm install piscina
```

```typescript
import { createTrustValidator } from "x509-trust";
import { createWorkerPkiEngine } from "x509-trust/worker";

const engine = createWorkerPkiEngine({
  maxThreads: 2,
  maxQueue: 16,
  taskTimeoutMs: 5000,
});

try {
  const validator = createTrustValidator({
    trustAnchors: [rootCertificate],
    engine,
  });
  const result = await validator.verify({
    certificateChain: [leafCertificate, intermediateCertificate],
  });
  console.log(result);
} finally {
  await engine.close();
}
```

The same engine can be supplied to multiple validators or a registry. Close it
when the application no longer needs it.

| Option            | Default                         | Usage                                                     |
| ----------------- | ------------------------------- | --------------------------------------------------------- |
| `maxThreads`    | Automatically selected, up to 4 | Limit worker threads.                                     |
| `minThreads`    | `0`                           | Keep this many threads ready.                             |
| `maxQueue`      | `maxThreads * 4`              | Limit tasks waiting for execution.                        |
| `idleTimeout`   | `30000`                       | Idle worker timeout in milliseconds.                      |
| `taskTimeoutMs` | `10000`                       | Per-task timeout in milliseconds.                         |
| `filename`      | Packaged worker                 | Supply a worker path or URL when packaging it separately. |

`engine.stats()` returns `threads`, `idleThreads`, `queueSize`, and `completed`.
Use `engine.close()` for shutdown, `engine.close({ force: true })` to abort queued
tasks while shutting down, or `engine.destroy()` to stop immediately.

## Receive diagnostics

```typescript
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  onDiagnostic(event) {
    console.log(event.event, event.mechanism, event.certificateIndex, event.code);
  },
});
```

A `DiagnosticEvent` contains `event`, `mechanism`, `message`, and optional
`certificateIndex`, `code`, and `status`. Events are `cache_hit`, `cache_miss`,
`cache_discarded`, `cache_error`, `revocation_result`, and `revocation_error`.
The callback may return a promise; callback failures do not change verification
results. Use `result.findings` for source URLs and attempt durations.

## Supported use

Provide the complete intermediate chain and explicitly approved trust anchors.
Missing issuer certificates are not downloaded, and system trust roots are not
selected automatically. Revocation is checked for the leaf and intermediates;
the configured trust anchor is excluded.

Use complete CRLs signed directly by the issuer, or OCSP responses signed
directly by the issuer. Both require `nextUpdate`. Delegated OCSP responders,
delta CRLs, and scoped or indirect CRLs are unsupported.

A successful result establishes certificate trust and the configured revocation
and profile requirements. Applications perform any additional JWT signature,
claim, identity-matching, or authorization checks required by their protocol.

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
The package also exports `createTrustValidator()`, `createMemoryCache()`,
`getUriSubjectAlternativeNames()`, `compileTrustPolicy()`, `PolicyError`, and
the policy/capability types.

```typescript
type CertificateInput = string | Uint8Array;

interface TrustValidatorOptions {
  trustAnchors: readonly CertificateInput[];
  loadCrl?: ((url: string) => Promise<Uint8Array>) | false;
  loadOcsp?: ((options: OcspLoadOptions) => Promise<Uint8Array>) | false;
  http?: HttpOptions;
  cache?: CacheStore;
  maxCacheAgeMs?: number;
  cacheKeyPrefix?: string;
  now?: () => number;
  onDiagnostic?: DiagnosticCallback;
}

interface OcspLoadOptions {
  url: string;
  certificate: Uint8Array;
  issuerCertificate: Uint8Array;
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
| `createMemoryCache().maxEntries` | `256`                        | Maximum entries; the oldest inserted entry is evicted when full.                       |
| `createMemoryCache().now`        | `Date.now`                   | Clock used to expire entries in that memory store.                                     |

### Results and failure codes

```typescript
type ValidationFailureCode =
  | "INVALID_CERTIFICATE"
  | "INVALID_CERTIFICATE_PATH"
  | "CERTIFICATE_REVOKED"
  | "REVOCATION_STATUS_UNKNOWN";

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

Revocation failures include `certificateIndex`, the zero-based position in the
validated path (`0` is the leaf). Use `code` for application decisions and
`message` for diagnostic detail. Invalid validator configuration and invalid
`checkDate` values throw errors.

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

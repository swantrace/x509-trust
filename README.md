# x509-trust

Validate X.509 certificate chains and certificate revocation status in Node.js.
Requires Node.js 24 or later.

This exploration branch uses a Rust addon for URI SAN and revocation endpoint
extraction, CRL and OCSP validation (`x509-parser`, with `ring`) and certificate
path validation (`rustls-webpki`, with the `ring` backend). OCSP DER requests and
responses use `x509-ocsp` for encoding and decoding; the addon checks responder
identity, CertID, freshness, extensions and signatures. Path and revocation
validation and OCSP request encoding run on the Node.js worker pool; inputs are
copied before dispatch. Internal revocation interfaces carry DER bytes. HTTP,
cache management and orchestration remain in TypeScript. PKI.js and ASN1.js are
used only by tests, with no JavaScript runtime dependencies.

PEM/DER certificate decoding and trust-anchor SHA-256 fingerprints also run in
Rust. Certificate normalization returns a validated DER snapshot and rejects
trailing DER bytes. TypeScript reuses the generated native declarations for
revocation statuses, error codes and native function signatures; its API types
still describe JavaScript dates, callbacks and validation orchestration.

Building from source requires stable Rust (Cargo and a platform linker) in
addition to Node.js. Run `npm ci` to install dependencies and build both the
native addon and TypeScript. Use `npm test` for the test suite and `npm run build`
to rebuild both. `npm run prepack` builds an optimized native addon for packaging.
Packages currently contain a binary for the build host only; cross-platform
prebuilt distribution is not configured yet.

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
The package also exports `createTrustValidator()`, `createMemoryCache()`, and
`getUriSubjectAlternativeNames()`.

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

type ValidationResult =
  | {
      valid: true;
      certificatePath: Uint8Array[];
      trustAnchorFingerprint256: string;
      leafUriSubjectAlternativeNames: string[];
    }
  | {
      valid: false;
      code: ValidationFailureCode;
      message: string;
      certificateIndex?: number;
    };
```

On success, `certificatePath` contains the validated path as DER bytes, leaf
first and including the selected trust anchor. `trustAnchorFingerprint256` is
that anchor's SHA-256 fingerprint. These fields let applications inspect the
selected path or record which anchor established trust.

`leafUriSubjectAlternativeNames` contains the leaf certificate's URI SAN entries,
in their original order and without normalization. It is empty when the leaf has
no URI SANs. Applications can use these values for protocol-specific issuer
matching without parsing the certificate again. This field is returned only
after path and revocation validation succeed; the library does not perform JWT
issuer matching.

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

## Validation policy and supported PKI

The validator first builds and validates a path to a configured trust anchor,
then checks revocation for the leaf and every intermediate. The configured
anchor itself is not checked for revocation; applications control trust in it
by adding or removing it from `trustAnchors` when creating a validator.

Path validation uses only the configured anchors, not system or browser root
stores. It checks certificate validity at millisecond precision, including the
selected anchor, and requires each issuer and anchor to be a CA with
`keyCertSign` when Key Usage is present. The returned path includes the original
DER of that configured anchor. No hostname check or TLS-specific EKU requirement
is imposed; applications must enforce their intended certificate purpose.

This backend supports X.509 v3 end-entity and intermediate certificates and the
signature algorithms enabled by `rustls-webpki`'s `ring` backend: RSA PKCS#1 v1.5
and RSA-PSS with supported RSA keys and SHA-256/384/512, ECDSA P-256/P-384 with
supported SHA-256/384 combinations, and Ed25519. Unsupported algorithms, such as
P-521 or SHA-1 certificate signatures, fail path validation. Root certificates
are explicitly trusted inputs; their self-signatures do not establish trust.

Full certificate-policy-tree processing is not implemented. Paths containing
`policyMappings`, `policyConstraints`, or `inhibitAnyPolicy` are rejected even
when those extensions are noncritical. Unsupported critical extensions,
unsupported name constraints, and dates before the Unix epoch also fail path
validation. This is a restricted validation profile, not a full RFC 5280 policy
engine or a promise of identical acceptance behavior to PKI.js.

For each certificate, sources advertised in its OCSP AIA and CRL Distribution
Points extensions are tried in this order:

1. Try OCSP addresses first.
2. If an attempt fails or cannot establish status, try the next source,
   continuing with CRL addresses after OCSP addresses.
3. The first authenticated, current `good` or `revoked` result ends the search
   for that certificate. `revoked` fails validation immediately; `good` allows
   validation to continue with the next certificate in the path.
4. If no source establishes status, return `REVOCATION_STATUS_UNKNOWN`.

OCSP-first is this library's policy, not a UDAP requirement. It queries status
for the individual certificate before falling back to downloading a CRL.
Sources are alternatives: the validator does not query all of them or reconcile
conflicting results after obtaining a usable answer.

This is a fail-closed policy: unavailable endpoints, missing endpoints, disabled
mechanisms, invalid signatures, expired evidence, or unsupported evidence never
count as proof that a certificate is not revoked. Another usable source may
still establish status. Disabling both CRL and OCSP does not bypass revocation
validation for non-anchor certificates.

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

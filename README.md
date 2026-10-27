# @sahara/x509-trust

A Node.js package for X.509 certificate chain and revocation validation using PKI.js.

Requires Node.js 24 or later. Create a validator once and reuse it across requests:

```typescript
import { createTrustValidator } from "@sahara/x509-trust";

const validator = createTrustValidator({
  trustAnchors: [rootCertificate]
});

const result = await validator.verify({
  certificateChain: [clientCertificate, intermediateCertificate]
});

if (result.valid) {
  console.log(result.trustAnchorFingerprint256);
} else {
  console.error(result.code, result.message);
}
```

Each input certificate is a PEM string or DER byte array. `certificateChain`
must be leaf-first; the root can be omitted. Configured trust anchors are copied
when the validator is created. Including a root in a request does not establish
trust. Consumers do not need to construct PKI.js objects.

The validator builds and validates the certificate path, then checks revocation
for the leaf and every intermediate. The configured trust anchor itself is not
checked for revocation. OCSP addresses are tried first, followed by CRL addresses
when OCSP is unavailable or inconclusive. A verified revoked status stops
validation immediately; a fallback cannot override it.

By default the validator downloads CRLs with HTTP GET and sends DER OCSP requests
with HTTP POST to the certificate's advertised addresses. CRL downloads may be
DER or PEM. OCSP requests identify the target certificate and issuer, are
unsigned, and omit the optional nonce; response signatures and freshness are
verified before use.

Configure the built-in transport with `http`:

```typescript
const validator = createTrustValidator({
  trustAnchors: [rootCertificate],
  http: {
    timeoutMs: 5000,
    maxResponseBytes: 5 * 1024 * 1024,
    allowedOrigins: ["https://ca.example.org", "http://ocsp.example.org"]
  }
});
```

The defaults are a five-second deadline for each request, including its body,
and a five-MiB response limit. Redirects are rejected. HTTP(S) URLs with embedded
credentials or fragments are rejected. Only public IPv4 and global-unicast IPv6
destinations are permitted by default, with DNS addresses checked as part of
establishing each connection. `allowedOrigins` can further restrict destinations.
For local tests or private CA infrastructure, explicitly set
`http.allowPrivateAddresses: true`, preferably with an origin allowlist.

Custom `loadCrl` and `loadOcsp` callbacks remain optional overrides. Set either
option to `false` to disable that mechanism; disabling both still fails
revocation validation. Override callbacks return DER bytes and have these
signatures:

```typescript
type LoadCrl = (url: string) => Promise<Uint8Array>;

type LoadOcsp = (request: {
  url: string;
  certificate: Uint8Array;
  issuerCertificate: Uint8Array;
}) => Promise<Uint8Array>;
```

These callback signatures describe application-provided implementations, not
functions exported by this package. The `http` settings apply only to built-in
loaders; overrides own their network controls and limits. Missing endpoints,
disabled loaders, loading failures, or unusable evidence result in
`REVOCATION_STATUS_UNKNOWN` unless another source succeeds.

Successful results contain `valid: true`, a leaf-first DER `certificatePath`
including the selected anchor, and `trustAnchorFingerprint256`. Failures contain
`valid: false`, `code`, and `message`. Revocation failures also include a
zero-based `certificateIndex`, where `0` is the leaf.

| Failure code | Meaning |
| --- | --- |
| `INVALID_CERTIFICATE` | A request certificate could not be parsed. |
| `INVALID_CERTIFICATE_PATH` | No valid path to a configured anchor was found, including signature or date failures. |
| `CERTIFICATE_REVOKED` | An authenticated source reports that a path certificate is revoked. |
| `REVOCATION_STATUS_UNKNOWN` | Revocation status could not be established for a path certificate. |

Invalid validator configuration and invalid `checkDate` values throw errors.
Pass `checkDate` to `verify()` for historical or offline checks; normal requests
use the current time. Currently supported evidence is direct, complete CRLs and
OCSP responses signed directly by the issuer. Delegated responders, delta and
scoped CRLs are not supported. Although OCSP permits omitting `nextUpdate`, this
verifier currently requires it to bound freshness.

The default cache is an in-memory store limited to 256 entries. Verified DER data
is cached until the earlier of `nextUpdate` or `maxCacheAgeMs` (one hour by
default). Each cache hit is revalidated for the requested certificate, issuer,
and date. Unknown results are not cached. CRLs can be shared across certificates
from the same issuer; OCSP entries are specific to a certificate and issuer.

`CacheStore` and `createMemoryCache()` are exported for custom storage. A store
implements async `get(key)`, `set(key, value, ttlMs)`, and `delete(key)`. Values
are strings and expiration is in milliseconds, so a connected Redis client can
be adapted without adding Redis as a dependency of this package:

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

The application owns the Redis connection. Cache failures cause fresh loading
and validation; expired data is never used as a fallback. Configure
`maxCacheAgeMs` and `cacheKeyPrefix` on `createTrustValidator()` as needed.
Certificate paths are validated again for every request, including cache hits.

```sh
npm ci
npm run typecheck
npm run build
npm test
```

Source files live in `src/`. The build produces JavaScript and TypeScript declaration files in `dist/`.

Install the recommended Biome extension in VS Code to format code and organize
imports on save. Run `npm run format` to apply both actions from the terminal,
or `npm run format:check` to check them without changing files. Formatting uses
two spaces, double quotes, semicolons, and no trailing commas.

`npm ci` also installs the Husky pre-commit hook. Before each commit,
lint-staged formats staged JavaScript, TypeScript, and JSON files and organizes
their imports, then adds the changes to the commit.

GitHub Actions checks formatting, types, tests, builds, and package contents on
pull requests targeting `main` and pushes to `main`.

Tests use committed certificates and a fixed validation time derived from the
fixtures, so running tests does not require certificate generation. To regenerate
the fixtures with OpenSSL, run `bash test/fixtures/generate.sh`. Private keys are
temporary and are deleted when the script exits.

HTTP tests start temporary Node.js servers on random loopback ports and close
them automatically. They exercise downloads, OCSP requests, fallback, caching,
deadlines, size limits, and destination restrictions without external services.

Revocation fixtures are documented in [test/fixtures/README.md](test/fixtures/README.md).

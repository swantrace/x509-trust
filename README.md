# @sahara/x509-trust

A Node.js package for X.509 certificate chain and revocation validation using PKI.js.

The internal `validateCertificatePath()` function validates certificate paths,
signatures, and validity dates using PKI.js. The package entry point does not
export a public validation API yet.

The internal `getRevocationEndpoints()` function accepts a parsed PKI.js
certificate and extracts CRL distribution point URIs and OCSP responder URIs.
Missing extensions produce empty arrays; malformed extensions throw an error.
The function preserves multiple addresses and does not fetch or validate URLs.

The internal `validateCrl()` function checks a DER-encoded, direct, complete CRL
against a certificate and its issuer from a validated path. It verifies the CRL
issuer, signing permission, signature, validity interval, and revocation records,
returning `good`, `revoked`, or `unknown`. Missing `nextUpdate`, unsupported CRL
scope or delta extensions, and unusable CRLs produce `unknown`. It does not fetch
or cache CRLs.

The internal `validateOcsp()` function validates DER OCSP responses signed
directly by the issuer from a validated certificate path. It matches the full
certificate identifier, verifies the response signature, and checks `producedAt`,
`thisUpdate`, and `nextUpdate`, returning `good`, `revoked`, or `unknown`.
Delegated responders are not supported yet. Although OCSP permits responses
without `nextUpdate`, this verifier currently requires it to bound freshness.
It does not fetch or cache responses.

The internal `createRevocationChecker()` wraps both validators with caching.
Its `checkCrl()` and `checkOcsp()` methods take `certificate`, `issuerCertificate`,
`source`, and an async `load()` callback returning DER bytes. `source` identifies
the URL or other origin of the data. Network fetching will be added separately.

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
const checker = createRevocationChecker({
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

The checker is currently internal; the public certificate validator will accept
the same storage interface. The application owns the Redis connection. Cache
failures cause fresh loading and validation, while loader errors propagate;
expired cached data is never used as a fallback.

Requires Node.js 24 or later.

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

Revocation fixtures are documented in [test/fixtures/README.md](test/fixtures/README.md).

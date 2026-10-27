# @sahara/x509-trust

A Node.js package for X.509 certificate chain and revocation validation using PKI.js.

The internal `validateCertificatePath()` function validates certificate paths,
signatures, and validity dates using PKI.js. The package entry point does not
export a public validation API yet; CRL/OCSP checks are not implemented.

The internal `getRevocationEndpoints()` function accepts a parsed PKI.js
certificate and extracts CRL distribution point URIs and OCSP responder URIs.
Missing extensions produce empty arrays; malformed extensions throw an error.
The function preserves multiple addresses and does not fetch or validate URLs.

Requires Node.js 24 or later.

```sh
npm ci
npm run typecheck
npm run build
npm test
```

Source files live in `src/`. The build produces JavaScript and TypeScript declaration files in `dist/`.

Tests use committed certificates and a fixed validation time derived from the
fixtures, so running tests does not require certificate generation. To regenerate
the fixtures with OpenSSL, run `bash test/fixtures/generate.sh`. Private keys are
temporary and are deleted when the script exits.

Revocation fixtures are documented in [test/fixtures/README.md](test/fixtures/README.md).

# @sahara/x509-trust

A Node.js package for X.509 certificate chain and revocation validation using PKI.js.

The internal `validateCertificatePath()` function validates certificate paths,
signatures, and validity dates using PKI.js. The package entry point does not
export a public validation API yet; CRL/OCSP checks are not implemented.

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

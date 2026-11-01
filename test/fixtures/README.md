# Certificate and revocation fixtures

[Back to README](../../README.md)

Run `bash test/fixtures/generate.sh` from the repository root to regenerate all
fixtures together. This requires OpenSSL 3.0 or later and replaces existing
fixtures. Tests use the committed files without generating keys or starting
external services.

| File | Purpose |
| --- | --- |
| `root.pem` | Trust anchor; signs the intermediate certificate. |
| `intermediate.pem` | Signs both client certificates. |
| `leaf.pem` | Client certificate that remains valid. |
| `revoked-leaf.pem` | Client certificate revoked for key compromise. |
| `untrusted-root.pem` | Unrelated root for untrusted-path tests. |
| `crl/root.crl.pem` | Confirms that the intermediate is not revoked. |
| `crl/intermediate-clean.crl.pem` | Issued before revoking the client; lists no revoked certificates. |
| `crl/intermediate-revoked.crl.pem` | Lists `revoked-leaf.pem`; does not list `leaf.pem`. |
| `crl/intermediate-expired.crl.pem` | Signed CRL whose `nextUpdate` is in the past. |
| `ocsp/good.der` | Signed `good` response for `leaf.pem`. |
| `ocsp/revoked.der` | Signed `revoked` response for `revoked-leaf.pem`. |
| `ocsp/unknown.der` | Signed `unknown` response for `leaf.pem`, using an empty CA index. |
| `ocsp/intermediate-good.der` | Signed `good` response for `intermediate.pem`. |
| `validation-time.txt` | UTC time captured after generating the revocation fixtures. |

Each OCSP response is signed directly by the certificate's issuing CA and omits
the nonce. CRLs and OCSP responses normally have a 30-day lifetime; revocation
tests should use `validation-time.txt` as their check date to remain independent
of the current date. The expired CRL has a fixed validity period in January 2020.
`intermediate-clean.crl.pem` represents the state before revocation; the later
revocation must not be inferred from that earlier CRL.

The intermediate advertises `http://crl.example.test/root.crl` and
`http://ocsp.example.test/root`. Client certificates advertise
`http://crl.example.test/intermediate.crl` and
`http://ocsp.example.test/intermediate`. These are test addresses for a mocked
transport, not running public services. The intermediate CRL endpoint can return
different fixtures to test freshness and cache updates.

CA databases, requests, and private keys exist only in a temporary directory and
are deleted when generation finishes. These fixtures prepare for revocation
tests. Local CRL and direct-issuer OCSP validation use these files.

# Validation capabilities

[Back to README](../README.md)

This library uses PKI.js for X.509 path and revocation computation and adds a
small set of fail-closed guards. A capability listed as *verified* has an
in-repository test; parsing a structure is not treated as supporting its full
semantics.

## Certificate path

| Capability | Status | Notes |
| --- | --- | --- |
| DER/PEM certificate parsing | Verified | Exactly one DER value per input; caller buffers are copied. |
| Chain building to configured anchors | Verified | Leaf-first input; the anchor may be omitted from the chain. |
| Signature and name chaining | Verified | PKI.js `CertificateChainValidationEngine`. |
| Validity periods, including the trust anchor | Verified | Checked at the supplied validation time. |
| CA `basicConstraints` and `keyUsage.keyCertSign` | Verified | Checked for every non-leaf path certificate. |
| `pathLenConstraint` | Verified | Enforced by this library because PKI.js does not enforce it. |
| Name constraints | Verified by PKI.js | Permitted/excluded subtree processing. |
| Duplicate extensions | Rejected | A certificate has at most one extension of each OID. |
| Unsupported critical extensions | Rejected | Only extensions whose semantics are handled are accepted as critical. |
| Exact DER with no trailing bytes | Verified | Trailing data is rejected instead of silently ignored. |
| Bounded chain/anchor counts and DER size | Verified | Prevents unbounded parsing work. |
| Full RFC 5280 policy tree | Not claimed | PKI.js performs partial policy processing; this library only reads leaf policy OIDs for explicit policy rules. |

## Revocation checks

| Revocation data | Status | Notes |
| --- | --- | --- |
| Complete CRL signed directly by the issuer | Verified | `nextUpdate` required; unsupported CRL extensions rejected. |
| OCSP BasicResponse signed directly by the issuer | Verified | Responder is pinned to the validated issuer; embedded certificates grant no trust. |
| Delegated OCSP responders | Not supported | Not claimed without independent authorization tests. |
| Delta or indirect CRLs | Not supported | Rejected as unsupported revocation data. |
| OCSP responses without `nextUpdate` | Not accepted | Treated as unknown so another source may be tried. |
| Cached revocation data | Verified | Raw DER is cached and reauthenticated for the current certificate, issuer, time and profile. |

## Deliberately outside this library

JWT/OAuth/FHIR business validation, issuer/SAN matching, AIA certificate
download, TLS hostname verification for the revocation data endpoints, automatic
trust of system roots, and external framework profiles (for example Carequality
or TEFCA) presets. A successful result means certificate trust and configured
revocation checks only.

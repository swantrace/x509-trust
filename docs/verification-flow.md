# Verification flow

The public entry point is `createTrustValidator(options).verify(input)`.
All native calls pass through [src/native.ts](../src/native.ts). Normal cold
and cached verification each make **two Rust API calls**, regardless of the
number of certificates or configured trust anchors.

## Initialization and API behavior

Construction copies trust-anchor input bytes in TypeScript and configures loaders,
cache storage and diagnostics. It makes **zero native API calls**. Certificate
syntax and trust are checked by the path worker during `verify`. Malformed
anchors return `INVALID_CERTIFICATE` from verification before any loader runs;
empty anchor lists and invalid runtime options still throw during construction.

Certificate loaders can now run concurrently for different certificates. Within
one certificate, OCSP URLs remain ordered before CRL URLs and only one source is
attempted at a time. A loader must support concurrent invocations. Initial loads
for intermediates may already have happened when a revoked leaf is discovered.

`OcspLoadOptions.request?: Uint8Array` carries an unsigned, nonce-free request
prepared in Rust. Custom loaders may send it directly or ignore it. The built-in
OCSP loader requires these prepared bytes; it no longer enters Rust to build a
request. Missing request bytes fail that source and allow CRL fallback.

## Two-phase verification

```mermaid
sequenceDiagram
    participant TS as TypeScript
    participant RS as Rust worker
    TS->>RS: validateCertificatePath(inputs, anchors, date)
    Note over RS: Decode PEM/DER, validate path,<br/>extract SAN/URLs, encode OCSP requests
    RS-->>TS: Ordered DER path, fingerprint, SAN, targets and requests
    Note over TS: After trust succeeds, read caches/load current sources concurrently
    TS->>RS: validateEvidence(path, evidence for all ready certificates)
    RS-->>TS: Indexed CRL/OCSP statuses and freshness bounds
    Note over TS: Store authenticated evidence, finish good certificates
    opt Unknown cached evidence or another source needed
        Note over TS: Discard/reload or advance that certificate's source
        TS->>RS: validateEvidence(remaining evidence)
        RS-->>TS: Remaining indexed results
    end
    Note over TS: Any authenticated revoked fails;<br/>success requires good status for every non-anchor certificate
```

1. `certificates.ts` converts string input to UTF-8 bytes without native parsing.
   The first worker call snapshots every input, decodes and checks all candidates
   (including unused ones), builds the trusted path and validates its constraints.
2. Before returning, that same worker extracts the leaf URI SANs, all non-anchor
   OCSP/CRL URLs and one OCSP request per advertised OCSP target. Request encoding
   failure leaves the request absent so CRL or custom-loader fallback remains
   possible. There are no separate metadata or request-building calls in `verify`.
3. TypeScript starts one source pipeline per non-anchor certificate. Each pipeline
   checks its raw-evidence cache before invoking its loader. Cache entries never
   establish trust on their own and are always authenticated again.
4. `revocation-batch.ts` waits until every unresolved certificate either has
   evidence ready or has finished without evidence. This barrier batches actual
   I/O completions, even when requests finish in different event-loop turns.
   It does not use a delay or timing heuristic.
5. One `validateEvidence` worker call checks all ready CRL/OCSP evidence. Each
   item identifies its certificate index and mechanism. Rust snapshots path and
   evidence bytes before dispatch; results retain the same identity.
6. Successful timestamps become JavaScript `Date` objects. Fresh authenticated
   `good`/`revoked` evidence is cached with a TTL bounded by `nextUpdate` and
   `maxCacheAgeMs`. Valid cache hits return without extending their lifetime.
7. An unknown cached result discards that entry and reloads the same source.
   An unknown fresh result advances that certificate to its next source.
   Finished certificates leave the barrier; only unresolved certificates
   participate in later batches. Transport failures can advance a pipeline
   before any evidence batch is needed.
8. Any authenticated `revoked` result prevents further source attempts and takes
   precedence over unknown results in the same batch. Otherwise all non-anchor
   certificates must establish `good`; exhaustion fails closed. The trust anchor
   itself is not queried for revocation.

Without an explicit `checkDate`, the batch reads the clock after **all** its I/O
has completed. Evidence that expires while waiting for another source is rejected.
An explicit date is snapshotted for each queued item.

## Native call counts

| Scenario | Rust API calls per `verify` |
| --- | --- |
| First OCSP sources return good, cache cold | 2 |
| Valid cache hits for all first sources | 2 |
| CRL-only cold or cached success | 2 |
| Transport failure followed by usable evidence before the first batch | 2 |
| Unknown OCSP requiring a later CRL validation batch | 3 or more |
| Invalid cached evidence requiring another validation batch | 3 or more |
| Path rejected before evidence retrieval | 1 |

Calls are native API invocations with their returned results; worker-internal
`compute`/`resolve` and Rust-to-Rust helper calls are not counted separately.
The count is measured by wrapping the real addon exports in
[test/native-roundtrips.test.ts](../test/native-roundtrips.test.ts).

## Modules

| Module | Responsibility |
| --- | --- |
| `trust-validator.ts` | Initialization, parallel certificate pipelines and final result. |
| `certificates.ts` | Input bytes, prepared-path adapter and standalone certificate helpers. |
| `certificate-revocation.ts` | Per-certificate source order and fallback. |
| `revocation-checker.ts` | Per-source cache/load lifecycle; a batch validator is supplied by `verify`. |
| `revocation-batch.ts` | Readiness barrier, one native call per evidence round, and identity checks. |
| `revocation-validation.ts` | Result adapters and standalone low-level validation. |
| `cache.ts` | Raw evidence storage, TTL and eviction. |
| `http-loaders.ts` / `http-policy.ts` | HTTP transport and destination restrictions. |
| `native.ts` | Typed addon binding and synchronous error translation. |
| `validation-types.ts` / `diagnostics.ts` | Public contracts and callback isolation. |
| `index.ts` | Public exports. |

Standalone URI extraction uses one synchronous `getUriSubjectAlternativeNames`
call for PEM or DER. Low-level certificate/CRL/OCSP helpers remain available for
focused use and tests; they are not extra stages of the batched `verify` path.
Worker computation runs in libuv's pool, and its Promise completes on the
JavaScript thread. HTTP, cache I/O and user callbacks stay in TypeScript.

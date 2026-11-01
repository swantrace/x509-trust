// Loads and authenticates one revocation source, reusing cached bytes when valid.
import type {
  DiagnosticReporter,
  SourceDiagnosticReporter
} from "../diagnostics.ts";
import type { CrlValidationResult } from "../engine/crl.ts";
import type { OcspValidationResult } from "../engine/ocsp.ts";
import type { PkiEngine } from "../engine/pki-engine.ts";
import { revocationErrorCode } from "../errors.ts";
import type { SourceCheckOptions } from "./revocation.ts";
import type { RevocationCache } from "./revocation-cache.ts";
import type { RevocationProvider } from "./revocation-provider.ts";

type RevocationResult = CrlValidationResult | OcspValidationResult;
type RevocationSourceChecker = (
  options: SourceCheckOptions
) => Promise<RevocationResult>;
export function createRevocationSourceChecker({
  provider,
  engine,
  now,
  cache,
  report
}: {
  provider: RevocationProvider;
  engine: PkiEngine;
  now: () => number;
  cache: RevocationCache;
  report: DiagnosticReporter;
}): RevocationSourceChecker {
  async function checkSource(
    options: SourceCheckOptions
  ): Promise<RevocationResult> {
    const { mechanism, checkDateMs, signal } = options;
    if (checkDateMs !== undefined && !Number.isFinite(checkDateMs)) {
      throw new TypeError("checkDate must be a valid date");
    }
    const key = cache.cacheKey(mechanism, options);
    const notify: SourceDiagnosticReporter = (event) =>
      report({
        ...event,
        mechanism,
        certificateIndex: options.certificateIndex
      });

    function validate(data: Uint8Array): Promise<RevocationResult> {
      const input = {
        certificateDer: options.certificateDer,
        issuerDer: options.issuerDer,
        checkDateMs: checkDateMs ?? now(),
        signal
      };
      return mechanism === "crl"
        ? engine.validateCrl({ ...input, crl: data })
        : engine.validateOcsp({ ...input, response: data });
    }

    const cached = await cache.read(key, notify);
    if (cached !== null) {
      notify({ event: "cache_hit", message: "Revalidating cached evidence" });
      const result = await validate(cached);
      if (result.status !== "unknown") {
        notify({
          event: "revocation_result",
          status: result.status,
          message: "Cached evidence established revocation status"
        });
        return result;
      }
      notify({
        event: "revocation_result",
        status: result.status,
        code: result.code,
        message: result.message
      });
      notify({
        event: "cache_discarded",
        message: "Cached evidence did not establish revocation status"
      });
      await cache.discard(key, notify);
    } else {
      notify({ event: "cache_miss", message: "No usable cached evidence" });
    }

    let result: RevocationResult;
    let data: Uint8Array;
    try {
      const request = {
        url: options.source,
        issuerCertificate: options.issuerDer,
        signal
      };
      const downloaded =
        mechanism === "crl"
          ? await provider.loadCrl!(request)
          : await provider.loadOcsp!({
              ...request,
              certificate: Uint8Array.from(options.certificateDer),
              issuerCertificate: Uint8Array.from(options.issuerDer),
              requestDer: options.ocspRequestDer!
            });
      data = Uint8Array.from(downloaded);
      result = await validate(data);
    } catch (error) {
      notify({
        event: "revocation_error",
        code: revocationErrorCode(error),
        message: "Unable to load or validate revocation evidence"
      });
      throw error;
    }
    notify({
      event: "revocation_result",
      status: result.status,
      ...(result.status === "unknown"
        ? { code: result.code, message: result.message }
        : { message: "Loaded evidence established revocation status" })
    });
    if (result.status !== "unknown") {
      const write = cache.write(key, data, result.nextUpdate, notify);
      // Confirmed revocation must not wait for cache persistence.
      if (result.status !== "revoked") await write;
    }
    return result;
  }

  return checkSource;
}

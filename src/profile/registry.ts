// Registers immutable profile versions and selects the validator for each verification request.
import { z } from "zod";
import type { DiagnosticCallback } from "../diagnostics.ts";
import type { CertificateInput } from "../engine/certificate-path.ts";
import type { PkiEngine } from "../engine/pki-engine.ts";
import { invalidProfile } from "../errors.ts";
import type { CacheStore } from "../revocation/cache.ts";
import type { HttpOptions } from "../revocation/http-loaders.ts";
import type {
  RevocationLoaderOptions,
  RevocationProvider
} from "../revocation/revocation-provider.ts";
import {
  createPreparedTrustValidator,
  type TrustValidator,
  type ValidationResult
} from "../trust-validator.ts";
import type { ProfileVersion, ValidationProfileInput } from "./profile.ts";
import type { TrustRuleRegistration } from "./rules.ts";
import {
  nonEmptyString,
  parseProfileInput,
  profileVersionSchema
} from "./validation.ts";
import {
  type PreparedValidatorConfig,
  prepareValidatorConfig
} from "./validator-config.ts";

export interface ValidationProfileRegistration {
  profile: ValidationProfileInput;
  trustAnchors: readonly CertificateInput[];
  rules?: readonly TrustRuleRegistration[];
}

export interface ValidationProfileRegistryOptions
  extends RevocationLoaderOptions {
  provider?: RevocationProvider;
  engine?: PkiEngine;
  http?: HttpOptions;
  deadlineMs?: number;
  cache?: CacheStore;
  maxCacheAgeMs?: number;
  cacheKeyPrefix?: string;
  now?: () => number;
  onDiagnostic?: DiagnosticCallback;
}

const certificateInputSchema = z.union([z.string(), z.instanceof(Uint8Array)]);
const registrationSchema = z.strictObject({
  profile: z.record(z.string(), z.unknown()),
  trustAnchors: z.array(certificateInputSchema).min(1),
  rules: z.unknown().optional()
});
const verifyOptionsSchema = z.strictObject({
  profileId: nonEmptyString,
  profileVersion: profileVersionSchema.optional(),
  // The engine checks chain length before inspecting certificate inputs.
  certificateChain: z.custom<readonly CertificateInput[]>(
    Array.isArray,
    "must be an array"
  ),
  checkDate: z.instanceof(Date).optional()
});

export type ValidationProfileRegistryVerifyOptions = z.infer<
  typeof verifyOptionsSchema
>;

export interface ValidationProfileRegistry {
  register(registration: unknown): void;
  verify(options: unknown): Promise<ValidationResult>;
}

interface ProfileSnapshot {
  version: ProfileVersion;
  versionOrder: number;
  validator: TrustValidator;
}

export function createValidationProfileRegistry(
  options: ValidationProfileRegistryOptions = {}
): ValidationProfileRegistry {
  const profiles = new Map<string, Map<string, ProfileSnapshot>>();

  return {
    register(input): void {
      const registration = parseProfileInput(
        registrationSchema,
        input,
        "profile registration"
      );
      let config: PreparedValidatorConfig;
      try {
        config = prepareValidatorConfig(registration);
      } catch (error) {
        if (error instanceof TypeError) {
          throw invalidProfile("trustAnchors contains an invalid certificate");
        }
        throw error;
      }
      const { profile } = config;
      const profileId = profile.id;
      const versionKey = String(profile.version);
      let versions = profiles.get(profileId);
      if (versions?.has(versionKey)) {
        throw invalidProfile(
          `Profile "${profileId}" version ${profile.version} is already registered`
        );
      }
      for (const existing of versions?.values() ?? []) {
        if (existing.versionOrder === profile.versionOrder) {
          throw invalidProfile(
            `Profile "${profileId}" already has versionOrder ${profile.versionOrder}`
          );
        }
      }
      const validator = createPreparedTrustValidator({ ...options, ...config });
      if (!versions) {
        versions = new Map();
        profiles.set(profileId, versions);
      }
      versions.set(versionKey, {
        version: profile.version,
        versionOrder: profile.versionOrder,
        validator
      });
    },

    async verify(input): Promise<ValidationResult> {
      const parsed = verifyOptionsSchema.safeParse(input);
      if (!parsed.success) throw new TypeError(z.prettifyError(parsed.error));
      const request = parsed.data;
      const versions = profiles.get(request.profileId);
      if (!versions) {
        return {
          valid: false,
          code: "UNKNOWN_PROFILE",
          message: `Unknown validation profile: ${request.profileId}`
        };
      }
      let snapshot: ProfileSnapshot | undefined;
      if (request.profileVersion === undefined) {
        for (const candidate of versions.values()) {
          if (!snapshot || candidate.versionOrder > snapshot.versionOrder) {
            snapshot = candidate;
          }
        }
      } else {
        snapshot = versions.get(String(request.profileVersion));
      }
      if (!snapshot) {
        return {
          valid: false,
          code: "UNKNOWN_PROFILE_VERSION",
          message: `Profile "${request.profileId}" has no version ${request.profileVersion}`,
          profileId: request.profileId
        };
      }
      // The snapshot is chosen before any await, so a later registration
      // cannot change the profile or anchors used by this request.
      return snapshot.validator.verify({
        certificateChain: request.certificateChain,
        checkDate: request.checkDate
      });
    }
  };
}

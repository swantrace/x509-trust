import { X509Certificate } from "node:crypto";
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
  createTrustValidator,
  type TrustValidator,
  type ValidationResult
} from "../trust-validator.ts";
import {
  compileValidationProfile,
  type ProfileVersion,
  type ValidationProfileInput
} from "./profile.ts";
import {
  normalizeRuleRegistrations,
  type TrustRuleRegistration
} from "./rules.ts";

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

export interface ValidationProfileRegistryVerifyOptions {
  profileId: string;
  profileVersion?: ProfileVersion;
  certificateChain: readonly CertificateInput[];
  checkDate?: Date;
}

export interface ValidationProfileRegistry {
  register(registration: unknown): void;
  verify(options: unknown): Promise<ValidationResult>;
}

interface ProfileSnapshot {
  version: ProfileVersion;
  versionOrder: number;
  validator: TrustValidator;
}

function assertRegistrationShape(
  input: unknown
): asserts input is ValidationProfileRegistration {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw invalidProfile("profile registration must be an object");
  }
  for (const key of Object.keys(input)) {
    if (!["profile", "trustAnchors", "rules"].includes(key)) {
      throw invalidProfile(
        `profile registration contains unknown field "${key}"`
      );
    }
  }
  const { profile, trustAnchors } = input as {
    profile?: unknown;
    trustAnchors?: unknown;
  };
  if (
    profile === null ||
    typeof profile !== "object" ||
    Array.isArray(profile)
  ) {
    throw invalidProfile("profile must be an object");
  }
  if (!Array.isArray(trustAnchors) || trustAnchors.length === 0) {
    throw invalidProfile("trustAnchors must be a non-empty array");
  }
}

function assertVerifyOptionsShape(
  input: unknown
): asserts input is ValidationProfileRegistryVerifyOptions {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("verify options must be an object");
  }
  for (const key of Object.keys(input)) {
    if (
      ![
        "profileId",
        "profileVersion",
        "certificateChain",
        "checkDate"
      ].includes(key)
    ) {
      throw new TypeError(`verify options contain unknown field "${key}"`);
    }
  }
  const { profileId, profileVersion, certificateChain, checkDate } = input as {
    profileId?: unknown;
    profileVersion?: unknown;
    certificateChain?: unknown;
    checkDate?: unknown;
  };
  if (typeof profileId !== "string" || profileId.trim() === "") {
    throw new TypeError("profileId must be a non-empty string");
  }
  if (profileVersion !== undefined) {
    if (typeof profileVersion === "string") {
      if (profileVersion.trim() === "") {
        throw new TypeError("profileVersion must be a non-empty string");
      }
    } else if (
      !Number.isSafeInteger(profileVersion) ||
      (profileVersion as number) <= 0
    ) {
      throw new TypeError(
        "profileVersion must be a string or positive integer"
      );
    }
  }
  if (!Array.isArray(certificateChain)) {
    throw new TypeError("certificateChain must be an array");
  }
  if (checkDate !== undefined && !(checkDate instanceof Date)) {
    throw new TypeError("checkDate must be a Date");
  }
}

export function createValidationProfileRegistry(
  options: ValidationProfileRegistryOptions = {}
): ValidationProfileRegistry {
  const profiles = new Map<string, Map<string, ProfileSnapshot>>();

  return {
    register(registration): void {
      assertRegistrationShape(registration);
      const profileInput = registration.profile;
      const rules = normalizeRuleRegistrations(registration.rules);
      // Compile once for duplicate/version validation; the validator compiles
      // its own immutable copy for the lifetime of the registered snapshot.
      const profile = compileValidationProfile(profileInput, {
        registeredRuleNames: rules.map((rule) => rule.name)
      });
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
      let trustAnchors: Uint8Array[];
      try {
        trustAnchors = registration.trustAnchors.map((anchor) =>
          Uint8Array.from(new X509Certificate(anchor).raw)
        );
      } catch {
        throw invalidProfile("trustAnchors contains an invalid certificate");
      }
      const validator = createTrustValidator({
        ...options,
        trustAnchors,
        profile: profileInput,
        rules
      });
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

    async verify(request): Promise<ValidationResult> {
      assertVerifyOptionsShape(request);
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

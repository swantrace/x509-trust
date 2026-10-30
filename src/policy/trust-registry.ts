import { X509Certificate } from "node:crypto";
import type { DiagnosticCallback } from "../diagnostics.ts";
import type { CertificateInput } from "../engine/certificate-path.ts";
import type { CrlIndexCacheOptions } from "../engine/crl-index-cache.ts";
import type { PkiEngine } from "../engine/pki-engine.ts";
import { invalidPolicy } from "../errors.ts";
import type { CacheStore } from "../evidence/cache.ts";
import type { EvidenceProvider } from "../evidence/evidence-provider.ts";
import type {
  CrlLoadOptions,
  HttpOptions,
  OcspLoadOptions
} from "../evidence/http-loaders.ts";
import {
  createTrustValidator,
  type TrustValidator,
  type ValidationResult
} from "../validator/trust-validator.ts";
import {
  compileTrustPolicy,
  type PolicyVersion,
  type TrustPolicyInput
} from "./policy.ts";
import {
  normalizeRuleRegistrations,
  type TrustRuleRegistration
} from "./rules.ts";

export interface TrustCommunityRegistration {
  communityId: string;
  trustAnchors: readonly CertificateInput[];
  policy: TrustPolicyInput;
  rules?: readonly TrustRuleRegistration[];
}

export interface TrustRegistryOptions {
  loadCrl?:
    | ((url: string, options?: CrlLoadOptions) => Promise<Uint8Array>)
    | false;
  loadOcsp?: ((options: OcspLoadOptions) => Promise<Uint8Array>) | false;
  provider?: EvidenceProvider;
  engine?: PkiEngine;
  crlIndexCache?: CrlIndexCacheOptions | false;
  http?: HttpOptions;
  deadlineMs?: number;
  cache?: CacheStore;
  maxCacheAgeMs?: number;
  cacheKeyPrefix?: string;
  now?: () => number;
  onDiagnostic?: DiagnosticCallback;
}

export interface TrustRegistryVerifyOptions {
  communityId: string;
  policyVersion?: PolicyVersion;
  certificateChain: readonly CertificateInput[];
  checkDate?: Date;
}

export interface TrustRegistry {
  register(registration: unknown): void;
  verify(options: unknown): Promise<ValidationResult>;
}

interface PolicySnapshot {
  version: PolicyVersion;
  versionOrder: number;
  validator: TrustValidator;
}

function assertRegistrationShape(
  input: unknown
): asserts input is TrustCommunityRegistration {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw invalidPolicy("community registration must be an object");
  }
  for (const key of Object.keys(input)) {
    if (!["communityId", "trustAnchors", "policy", "rules"].includes(key)) {
      throw invalidPolicy(
        `community registration contains unknown field "${key}"`
      );
    }
  }
  const { communityId, trustAnchors } = input as {
    communityId?: unknown;
    trustAnchors?: unknown;
  };
  if (typeof communityId !== "string" || communityId.trim() === "") {
    throw invalidPolicy("communityId must be a non-empty string");
  }
  if (!Array.isArray(trustAnchors) || trustAnchors.length === 0) {
    throw invalidPolicy("trustAnchors must be a non-empty array");
  }
}

function assertVerifyOptionsShape(
  input: unknown
): asserts input is TrustRegistryVerifyOptions {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("verify options must be an object");
  }
  for (const key of Object.keys(input)) {
    if (
      ![
        "communityId",
        "policyVersion",
        "certificateChain",
        "checkDate"
      ].includes(key)
    ) {
      throw new TypeError(`verify options contain unknown field "${key}"`);
    }
  }
  const { communityId, policyVersion, certificateChain, checkDate } = input as {
    communityId?: unknown;
    policyVersion?: unknown;
    certificateChain?: unknown;
    checkDate?: unknown;
  };
  if (typeof communityId !== "string" || communityId.trim() === "") {
    throw new TypeError("communityId must be a non-empty string");
  }
  if (policyVersion !== undefined) {
    if (typeof policyVersion === "string") {
      if (policyVersion.trim() === "") {
        throw new TypeError("policyVersion must be a non-empty string");
      }
    } else if (
      !Number.isSafeInteger(policyVersion) ||
      (policyVersion as number) <= 0
    ) {
      throw new TypeError("policyVersion must be a string or positive integer");
    }
  }
  if (!Array.isArray(certificateChain)) {
    throw new TypeError("certificateChain must be an array");
  }
  if (checkDate !== undefined && !(checkDate instanceof Date)) {
    throw new TypeError("checkDate must be a Date");
  }
}

export function createTrustRegistry(
  options: TrustRegistryOptions = {}
): TrustRegistry {
  const communities = new Map<string, Map<string, PolicySnapshot>>();

  return {
    register(registration): void {
      assertRegistrationShape(registration);
      const communityId = registration.communityId;
      const rules = normalizeRuleRegistrations(registration.rules);
      // Compile once for duplicate/version validation; the validator compiles
      // its own immutable copy for the lifetime of the registered snapshot.
      const policy = compileTrustPolicy(registration.policy, {
        registeredRuleNames: rules.map((rule) => rule.name)
      });
      let versions = communities.get(communityId);
      const versionKey = String(policy.version);
      if (versions?.has(versionKey)) {
        throw invalidPolicy(
          `Community "${communityId}" policy version ${policy.version} is already registered`
        );
      }
      for (const existing of versions?.values() ?? []) {
        if (existing.versionOrder === policy.versionOrder) {
          throw invalidPolicy(
            `Community "${communityId}" already has a policy with versionOrder ${policy.versionOrder}`
          );
        }
      }
      let trustAnchors: Uint8Array[];
      try {
        trustAnchors = registration.trustAnchors.map((anchor) =>
          Uint8Array.from(new X509Certificate(anchor).raw)
        );
      } catch {
        throw invalidPolicy("trustAnchors contains an invalid certificate");
      }
      const validator = createTrustValidator({
        ...options,
        trustAnchors,
        policy: registration.policy,
        rules,
        communityId
      });
      if (!versions) {
        versions = new Map();
        communities.set(communityId, versions);
      }
      versions.set(versionKey, {
        version: policy.version,
        versionOrder: policy.versionOrder,
        validator
      });
    },

    async verify(request): Promise<ValidationResult> {
      assertVerifyOptionsShape(request);
      const versions = communities.get(request.communityId);
      if (!versions) {
        return {
          valid: false,
          code: "UNKNOWN_COMMUNITY",
          message: `Unknown trust community: ${request.communityId}`
        };
      }
      let snapshot: PolicySnapshot | undefined;
      if (request.policyVersion === undefined) {
        for (const candidate of versions.values()) {
          if (!snapshot || candidate.versionOrder > snapshot.versionOrder) {
            snapshot = candidate;
          }
        }
      } else {
        snapshot = versions.get(String(request.policyVersion));
      }
      if (!snapshot) {
        return {
          valid: false,
          code: "UNKNOWN_POLICY_VERSION",
          message: `Community "${request.communityId}" has no policy version ${request.policyVersion}`,
          communityId: request.communityId
        };
      }
      // The snapshot is chosen before any await, so a later registration
      // cannot change the policy or anchors used by this request.
      return snapshot.validator.verify({
        certificateChain: request.certificateChain,
        checkDate: request.checkDate
      });
    }
  };
}

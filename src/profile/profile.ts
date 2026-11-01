import { z } from "zod";
import type { KeyUsageName } from "../engine/leaf-certificate.ts";
import { invalidProfile, unsupportedProfile } from "../errors.ts";
import {
  nonEmptyString,
  parseProfileInput,
  profileObject,
  profileVersionSchema,
  uniqueList
} from "./validation.ts";

const mechanismSchema = z.enum(["crl", "ocsp"]);
const requiredEvidenceSchema = z.enum(["any", "crl", "ocsp", "both"]);
const keyUsageSchema = z.enum([
  "digitalSignature",
  "nonRepudiation",
  "keyEncipherment",
  "dataEncipherment",
  "keyAgreement",
  "keyCertSign",
  "cRLSign",
  "encipherOnly",
  "decipherOnly"
]);
const oidSchema = nonEmptyString.regex(/^[0-2](?:\.(?:0|[1-9]\d*))+$/);
const sourceSchema = profileObject({
  uri: nonEmptyString,
  version: nonEmptyString.optional(),
  effectiveDate: nonEmptyString
    .refine(
      (value) => !Number.isNaN(Date.parse(value)),
      "must be a valid date string"
    )
    .optional()
});
const rulesSchema = profileObject({
  leafKeyUsage: uniqueList(nonEmptyString.pipe(keyUsageSchema)).optional(),
  leafExtendedKeyUsage: uniqueList(oidSchema).optional(),
  requiredCertificatePolicyOids: uniqueList(oidSchema).optional(),
  maxPathDepth: z.int().positive().optional(),
  requiredRuleNames: uniqueList(nonEmptyString).optional()
});
const profileSchema = profileObject({
  id: nonEmptyString,
  version: profileVersionSchema,
  versionOrder: z.int().positive().optional(),
  source: z.union([nonEmptyString, sourceSchema]),
  anchorSetId: nonEmptyString,
  revocation: profileObject({
    requiredEvidence: requiredEvidenceSchema.optional(),
    sourceOrder: uniqueList(nonEmptyString.pipe(mechanismSchema)).optional(),
    onUnknown: z.literal("reject").optional(),
    scope: z.literal("non-anchor-chain").optional(),
    requireNextUpdate: z.literal(true).optional(),
    clockSkewMs: z.literal(0).optional()
  }).optional(),
  rules: rulesSchema.optional()
});

export type RevocationMechanism = z.infer<typeof mechanismSchema>;
export type RequiredEvidence = z.infer<typeof requiredEvidenceSchema>;
export type ProfileVersion = z.infer<typeof profileVersionSchema>;
export type ProfileSource = z.infer<typeof sourceSchema>;
export type ValidationProfileInput = z.infer<typeof profileSchema>;

export interface CompiledValidationProfile {
  readonly id: string;
  readonly version: ProfileVersion;
  readonly versionOrder: number;
  readonly source: Readonly<ProfileSource>;
  readonly anchorSetId: string;
  readonly revocation: Readonly<{
    requiredEvidence: RequiredEvidence;
    sourceOrder: readonly RevocationMechanism[];
    onUnknown: "reject";
    scope: "non-anchor-chain";
    requireNextUpdate: true;
    clockSkewMs: 0;
  }>;
  readonly rules?: Readonly<{
    leafKeyUsage?: readonly KeyUsageName[];
    leafExtendedKeyUsage?: readonly string[];
    requiredCertificatePolicyOids?: readonly string[];
    maxPathDepth?: number;
    requiredRuleNames?: readonly string[];
  }>;
}

export interface CompileProfileOptions {
  registeredRuleNames?: readonly string[];
}

export const DEFAULT_VALIDATION_PROFILE: ValidationProfileInput = Object.freeze(
  {
    id: "x509-trust:strict-default",
    version: 1,
    versionOrder: 1,
    source: Object.freeze({
      uri: "x509-trust:built-in-strict-default",
      version: "1"
    }),
    anchorSetId: "explicit",
    revocation: Object.freeze({
      requiredEvidence: "any" as const,
      sourceOrder: Object.freeze(["ocsp", "crl"] as const),
      onUnknown: "reject" as const,
      scope: "non-anchor-chain" as const,
      requireNextUpdate: true as const,
      clockSkewMs: 0 as const
    })
  }
);

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const entry of Object.values(value as Record<string, unknown>)) {
      deepFreeze(entry);
    }
  }
  return value;
}

export function compileValidationProfile(
  input: unknown = DEFAULT_VALIDATION_PROFILE,
  { registeredRuleNames = [] }: CompileProfileOptions = {}
): CompiledValidationProfile {
  const profile = parseProfileInput(profileSchema, input, "profile");
  const versionOrder =
    profile.versionOrder ??
    (typeof profile.version === "number" ? profile.version : undefined);
  if (versionOrder === undefined) {
    throw invalidProfile(
      "profile.versionOrder is required when profile.version is a string"
    );
  }
  const requiredEvidence = profile.revocation?.requiredEvidence ?? "any";
  const sourceOrder =
    profile.revocation?.sourceOrder ?? (["ocsp", "crl"] as const);
  const requiredMechanisms =
    requiredEvidence === "any"
      ? []
      : requiredEvidence === "both"
        ? (["crl", "ocsp"] as const)
        : [requiredEvidence];
  for (const mechanism of requiredMechanisms) {
    if (!sourceOrder.includes(mechanism)) {
      throw invalidProfile(
        `profile.revocation.sourceOrder must include required mechanism "${mechanism}"`
      );
    }
  }
  const rules =
    profile.rules && Object.keys(profile.rules).length > 0
      ? profile.rules
      : undefined;
  const registered = new Set(registeredRuleNames);
  for (const name of rules?.requiredRuleNames ?? []) {
    if (!registered.has(name)) {
      throw unsupportedProfile(
        `No registered rule handler is available for "${name}"`
      );
    }
  }
  return deepFreeze({
    id: profile.id,
    version: profile.version,
    versionOrder,
    source:
      typeof profile.source === "string"
        ? { uri: profile.source }
        : profile.source,
    anchorSetId: profile.anchorSetId,
    revocation: {
      requiredEvidence,
      sourceOrder,
      onUnknown: "reject" as const,
      scope: "non-anchor-chain" as const,
      requireNextUpdate: true as const,
      clockSkewMs: 0 as const
    },
    ...(rules ? { rules } : {})
  });
}

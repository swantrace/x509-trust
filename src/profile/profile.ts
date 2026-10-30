import type { KeyUsageName } from "../engine/leaf-certificate.ts";
import { invalidProfile, unsupportedProfile } from "../errors.ts";

export type RevocationMechanism = "crl" | "ocsp";
export type RequiredEvidence = "any" | "crl" | "ocsp" | "both";
export type ProfileVersion = string | number;
export type ProfileCapability =
  | "revocation:any"
  | "revocation:crl"
  | "revocation:ocsp"
  | "revocation:both"
  | "revocation:non-anchor-chain"
  | "revocation:require-next-update"
  | "revocation:zero-clock-skew"
  | "rules:leaf-key-usage"
  | "rules:leaf-extended-key-usage"
  | "rules:required-certificate-policy-oids"
  | "rules:max-path-depth"
  | "rules:required-rule-names";

export interface ProfileSource {
  uri: string;
  version?: string;
  effectiveDate?: string;
}

export interface ValidationProfileInput {
  id: string;
  version: ProfileVersion;
  /** Explicit ordering used to select the latest version in a registry. */
  versionOrder?: number;
  source: string | ProfileSource;
  anchorSetId: string;
  /** Capabilities this profile explicitly requires the engine to support. */
  requiredCapabilities?: readonly ProfileCapability[];
  revocation?: {
    requiredEvidence?: RequiredEvidence;
    sourceOrder?: readonly RevocationMechanism[];
    onUnknown?: "reject";
    scope?: "non-anchor-chain";
    requireNextUpdate?: true;
    clockSkewMs?: 0;
  };
  rules?: {
    leafKeyUsage?: readonly KeyUsageName[];
    leafExtendedKeyUsage?: readonly string[];
    requiredCertificatePolicyOids?: readonly string[];
    maxPathDepth?: number;
    requiredRuleNames?: readonly string[];
  };
}

export interface CompiledValidationProfile {
  readonly id: string;
  readonly version: ProfileVersion;
  readonly versionOrder: number;
  readonly source: Readonly<ProfileSource>;
  readonly anchorSetId: string;
  /** Capabilities explicitly declared by the caller. */
  readonly requiredCapabilities: readonly ProfileCapability[];
  /** Capabilities actually exercised by the compiled profile. */
  readonly capabilities: readonly ProfileCapability[];
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

export const PROFILE_CAPABILITIES: readonly ProfileCapability[] = Object.freeze(
  [
    "revocation:any",
    "revocation:crl",
    "revocation:ocsp",
    "revocation:both",
    "revocation:non-anchor-chain",
    "revocation:require-next-update",
    "revocation:zero-clock-skew",
    "rules:leaf-key-usage",
    "rules:leaf-extended-key-usage",
    "rules:required-certificate-policy-oids",
    "rules:max-path-depth",
    "rules:required-rule-names"
  ] as const
);

const SUPPORTED_CAPABILITIES = new Set<string>(PROFILE_CAPABILITIES);

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
    requiredCapabilities: Object.freeze([
      "revocation:any",
      "revocation:crl",
      "revocation:ocsp",
      "revocation:non-anchor-chain",
      "revocation:require-next-update",
      "revocation:zero-clock-skew"
    ] as const),
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

export const profileCapabilities = Object.freeze({
  supported: PROFILE_CAPABILITIES,
  revocationScope: Object.freeze(["non-anchor-chain"] as const),
  requiredEvidence: Object.freeze(["any", "crl", "ocsp", "both"] as const),
  rules: Object.freeze([
    "leafKeyUsage",
    "leafExtendedKeyUsage",
    "requiredCertificatePolicyOids",
    "maxPathDepth",
    "requiredRuleNames"
  ] as const),
  unsupported: Object.freeze({
    fullPathCertificatePolicyProcessing:
      "Certificate policy OIDs are read from the leaf only; no RFC 5280 policy tree result is claimed.",
    delegatedOcsp: "Delegated OCSP responders are not verified.",
    deltaOrIndirectCrl: "Delta and indirect CRLs are rejected.",
    ocspWithoutNextUpdate: "OCSP responses must carry nextUpdate.",
    clockSkew: "Non-zero revocation clock skew is not configurable.",
    leafOnlyRevocation: "Revocation always covers every non-anchor certificate."
  })
});

const REVOCATION_MECHANISMS = new Set<RevocationMechanism>(["crl", "ocsp"]);
const REQUIRED_EVIDENCE = new Set<RequiredEvidence>([
  "any",
  "crl",
  "ocsp",
  "both"
]);
const KEY_USAGE_NAMES = new Set<KeyUsageName>([
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
const OID = /^[0-2](?:\.(?:0|[1-9]\d*))+$/;

function assertObject(
  value: unknown,
  path: string,
  allowedKeys: readonly string[]
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw invalidProfile(`${path} must be an object`);
  }
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(value)) {
    if ((value as Record<string, unknown>)[key] === undefined) continue;
    if (!allowed.has(key)) {
      throw invalidProfile(`${path} contains unknown field "${key}"`);
    }
  }
}

function nonEmptyString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw invalidProfile(`${path} must be a non-empty string`);
  }
  return value;
}

function copyStringList(
  value: unknown,
  path: string,
  validate?: (entry: string) => string
): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw invalidProfile(`${path} must be a non-empty array`);
  }
  const result: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string" || entry.trim() === "") {
      throw invalidProfile(`${path} entries must be non-empty strings`);
    }
    const normalized = validate ? validate(entry) : entry;
    if (result.includes(normalized)) {
      throw invalidProfile(`${path} must not contain duplicates`);
    }
    result.push(normalized);
  }
  return result;
}

function oid(value: string, path: string): string {
  if (!OID.test(value)) {
    throw invalidProfile(`${path} contains an invalid OID "${value}"`);
  }
  return value;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const entry of Object.values(value as Record<string, unknown>)) {
      deepFreeze(entry);
    }
  }
  return value;
}

function compileProfileVersion(
  version: unknown,
  versionOrder: unknown
): { version: ProfileVersion; versionOrder: number } {
  let order: number | undefined;
  if (versionOrder !== undefined) {
    if (!Number.isSafeInteger(versionOrder) || (versionOrder as number) <= 0) {
      throw invalidProfile("profile.versionOrder must be a positive integer");
    }
    order = versionOrder as number;
  }
  if (typeof version === "number") {
    if (!Number.isSafeInteger(version) || version <= 0) {
      throw invalidProfile("profile.version must be a positive integer");
    }
    return { version, versionOrder: order ?? version };
  }
  if (typeof version === "string") {
    if (version.trim() === "") {
      throw invalidProfile("profile.version must be a non-empty string");
    }
    if (order === undefined) {
      throw invalidProfile(
        "profile.versionOrder is required when profile.version is a string"
      );
    }
    return { version, versionOrder: order };
  }
  throw invalidProfile("profile.version must be a string or positive integer");
}

function compileProfileSource(value: unknown): ProfileSource {
  if (typeof value === "string") {
    return { uri: nonEmptyString(value, "profile.source") };
  }
  assertObject(value, "profile.source", ["uri", "version", "effectiveDate"]);
  const uri = nonEmptyString(value.uri, "profile.source.uri");
  const sourceVersion =
    value.version === undefined
      ? undefined
      : nonEmptyString(value.version, "profile.source.version");
  let effectiveDate: string | undefined;
  if (value.effectiveDate !== undefined) {
    effectiveDate = nonEmptyString(
      value.effectiveDate,
      "profile.source.effectiveDate"
    );
    if (Number.isNaN(Date.parse(effectiveDate))) {
      throw invalidProfile(
        "profile.source.effectiveDate must be a valid date string"
      );
    }
  }
  return {
    uri,
    ...(sourceVersion === undefined ? {} : { version: sourceVersion }),
    ...(effectiveDate === undefined ? {} : { effectiveDate })
  };
}

function copyCapabilities(value: unknown, path: string): ProfileCapability[] {
  const capabilities = copyStringList(value, path);
  for (const capability of capabilities) {
    if (!SUPPORTED_CAPABILITIES.has(capability)) {
      throw unsupportedProfile(
        `Unsupported profile capability "${capability}"`
      );
    }
  }
  return capabilities as ProfileCapability[];
}

export function compileValidationProfile(
  input: unknown = DEFAULT_VALIDATION_PROFILE,
  { registeredRuleNames = [] }: CompileProfileOptions = {}
): CompiledValidationProfile {
  assertObject(input, "profile", [
    "id",
    "version",
    "versionOrder",
    "source",
    "anchorSetId",
    "requiredCapabilities",
    "revocation",
    "rules"
  ]);
  const id = nonEmptyString(input.id, "profile.id");
  const { version, versionOrder } = compileProfileVersion(
    input.version,
    input.versionOrder
  );
  const source = compileProfileSource(input.source);
  const anchorSetId = nonEmptyString(input.anchorSetId, "profile.anchorSetId");
  const requiredCapabilities =
    input.requiredCapabilities === undefined
      ? []
      : copyCapabilities(
          input.requiredCapabilities,
          "profile.requiredCapabilities"
        );

  let requiredEvidence: RequiredEvidence = "any";
  let sourceOrder: RevocationMechanism[] = ["ocsp", "crl"];
  if (input.revocation !== undefined) {
    assertObject(input.revocation, "profile.revocation", [
      "requiredEvidence",
      "sourceOrder",
      "onUnknown",
      "scope",
      "requireNextUpdate",
      "clockSkewMs"
    ]);
    const revocation = input.revocation;
    if (revocation.requiredEvidence !== undefined) {
      if (
        typeof revocation.requiredEvidence !== "string" ||
        !REQUIRED_EVIDENCE.has(revocation.requiredEvidence as RequiredEvidence)
      ) {
        throw unsupportedProfile(
          `Unsupported revocation.requiredEvidence: ${String(
            revocation.requiredEvidence
          )}`
        );
      }
      requiredEvidence = revocation.requiredEvidence as RequiredEvidence;
    }
    if (revocation.sourceOrder !== undefined) {
      const order = copyStringList(
        revocation.sourceOrder,
        "profile.revocation.sourceOrder"
      );
      sourceOrder = order.map((entry) => {
        if (!REVOCATION_MECHANISMS.has(entry as RevocationMechanism)) {
          throw unsupportedProfile(
            `Unsupported revocation mechanism: ${entry}`
          );
        }
        return entry as RevocationMechanism;
      });
    }
    if (
      revocation.onUnknown !== undefined &&
      revocation.onUnknown !== "reject"
    ) {
      throw unsupportedProfile(
        'Only revocation.onUnknown = "reject" is supported'
      );
    }
    if (
      revocation.scope !== undefined &&
      revocation.scope !== "non-anchor-chain"
    ) {
      throw unsupportedProfile(
        'Only revocation.scope = "non-anchor-chain" is supported'
      );
    }
    if (
      revocation.requireNextUpdate !== undefined &&
      revocation.requireNextUpdate !== true
    ) {
      throw unsupportedProfile("Evidence without nextUpdate is not supported");
    }
    if (revocation.clockSkewMs !== undefined && revocation.clockSkewMs !== 0) {
      throw unsupportedProfile(
        "Non-zero revocation clock skew is not supported"
      );
    }
  }

  const requiredMechanisms =
    requiredEvidence === "any"
      ? []
      : requiredEvidence === "both"
        ? (["crl", "ocsp"] as const)
        : ([requiredEvidence] as const);
  for (const mechanism of requiredMechanisms) {
    if (!sourceOrder.includes(mechanism)) {
      throw invalidProfile(
        `profile.revocation.sourceOrder must include required mechanism "${mechanism}"`
      );
    }
  }

  let rules: CompiledValidationProfile["rules"];
  if (input.rules !== undefined) {
    assertObject(input.rules, "profile.rules", [
      "leafKeyUsage",
      "leafExtendedKeyUsage",
      "requiredCertificatePolicyOids",
      "maxPathDepth",
      "requiredRuleNames"
    ]);
    const inputRules = input.rules;
    const normalizedRules: {
      leafKeyUsage?: readonly KeyUsageName[];
      leafExtendedKeyUsage?: readonly string[];
      requiredCertificatePolicyOids?: readonly string[];
      maxPathDepth?: number;
      requiredRuleNames?: readonly string[];
    } = {};
    if (inputRules.leafKeyUsage !== undefined) {
      const usages = copyStringList(
        inputRules.leafKeyUsage,
        "profile.rules.leafKeyUsage"
      );
      for (const usage of usages) {
        if (!KEY_USAGE_NAMES.has(usage as KeyUsageName)) {
          throw unsupportedProfile(`Unsupported key usage: ${usage}`);
        }
      }
      normalizedRules.leafKeyUsage = usages as KeyUsageName[];
    }
    if (inputRules.leafExtendedKeyUsage !== undefined) {
      normalizedRules.leafExtendedKeyUsage = copyStringList(
        inputRules.leafExtendedKeyUsage,
        "profile.rules.leafExtendedKeyUsage",
        (entry) => oid(entry, "profile.rules.leafExtendedKeyUsage")
      );
    }
    if (inputRules.requiredCertificatePolicyOids !== undefined) {
      normalizedRules.requiredCertificatePolicyOids = copyStringList(
        inputRules.requiredCertificatePolicyOids,
        "profile.rules.requiredCertificatePolicyOids",
        (entry) => oid(entry, "profile.rules.requiredCertificatePolicyOids")
      );
    }
    if (inputRules.maxPathDepth !== undefined) {
      if (
        !Number.isSafeInteger(inputRules.maxPathDepth) ||
        (inputRules.maxPathDepth as number) < 1
      ) {
        throw invalidProfile(
          "profile.rules.maxPathDepth must be a positive integer"
        );
      }
      normalizedRules.maxPathDepth = inputRules.maxPathDepth as number;
    }
    if (inputRules.requiredRuleNames !== undefined) {
      const names = copyStringList(
        inputRules.requiredRuleNames,
        "profile.rules.requiredRuleNames"
      );
      const registered = new Set(registeredRuleNames);
      for (const name of names) {
        if (!registered.has(name)) {
          throw unsupportedProfile(
            `No registered rule handler is available for "${name}"`
          );
        }
      }
      normalizedRules.requiredRuleNames = names;
    }
    if (Object.keys(normalizedRules).length > 0) {
      rules = normalizedRules;
    }
  }

  const capabilities = new Set<ProfileCapability>([
    `revocation:${requiredEvidence}`,
    "revocation:non-anchor-chain",
    "revocation:require-next-update",
    "revocation:zero-clock-skew"
  ]);
  for (const mechanism of sourceOrder) {
    capabilities.add(`revocation:${mechanism}`);
  }
  if (rules?.leafKeyUsage) capabilities.add("rules:leaf-key-usage");
  if (rules?.leafExtendedKeyUsage)
    capabilities.add("rules:leaf-extended-key-usage");
  if (rules?.requiredCertificatePolicyOids)
    capabilities.add("rules:required-certificate-policy-oids");
  if (rules?.maxPathDepth) capabilities.add("rules:max-path-depth");
  if (rules?.requiredRuleNames) capabilities.add("rules:required-rule-names");

  return deepFreeze({
    id,
    version,
    versionOrder,
    source,
    anchorSetId,
    requiredCapabilities,
    capabilities: [...capabilities],
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

import type { KeyUsageName } from "../engine/leaf-certificate.ts";
import { invalidPolicy, unsupportedPolicy } from "../errors.ts";

export type RevocationMechanism = "crl" | "ocsp";
export type RequiredEvidence = "any" | "crl" | "ocsp" | "both";
export type PolicyVersion = string | number;
export type PolicyCapability =
  | "revocation:any"
  | "revocation:crl"
  | "revocation:ocsp"
  | "revocation:both"
  | "revocation:non-anchor-chain"
  | "revocation:require-next-update"
  | "revocation:zero-clock-skew"
  | "rules:leaf-key-usage"
  | "rules:leaf-extended-key-usage"
  | "rules:required-leaf-policy-oids"
  | "rules:max-path-depth"
  | "rules:required-rule-names";

export interface PolicySource {
  uri: string;
  version?: string;
  effectiveDate?: string;
}

export interface TrustPolicyInput {
  id: string;
  version: PolicyVersion;
  /** Explicit ordering used to select the latest version in a registry. */
  versionOrder?: number;
  source: string | PolicySource;
  anchorSetId: string;
  /** Capabilities this policy explicitly requires the engine to support. */
  requiredCapabilities?: readonly PolicyCapability[];
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
    requiredLeafPolicyOids?: readonly string[];
    maxPathDepth?: number;
    requiredRuleNames?: readonly string[];
  };
}

export interface CompiledTrustPolicy {
  readonly id: string;
  readonly version: PolicyVersion;
  readonly versionOrder: number;
  readonly source: Readonly<PolicySource>;
  readonly anchorSetId: string;
  /** Capabilities explicitly declared by the caller. */
  readonly requiredCapabilities: readonly PolicyCapability[];
  /** Capabilities actually exercised by the compiled policy. */
  readonly capabilities: readonly PolicyCapability[];
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
    requiredLeafPolicyOids?: readonly string[];
    maxPathDepth?: number;
    requiredRuleNames?: readonly string[];
  }>;
}

export const POLICY_CAPABILITIES: readonly PolicyCapability[] = Object.freeze([
  "revocation:any",
  "revocation:crl",
  "revocation:ocsp",
  "revocation:both",
  "revocation:non-anchor-chain",
  "revocation:require-next-update",
  "revocation:zero-clock-skew",
  "rules:leaf-key-usage",
  "rules:leaf-extended-key-usage",
  "rules:required-leaf-policy-oids",
  "rules:max-path-depth",
  "rules:required-rule-names"
] as const);

const SUPPORTED_CAPABILITIES = new Set<string>(POLICY_CAPABILITIES);

export interface CompilePolicyOptions {
  registeredRuleNames?: readonly string[];
}

export const DEFAULT_TRUST_POLICY: TrustPolicyInput = Object.freeze({
  id: "x509-trust:strict-default",
  version: 1,
  source: "x509-trust built-in strict default",
  anchorSetId: "explicit",
  revocation: Object.freeze({
    requiredEvidence: "any" as const,
    sourceOrder: Object.freeze(["ocsp", "crl"] as const)
  })
});

export const trustPolicyCapabilities = Object.freeze({
  supported: POLICY_CAPABILITIES,
  revocationScope: Object.freeze(["non-anchor-chain"] as const),
  requiredEvidence: Object.freeze(["any", "crl", "ocsp", "both"] as const),
  rules: Object.freeze([
    "leafKeyUsage",
    "leafExtendedKeyUsage",
    "requiredLeafPolicyOids",
    "maxPathDepth",
    "requiredRuleNames"
  ] as const),
  unsupported: Object.freeze({
    fullPathPolicyProcessing:
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
    throw invalidPolicy(`${path} must be an object`);
  }
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(value)) {
    if ((value as Record<string, unknown>)[key] === undefined) continue;
    if (!allowed.has(key)) {
      throw invalidPolicy(`${path} contains unknown field "${key}"`);
    }
  }
}

function nonEmptyString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw invalidPolicy(`${path} must be a non-empty string`);
  }
  return value;
}

function copyStringList(
  value: unknown,
  path: string,
  validate?: (entry: string) => string
): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw invalidPolicy(`${path} must be a non-empty array`);
  }
  const result: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string" || entry.trim() === "") {
      throw invalidPolicy(`${path} entries must be non-empty strings`);
    }
    const normalized = validate ? validate(entry) : entry;
    if (result.includes(normalized)) {
      throw invalidPolicy(`${path} must not contain duplicates`);
    }
    result.push(normalized);
  }
  return result;
}

function oid(value: string, path: string): string {
  if (!OID.test(value)) {
    throw invalidPolicy(`${path} contains an invalid OID "${value}"`);
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

function compilePolicyVersion(
  version: unknown,
  versionOrder: unknown
): { version: PolicyVersion; versionOrder: number } {
  let order: number | undefined;
  if (versionOrder !== undefined) {
    if (!Number.isSafeInteger(versionOrder) || (versionOrder as number) <= 0) {
      throw invalidPolicy("policy.versionOrder must be a positive integer");
    }
    order = versionOrder as number;
  }
  if (typeof version === "number") {
    if (!Number.isSafeInteger(version) || version <= 0) {
      throw invalidPolicy("policy.version must be a positive integer");
    }
    return { version, versionOrder: order ?? version };
  }
  if (typeof version === "string") {
    if (version.trim() === "") {
      throw invalidPolicy("policy.version must be a non-empty string");
    }
    if (order === undefined) {
      throw invalidPolicy(
        "policy.versionOrder is required when policy.version is a string"
      );
    }
    return { version, versionOrder: order };
  }
  throw invalidPolicy("policy.version must be a string or positive integer");
}

function compilePolicySource(value: unknown): PolicySource {
  if (typeof value === "string") {
    return { uri: nonEmptyString(value, "policy.source") };
  }
  assertObject(value, "policy.source", ["uri", "version", "effectiveDate"]);
  const uri = nonEmptyString(value.uri, "policy.source.uri");
  const sourceVersion =
    value.version === undefined
      ? undefined
      : nonEmptyString(value.version, "policy.source.version");
  let effectiveDate: string | undefined;
  if (value.effectiveDate !== undefined) {
    effectiveDate = nonEmptyString(
      value.effectiveDate,
      "policy.source.effectiveDate"
    );
    if (Number.isNaN(Date.parse(effectiveDate))) {
      throw invalidPolicy(
        "policy.source.effectiveDate must be a valid date string"
      );
    }
  }
  return {
    uri,
    ...(sourceVersion === undefined ? {} : { version: sourceVersion }),
    ...(effectiveDate === undefined ? {} : { effectiveDate })
  };
}

function copyCapabilities(value: unknown, path: string): PolicyCapability[] {
  const capabilities = copyStringList(value, path);
  for (const capability of capabilities) {
    if (!SUPPORTED_CAPABILITIES.has(capability)) {
      throw unsupportedPolicy(`Unsupported policy capability "${capability}"`);
    }
  }
  return capabilities as PolicyCapability[];
}

export function compileTrustPolicy(
  input: unknown = DEFAULT_TRUST_POLICY,
  { registeredRuleNames = [] }: CompilePolicyOptions = {}
): CompiledTrustPolicy {
  assertObject(input, "policy", [
    "id",
    "version",
    "versionOrder",
    "source",
    "anchorSetId",
    "requiredCapabilities",
    "revocation",
    "rules"
  ]);
  const id = nonEmptyString(input.id, "policy.id");
  const { version, versionOrder } = compilePolicyVersion(
    input.version,
    input.versionOrder
  );
  const source = compilePolicySource(input.source);
  const anchorSetId = nonEmptyString(input.anchorSetId, "policy.anchorSetId");
  const requiredCapabilities =
    input.requiredCapabilities === undefined
      ? []
      : copyCapabilities(
          input.requiredCapabilities,
          "policy.requiredCapabilities"
        );

  let requiredEvidence: RequiredEvidence = "any";
  let sourceOrder: RevocationMechanism[] = ["ocsp", "crl"];
  if (input.revocation !== undefined) {
    assertObject(input.revocation, "policy.revocation", [
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
        throw unsupportedPolicy(
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
        "policy.revocation.sourceOrder"
      );
      sourceOrder = order.map((entry) => {
        if (!REVOCATION_MECHANISMS.has(entry as RevocationMechanism)) {
          throw unsupportedPolicy(`Unsupported revocation mechanism: ${entry}`);
        }
        return entry as RevocationMechanism;
      });
    }
    if (
      revocation.onUnknown !== undefined &&
      revocation.onUnknown !== "reject"
    ) {
      throw unsupportedPolicy(
        'Only revocation.onUnknown = "reject" is supported'
      );
    }
    if (
      revocation.scope !== undefined &&
      revocation.scope !== "non-anchor-chain"
    ) {
      throw unsupportedPolicy(
        'Only revocation.scope = "non-anchor-chain" is supported'
      );
    }
    if (
      revocation.requireNextUpdate !== undefined &&
      revocation.requireNextUpdate !== true
    ) {
      throw unsupportedPolicy("Evidence without nextUpdate is not supported");
    }
    if (revocation.clockSkewMs !== undefined && revocation.clockSkewMs !== 0) {
      throw unsupportedPolicy(
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
      throw invalidPolicy(
        `policy.revocation.sourceOrder must include required mechanism "${mechanism}"`
      );
    }
  }

  let rules: CompiledTrustPolicy["rules"];
  if (input.rules !== undefined) {
    assertObject(input.rules, "policy.rules", [
      "leafKeyUsage",
      "leafExtendedKeyUsage",
      "requiredLeafPolicyOids",
      "maxPathDepth",
      "requiredRuleNames"
    ]);
    const inputRules = input.rules;
    const normalizedRules: {
      leafKeyUsage?: readonly KeyUsageName[];
      leafExtendedKeyUsage?: readonly string[];
      requiredLeafPolicyOids?: readonly string[];
      maxPathDepth?: number;
      requiredRuleNames?: readonly string[];
    } = {};
    if (inputRules.leafKeyUsage !== undefined) {
      const usages = copyStringList(
        inputRules.leafKeyUsage,
        "policy.rules.leafKeyUsage"
      );
      for (const usage of usages) {
        if (!KEY_USAGE_NAMES.has(usage as KeyUsageName)) {
          throw unsupportedPolicy(`Unsupported key usage: ${usage}`);
        }
      }
      normalizedRules.leafKeyUsage = usages as KeyUsageName[];
    }
    if (inputRules.leafExtendedKeyUsage !== undefined) {
      normalizedRules.leafExtendedKeyUsage = copyStringList(
        inputRules.leafExtendedKeyUsage,
        "policy.rules.leafExtendedKeyUsage",
        (entry) => oid(entry, "policy.rules.leafExtendedKeyUsage")
      );
    }
    if (inputRules.requiredLeafPolicyOids !== undefined) {
      normalizedRules.requiredLeafPolicyOids = copyStringList(
        inputRules.requiredLeafPolicyOids,
        "policy.rules.requiredLeafPolicyOids",
        (entry) => oid(entry, "policy.rules.requiredLeafPolicyOids")
      );
    }
    if (inputRules.maxPathDepth !== undefined) {
      if (
        !Number.isSafeInteger(inputRules.maxPathDepth) ||
        (inputRules.maxPathDepth as number) < 1
      ) {
        throw invalidPolicy(
          "policy.rules.maxPathDepth must be a positive integer"
        );
      }
      normalizedRules.maxPathDepth = inputRules.maxPathDepth as number;
    }
    if (inputRules.requiredRuleNames !== undefined) {
      const names = copyStringList(
        inputRules.requiredRuleNames,
        "policy.rules.requiredRuleNames"
      );
      const registered = new Set(registeredRuleNames);
      for (const name of names) {
        if (!registered.has(name)) {
          throw unsupportedPolicy(
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

  const capabilities = new Set<PolicyCapability>([
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
  if (rules?.requiredLeafPolicyOids)
    capabilities.add("rules:required-leaf-policy-oids");
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

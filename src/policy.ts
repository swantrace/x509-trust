import { invalidPolicy, unsupportedPolicy } from "./errors.ts";
import type { KeyUsageName } from "./leaf-certificate.ts";

export type RevocationMechanism = "crl" | "ocsp";
export type RequiredEvidence = "any" | "crl" | "ocsp" | "both";

export interface TrustPolicyInput {
  id: string;
  version: number;
  source: string;
  anchorSetId: string;
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
  readonly version: number;
  readonly source: string;
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
    requiredLeafPolicyOids?: readonly string[];
    maxPathDepth?: number;
    requiredRuleNames?: readonly string[];
  }>;
}

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

export function compileTrustPolicy(
  input: unknown = DEFAULT_TRUST_POLICY,
  { registeredRuleNames = [] }: CompilePolicyOptions = {}
): CompiledTrustPolicy {
  assertObject(input, "policy", [
    "id",
    "version",
    "source",
    "anchorSetId",
    "revocation",
    "rules"
  ]);
  const id = nonEmptyString(input.id, "policy.id");
  if (!Number.isSafeInteger(input.version) || (input.version as number) <= 0) {
    throw invalidPolicy("policy.version must be a positive integer");
  }
  const source = nonEmptyString(input.source, "policy.source");
  const anchorSetId = nonEmptyString(input.anchorSetId, "policy.anchorSetId");

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

  return deepFreeze({
    id,
    version: input.version as number,
    source,
    anchorSetId,
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

import { invalidPolicy, unsupportedPolicy } from "./errors.ts";
import type {
  CertificateFacts,
  KeyUsageName,
  ValidatedLeafCertificate
} from "./leaf-certificate.ts";
import type { CompiledTrustPolicy } from "./policy.ts";

export interface RuleLeafFacts {
  fingerprint256: string;
  serialNumber: string;
  uriSubjectAlternativeNames: readonly string[];
  notBeforeMs: number;
  notAfterMs: number;
  subject: string;
  issuer: string;
  keyUsages?: readonly KeyUsageName[];
  extendedKeyUsageOids?: readonly string[];
  certificatePolicyOids?: readonly string[];
}

export interface RulePathFacts {
  fingerprint256: string;
  subject: string;
  issuer: string;
  isCa: boolean;
  keyUsages?: readonly KeyUsageName[];
  extendedKeyUsageOids?: readonly string[];
  certificatePolicyOids?: readonly string[];
}

export interface TrustRuleContext {
  readonly communityId?: string;
  readonly policy: CompiledTrustPolicy;
  readonly leaf: RuleLeafFacts;
  readonly certificatePath: readonly RulePathFacts[];
}

export type TrustRuleResult = { ok: true } | { ok: false; message: string };

export type TrustRule = (
  context: TrustRuleContext
) => TrustRuleResult | Promise<TrustRuleResult>;

export interface TrustRuleRegistration {
  name: string;
  check: TrustRule;
}

function freezeList<T>(
  values: readonly T[] | undefined
): readonly T[] | undefined {
  return values ? Object.freeze([...values]) : undefined;
}

function toRuleLeafFacts(leaf: ValidatedLeafCertificate): RuleLeafFacts {
  return Object.freeze({
    fingerprint256: leaf.fingerprint256,
    serialNumber: leaf.serialNumber,
    uriSubjectAlternativeNames: freezeList(leaf.uriSubjectAlternativeNames)!,
    notBeforeMs: leaf.notBeforeMs,
    notAfterMs: leaf.notAfterMs,
    subject: leaf.subject,
    issuer: leaf.issuer,
    keyUsages: freezeList(leaf.keyUsages),
    extendedKeyUsageOids: freezeList(leaf.extendedKeyUsageOids),
    certificatePolicyOids: freezeList(leaf.certificatePolicyOids)
  });
}

function toRulePathFacts(facts: CertificateFacts): RulePathFacts {
  return Object.freeze({
    fingerprint256: facts.fingerprint256,
    subject: facts.subject,
    issuer: facts.issuer,
    isCa: facts.isCa,
    keyUsages: freezeList(facts.keyUsages),
    extendedKeyUsageOids: freezeList(facts.extendedKeyUsageOids),
    certificatePolicyOids: freezeList(facts.certificatePolicyOids)
  });
}

export function normalizeRuleRegistrations(
  input: unknown
): TrustRuleRegistration[] {
  if (input === undefined) return [];
  if (!Array.isArray(input)) {
    throw invalidPolicy("rules must be an array");
  }
  const names = new Set<string>();
  return input.map((entry, index) => {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw invalidPolicy(`rules[${index}] must be an object`);
    }
    for (const key of Object.keys(entry)) {
      if (!["name", "check"].includes(key)) {
        throw invalidPolicy(`rules[${index}] contains unknown field "${key}"`);
      }
    }
    const name = (entry as { name?: unknown }).name;
    const check = (entry as { check?: unknown }).check;
    if (typeof name !== "string" || name.trim() === "") {
      throw invalidPolicy(`rules[${index}].name must be a non-empty string`);
    }
    if (names.has(name)) {
      throw invalidPolicy(`Duplicate registered rule name: ${name}`);
    }
    if (typeof check !== "function") {
      throw invalidPolicy(`rules[${index}].check must be a function`);
    }
    names.add(name);
    return { name, check: check as TrustRule };
  });
}

function ruleResultMessage(name: string, result: unknown): string | undefined {
  if (result === null || typeof result !== "object") {
    return `Trust rule "${name}" returned an unrecognized result`;
  }
  const outcome = result as { ok?: unknown; message?: unknown };
  if (outcome.ok === true) return undefined;
  if (outcome.ok === false) {
    return typeof outcome.message === "string" && outcome.message.length > 0
      ? outcome.message
      : `Trust rule "${name}" rejected the certificate`;
  }
  return `Trust rule "${name}" returned an unrecognized result`;
}

export async function applyTrustRules({
  policy,
  leaf,
  certificatePath,
  communityId,
  rules
}: {
  policy: CompiledTrustPolicy;
  leaf: ValidatedLeafCertificate;
  certificatePath: readonly CertificateFacts[];
  communityId?: string;
  rules: readonly TrustRuleRegistration[];
}): Promise<string | undefined> {
  const required = policy.rules;
  if (!required) return undefined;

  if (
    required.maxPathDepth !== undefined &&
    certificatePath.length > required.maxPathDepth
  ) {
    return `The validated certificate path contains ${certificatePath.length} certificates and exceeds maxPathDepth ${required.maxPathDepth}`;
  }
  if (
    required.leafKeyUsage &&
    !required.leafKeyUsage.every((usage) =>
      (leaf.keyUsages ?? []).includes(usage)
    )
  ) {
    return "The leaf certificate does not contain every required key usage";
  }
  if (
    required.leafExtendedKeyUsage &&
    !required.leafExtendedKeyUsage.every((oid) =>
      (leaf.extendedKeyUsageOids ?? []).includes(oid)
    )
  ) {
    return "The leaf certificate does not contain every required extended key usage OID";
  }
  if (
    required.requiredLeafPolicyOids &&
    !required.requiredLeafPolicyOids.every((oid) =>
      (leaf.certificatePolicyOids ?? []).includes(oid)
    )
  ) {
    return "The leaf certificate does not contain every required certificate policy OID";
  }

  const context: TrustRuleContext = Object.freeze({
    communityId,
    policy,
    leaf: toRuleLeafFacts(leaf),
    certificatePath: Object.freeze(certificatePath.map(toRulePathFacts))
  });
  const byName = new Map(rules.map((rule) => [rule.name, rule]));
  for (const name of required.requiredRuleNames ?? []) {
    const rule = byName.get(name);
    if (!rule) {
      throw unsupportedPolicy(
        `No registered rule handler is available for "${name}"`
      );
    }
    let result: unknown;
    try {
      result = await rule.check(context);
    } catch {
      return `Trust rule "${name}" failed`;
    }
    const message = ruleResultMessage(name, result);
    if (message) return message;
  }
  return undefined;
}

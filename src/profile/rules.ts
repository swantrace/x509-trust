// Validates rule registrations and applies built-in and custom rules to trusted certificate facts.
import { z } from "zod";
import type {
  CertificateFacts,
  KeyUsageName,
  ValidatedLeafCertificate
} from "../engine/leaf-certificate.ts";
import { unsupportedProfile } from "../errors.ts";
import type { CompiledValidationProfile } from "./profile.ts";
import { nonEmptyString, parseProfileInput } from "./validation.ts";

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
  readonly profileId?: string;
  readonly profile: CompiledValidationProfile;
  readonly leaf: RuleLeafFacts;
  readonly certificatePath: readonly RulePathFacts[];
}

export type TrustRuleResult = { ok: true } | { ok: false; message: string };

export type TrustRule = (
  context: TrustRuleContext
) => TrustRuleResult | Promise<TrustRuleResult>;

const ruleRegistrationsSchema = z
  .array(
    z.strictObject({
      name: nonEmptyString,
      check: z.custom<TrustRule>(
        (value) => typeof value === "function",
        "must be a function"
      )
    })
  )
  .refine(
    (rules) => new Set(rules.map((rule) => rule.name)).size === rules.length,
    "must not contain duplicate rule names"
  );

export type TrustRuleRegistration = z.infer<
  typeof ruleRegistrationsSchema
>[number];

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
  return parseProfileInput(
    ruleRegistrationsSchema,
    input === undefined ? [] : input,
    "rules"
  );
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
  profile,
  leaf,
  certificatePath,
  profileId,
  rules
}: {
  profile: CompiledValidationProfile;
  leaf: ValidatedLeafCertificate;
  certificatePath: readonly CertificateFacts[];
  profileId?: string;
  rules: readonly TrustRuleRegistration[];
}): Promise<string | undefined> {
  const required = profile.rules;
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
    required.requiredCertificatePolicyOids &&
    !required.requiredCertificatePolicyOids.every((oid) =>
      (leaf.certificatePolicyOids ?? []).includes(oid)
    )
  ) {
    return "The leaf certificate does not contain every required certificate policy OID";
  }

  const context: TrustRuleContext = Object.freeze({
    profileId,
    profile,
    leaf: toRuleLeafFacts(leaf),
    certificatePath: Object.freeze(certificatePath.map(toRulePathFacts))
  });
  const byName = new Map(rules.map((rule) => [rule.name, rule]));
  for (const name of required.requiredRuleNames ?? []) {
    const rule = byName.get(name);
    if (!rule) {
      throw unsupportedProfile(
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

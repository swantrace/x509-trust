// Snapshots trust anchors and compiles the profile and rules used by a validator.
import { X509Certificate } from "node:crypto";
import type { CertificateInput } from "../engine/certificate-path.ts";
import {
  type CompiledValidationProfile,
  compileValidationProfile,
  DEFAULT_VALIDATION_PROFILE
} from "./profile.ts";
import {
  normalizeRuleRegistrations,
  type TrustRuleRegistration
} from "./rules.ts";

export interface PreparedValidatorConfig {
  trustAnchors: Uint8Array[];
  profile: CompiledValidationProfile;
  rules: TrustRuleRegistration[];
}
// Shared internally by direct construction and profile registration.
export function prepareValidatorConfig({
  trustAnchors,
  profile: profileInput,
  rules: ruleInput
}: {
  trustAnchors: readonly CertificateInput[];
  profile?: unknown;
  rules?: unknown;
}): PreparedValidatorConfig {
  if (trustAnchors.length === 0) {
    throw new TypeError("trustAnchors must contain at least one certificate");
  }
  const rules = normalizeRuleRegistrations(ruleInput);
  const profile = compileValidationProfile(
    profileInput ?? DEFAULT_VALIDATION_PROFILE,
    { registeredRuleNames: rules.map((rule) => rule.name) }
  );
  const anchors = trustAnchors.map((input) =>
    Uint8Array.from(new X509Certificate(input).raw)
  );
  return { trustAnchors: anchors, profile, rules };
}

export type PolicyErrorCode = "INVALID_POLICY" | "UNSUPPORTED_POLICY";

export class PolicyError extends Error {
  readonly code: PolicyErrorCode;

  constructor(code: PolicyErrorCode, message: string) {
    super(message);
    this.name = "PolicyError";
    this.code = code;
  }
}

export function invalidPolicy(message: string): PolicyError {
  return new PolicyError("INVALID_POLICY", message);
}

export function unsupportedPolicy(message: string): PolicyError {
  return new PolicyError("UNSUPPORTED_POLICY", message);
}

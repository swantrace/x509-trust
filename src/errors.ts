// Creates library errors and maps revocation failures to diagnostic codes.
export type ProfileErrorCode = "INVALID_PROFILE" | "UNSUPPORTED_PROFILE";

export class ProfileError extends Error {
  readonly code: ProfileErrorCode;

  constructor(code: ProfileErrorCode, message: string) {
    super(message);
    this.name = "ProfileError";
    this.code = code;
  }
}

export function invalidProfile(message: string): ProfileError {
  return new ProfileError("INVALID_PROFILE", message);
}

export function unsupportedProfile(message: string): ProfileError {
  return new ProfileError("UNSUPPORTED_PROFILE", message);
}

export class ResourceLimitError extends Error {
  readonly code = "RESOURCE_LIMIT_EXCEEDED" as const;

  constructor(message: string) {
    super(message);
    this.name = "ResourceLimitError";
  }
}

export function revocationErrorCode(error: unknown): string {
  if (error instanceof ResourceLimitError) return error.code;
  if (error instanceof Error) {
    if (
      error.name === "TimeoutError" ||
      (error.name === "AbortError" &&
        error.cause instanceof Error &&
        error.cause.name === "TimeoutError")
    ) {
      return "EVIDENCE_TIMEOUT";
    }
    if (error.name === "AbortError") return "EVIDENCE_ABORTED";
  }
  return "EVIDENCE_CHECK_FAILED";
}

export function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

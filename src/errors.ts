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

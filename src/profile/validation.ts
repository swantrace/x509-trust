import { z } from "zod";
import { invalidProfile, unsupportedProfile } from "../errors.ts";

export const nonEmptyString = z
  .string()
  .refine((value) => value.trim() !== "", "must be a non-empty string");
export const profileVersionSchema = z.union([
  nonEmptyString,
  z.int().positive()
]);

export function uniqueList<T extends z.ZodType>(item: T) {
  return z
    .array(item)
    .min(1)
    .refine(
      (items) => new Set(items).size === items.length,
      "must not contain duplicates"
    )
    .readonly();
}

export function profileObject<T extends z.ZodRawShape>(shape: T) {
  // Profile fields set to undefined are treated as absent, including unknown keys.
  return z.preprocess(
    (input) =>
      input !== null && typeof input === "object" && !Array.isArray(input)
        ? Object.fromEntries(
            Object.entries(input).filter(([, value]) => value !== undefined)
          )
        : input,
    z.strictObject(shape)
  );
}

export function parseProfileInput<T extends z.ZodType>(
  schema: T,
  input: unknown,
  label: string
): z.output<T> {
  const result = schema.safeParse(input);
  if (result.success) return result.data;
  const fail = result.error.issues.every(
    (issue) => issue.code === "invalid_value"
  )
    ? unsupportedProfile
    : invalidProfile;
  throw fail(`${label}: ${z.prettifyError(result.error)}`);
}

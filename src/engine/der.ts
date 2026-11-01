// Snapshots DER input and enforces size and single-value parsing limits.
import { fromBER } from "asn1js";

const MAX_DER_BYTES = 1024 * 1024;

export function parseDer(input: Uint8Array, label: string) {
  const bytes = Uint8Array.from(input);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_DER_BYTES) {
    throw new TypeError(`${label} has an unsupported DER size`);
  }
  const parsed = fromBER(bytes);
  if (parsed.offset < 0 || parsed.offset !== bytes.byteLength) {
    throw new TypeError(`${label} must contain exactly one DER value`);
  }
  return { bytes, schema: parsed.result };
}

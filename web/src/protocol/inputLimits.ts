const utf8Encoder = new TextEncoder();

// The Provider measures the exact JSON value it receives, including JSON escaping.
export function canonicalInferenceInputBytes(input: string): number {
  return utf8Encoder.encode(JSON.stringify(input)).byteLength;
}

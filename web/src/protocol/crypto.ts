export const API_KEY_PREFIX = "myco_test_";

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function generateApiKey(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `${API_KEY_PREFIX}${base64Url(bytes)}`;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function redactApiKey(value: string): string {
  if (value.length < 14) return "********";
  return `${value.slice(0, 10)}...${value.slice(-4)}`;
}

export function isGeneratedApiKey(value: string): boolean {
  return new RegExp(`^${API_KEY_PREFIX}[A-Za-z0-9_-]{43}$`).test(value);
}

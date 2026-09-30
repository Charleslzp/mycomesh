// TLS without certificate authorities: a Relay pins its self-signed certificate on-chain
// (https://IP:PORT#sha256=<hex> in the RelayDirectoryV11); mirrors mycomesh/tlspin.py.
import { createHash } from "node:crypto";
import { connect } from "node:tls";

const PIN_PREFIX = "#sha256=";
const trusted = new Map(); // pin -> PEM of the certificate that matched it

export function splitPin(endpoint) {
  const index = String(endpoint).indexOf(PIN_PREFIX);
  return index < 0 ? [String(endpoint), null] : [endpoint.slice(0, index), endpoint.slice(index + PIN_PREFIX.length).toLowerCase()];
}

/**
 * Fetch the Relay's certificate once, check it against the pin, and return
 * TLS options that trust exactly that certificate (no CA, no host name).
 */
export async function pinnedOptions(url, pin) {
  if (!trusted.has(pin)) {
    const target = new URL(url);
    const pem = await new Promise((resolve, reject) => {
      const socket = connect({ host: target.hostname, port: Number(target.port || 443), rejectUnauthorized: false }, () => {
        const der = socket.getPeerCertificate(true).raw;
        socket.end();
        if (!der || createHash("sha256").update(der).digest("hex") !== pin) {
          return reject(new Error(`Relay ${target.host} certificate does not match its on-chain pin`));
        }
        resolve(`-----BEGIN CERTIFICATE-----\n${der.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`);
      });
      socket.setTimeout(10_000, () => socket.destroy(new Error("TLS handshake timed out")));
      socket.on("error", reject);
    });
    trusted.set(pin, pem);
  }
  return { ca: [trusted.get(pin)], checkServerIdentity: () => undefined };
}

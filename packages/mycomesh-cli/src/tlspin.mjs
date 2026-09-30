// TLS without certificate authorities: a Relay pins its certificate on-chain
// (https://IP:PORT#sha256=<hex> in the RelayDirectoryV11); mirrors mycomesh/tlspin.py.
// The handshake completes, the fingerprint is compared, and only then does HTTP write a byte,
// whether the certificate is self-signed or issued by some CA.
import { createHash } from "node:crypto";
import { connect } from "node:tls";

const PIN_PREFIX = "#sha256=";

export function splitPin(endpoint) {
  const index = String(endpoint).indexOf(PIN_PREFIX);
  return index < 0 ? [String(endpoint), null] : [endpoint.slice(0, index), endpoint.slice(index + PIN_PREFIX.length).toLowerCase()];
}

/** Request options whose connection is handed to HTTP only after the certificate matches the pin. */
export function pinnedOptions(url, pin) {
  const target = new URL(url);
  return {
    createConnection: (_options, ready) => {
      const socket = connect({ host: target.hostname, port: Number(target.port || 443), rejectUnauthorized: false });
      socket.once("secureConnect", () => {
        const der = socket.getPeerCertificate(false)?.raw;
        if (!der || createHash("sha256").update(der).digest("hex") !== pin) {
          const error = new Error(`Relay ${target.host} certificate does not match its on-chain pin`);
          socket.destroy(error);
          return ready(error);
        }
        return ready(null, socket);
      });
      socket.once("error", (error) => ready(error));
      return undefined;
    },
  };
}

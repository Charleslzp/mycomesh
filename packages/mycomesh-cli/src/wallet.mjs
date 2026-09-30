// The Consumer's owner wallet: an Ethereum V3 keystore (the format MetaMask and geth import),
// so the key that holds the deposit never sits in a plaintext file.
import { createCipheriv, createDecipheriv, randomBytes, scryptSync, pbkdf2Sync, randomUUID } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { addressOf, keccak } from "./eip712.mjs";

const SCRYPT = { n: 1 << 15, r: 8, p: 1, dklen: 32 };

export function encryptKeystore(privateKey, password) {
  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const derived = scryptSync(Buffer.from(password, "utf8"), salt, SCRYPT.dklen,
    { N: SCRYPT.n, r: SCRYPT.r, p: SCRYPT.p, maxmem: 128 * SCRYPT.n * SCRYPT.r * 2 });
  const cipher = createCipheriv("aes-128-ctr", derived.subarray(0, 16), iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(privateKey.replace(/^0x/, ""), "hex")), cipher.final()]);
  return {
    version: 3, id: randomUUID(), address: addressOf(privateKey).slice(2),
    crypto: {
      cipher: "aes-128-ctr", cipherparams: { iv: iv.toString("hex") }, ciphertext: ciphertext.toString("hex"),
      kdf: "scrypt", kdfparams: { ...SCRYPT, salt: salt.toString("hex") },
      mac: keccak(Buffer.concat([derived.subarray(16, 32), ciphertext])).toString("hex"),
    },
  };
}

export function decryptKeystore(keystore, password) {
  const crypto = keystore.crypto || keystore.Crypto;
  if (keystore.version !== 3 || crypto?.cipher !== "aes-128-ctr") throw new Error("unsupported keystore");
  const params = crypto.kdfparams;
  const salt = Buffer.from(params.salt, "hex");
  const secret = Buffer.from(password, "utf8");
  let derived;
  if (crypto.kdf === "scrypt") {
    derived = scryptSync(secret, salt, params.dklen, { N: params.n, r: params.r, p: params.p, maxmem: 128 * params.n * params.r * 2 });
  } else if (crypto.kdf === "pbkdf2" && params.prf === "hmac-sha256") {
    derived = pbkdf2Sync(secret, salt, params.c, params.dklen, "sha256");
  } else {
    throw new Error(`unsupported keystore KDF ${crypto.kdf}`);
  }
  const ciphertext = Buffer.from(crypto.ciphertext, "hex");
  const mac = keccak(Buffer.concat([derived.subarray(16, 32), ciphertext])).toString("hex");
  if (mac !== crypto.mac.toLowerCase()) throw new Error("wrong wallet password");
  const decipher = createDecipheriv("aes-128-ctr", derived.subarray(0, 16), Buffer.from(crypto.cipherparams.iv, "hex"));
  const privateKey = `0x${Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("hex")}`;
  if (keystore.address && addressOf(privateKey).slice(2) !== keystore.address.toLowerCase().replace(/^0x/, "")) {
    throw new Error("keystore address does not match its key");
  }
  return privateKey;
}

/** Password from MYCOMESH_WALLET_PASSWORD, else a muted terminal prompt. */
export async function password(prompt, { confirm = false } = {}) {
  if (process.env.MYCOMESH_WALLET_PASSWORD) return process.env.MYCOMESH_WALLET_PASSWORD;
  if (!process.stdin.isTTY) throw new Error("set MYCOMESH_WALLET_PASSWORD or run in a terminal");
  const ask = (label) => new Promise((resolve, reject) => {
    process.stderr.write(label);
    const input = [];
    process.stdin.setRawMode(true);
    process.stdin.resume();
    const onData = (chunk) => {
      for (const char of chunk.toString("utf8")) {
        if (char === "\r" || char === "\n") { done(); return resolve(input.join("")); }
        if (char === "\u0003") { done(); return reject(new Error("cancelled")); }
        if (char === "\u007f") input.pop(); else input.push(char);
      }
    };
    const done = () => { process.stdin.setRawMode(false); process.stdin.pause(); process.stdin.off("data", onData); process.stderr.write("\n"); };
    process.stdin.on("data", onData);
  });
  const first = await ask(prompt);
  if (first.length < 8) throw new Error("use a wallet password of at least 8 characters");
  if (confirm && (await ask("Repeat the password: ")) !== first) throw new Error("passwords differ");
  return first;
}

export const walletPath = (dir) => join(dir, "owner-wallet.json");

export async function createWallet(dir, secret) {
  const path = walletPath(dir);
  if (existsSync(path)) return JSON.parse(readFileSync(path, "utf8"));
  if (secret !== undefined && String(secret).length < 8) throw new Error("use a wallet password of at least 8 characters");
  const keystore = encryptKeystore(`0x${randomBytes(32).toString("hex")}`,
    secret ?? await password("New wallet password (protects your deposit): ", { confirm: true }));
  writeFileSync(path, `${JSON.stringify(keystore, null, 2)}\n`, { mode: 0o600 });
  chmodSync(path, 0o600);
  return keystore;
}

export const walletAddress = (keystore) => `0x${keystore.address.toLowerCase().replace(/^0x/, "")}`;

/** The owner key: --owner-key-file (raw hex or a keystore), else this machine's wallet. */
export async function ownerKey(file, dir) {
  const path = file || walletPath(dir);
  if (!existsSync(path)) throw new Error("no owner wallet; run `mycomesh-consumer init` or pass --owner-key-file");
  const text = readFileSync(path, "utf8").trim();
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(text)) return text.startsWith("0x") ? text : `0x${text}`;
  return decryptKeystore(JSON.parse(text), await password("Wallet password: "));
}

export function ownerAddress(file, dir) {
  const path = file || walletPath(dir);
  if (!existsSync(path)) return null;
  const text = readFileSync(path, "utf8").trim();
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(text)) return addressOf(text.startsWith("0x") ? text : `0x${text}`);
  return walletAddress(JSON.parse(text));
}

/** Unlock this machine's wallet with a password given by the local console. */
export function unlockWallet(dir, secret) {
  const path = walletPath(dir);
  if (!existsSync(path)) throw new Error("no owner wallet yet");
  return decryptKeystore(JSON.parse(readFileSync(path, "utf8")), String(secret ?? ""));
}

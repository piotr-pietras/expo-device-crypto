#!/usr/bin/env node
/**
 * Encrypt UTF-8 text for an expo-device-crypto ECIES_P256_AES256_GCM key.
 *
 * Uses Node's built-in crypto (no npm install). Compatible with
 * DeviceCrypto.decrypt when peerPublicKey is the ephemeral public key
 * printed below.
 *
 * Scheme, matching Android DeviceCrypto and iOS CryptoKit:
 *   1. Ephemeral P-256 key pair
 *   2. ECDH with the recipient SPKI public key (shared secret = X coordinate)
 *   3. HKDF-SHA256, 32-byte zero salt, empty info, 32-byte AES key
 *   4. AES-256-GCM, 12-byte IV, 16-byte tag
 *   Payload: base64( IV || ciphertext || tag )
 *
 * Usage:
 *   node examples/ecies-encrypt.js
 *   node examples/ecies-encrypt.js <public-key> [plaintext]
 *
 * Public key: BASE64 SPKI from getPublicKey({ format: "BASE64" }),
 * or the default PEM from getPublicKey().
 */

const crypto = require("crypto");
const readline = require("readline");

function parsePublicKey(input) {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("Public key is empty.");
  }

  if (trimmed.includes("BEGIN")) {
    return crypto.createPublicKey(trimmed);
  }

  const der = Buffer.from(trimmed.replace(/\s+/g, ""), "base64");
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

function encrypt(recipientPublicKey, ephemeralPrivateKey, plaintext) {
  const sharedSecret = crypto.diffieHellman({
    privateKey: ephemeralPrivateKey,
    publicKey: recipientPublicKey,
  });

  const aesKey = Buffer.from(
    crypto.hkdfSync("sha256", sharedSecret, Buffer.alloc(32), Buffer.alloc(0), 32)
  );

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(plaintext, "utf8")),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, ciphertext, tag]).toString("base64");
}

function exportSpkiBase64(publicKey) {
  return publicKey.export({ format: "der", type: "spki" }).toString("base64");
}

function createInterface() {
  return readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
}

function readPublicKey(rl) {
  return new Promise((resolve) => {
    console.log(
      "Recipient public key (BASE64 SPKI, or PEM — paste every line):"
    );
    const lines = [];

    const onLine = (line) => {
      if (lines.length === 0 && line.trim() === "") return;
      lines.push(line);

      const done =
        line.includes("END PUBLIC KEY") ||
        (lines.length === 1 && !line.includes("BEGIN"));

      if (!done) return;
      rl.off("line", onLine);
      resolve(lines.join("\n"));
    };

    rl.on("line", onLine);
  });
}

function readPlaintext(rl) {
  return new Promise((resolve) => {
    rl.question("Plaintext to encrypt (empty line to quit): ", resolve);
  });
}

async function main() {
  const argKey = process.argv[2];
  const argPlaintext = process.argv[3];

  let recipientInput = argKey;
  let rl;

  if (!recipientInput) {
    rl = createInterface();
    recipientInput = await readPublicKey(rl);
  }

  const recipient = parsePublicKey(recipientInput);
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const ephemeralPublicKey = exportSpkiBase64(publicKey);

  console.log("");
  console.log("Ephemeral public key (pass as peerPublicKey to decrypt):");
  console.log(ephemeralPublicKey);
  console.log("");

  if (argPlaintext !== undefined) {
    console.log(encrypt(recipient, privateKey, argPlaintext));
    rl?.close();
    return;
  }

  rl ??= createInterface();

  for (;;) {
    const plaintext = await readPlaintext(rl);
    if (plaintext === "") break;
    console.log(encrypt(recipient, privateKey, plaintext));
  }

  rl.close();
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});

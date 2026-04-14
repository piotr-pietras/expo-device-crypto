import DeviceCrypto, { SigningAlgorithm } from "expo-device-crypto";

const alias = "user-signing-key";
const payload = "Sign this challenge payload";
const algorithmType = SigningAlgorithm.ECDSA_SECP256R1_SHA256;

// 1) Generate an auth-protected ECDSA key pair
await DeviceCrypto.generateKeyPair(alias, {
  algorithmType,
});

// 2) Optional: share public key with backend
const publicKeyPem = DeviceCrypto.getPublicKey(alias);

// 3) Sign with private key
// Note: The data to sign must be in UTF-8 format.
const signature = await DeviceCrypto.sign(alias, payload, {
  algorithmType,
});

// 5) Verify locally (usually done server-side with stored public key)
const isValid = await DeviceCrypto.verify(alias, payload, signature ?? "", {
  algorithmType,
});

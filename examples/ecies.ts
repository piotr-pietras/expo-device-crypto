import DeviceCrypto, { EncryptionAlgorithm } from "expo-device-crypto";

const alias1 = "ecies-alice";
const alias2 = "ecies-bob";
const dataToEncrypt = "Sensitive data";
const algorithmType = EncryptionAlgorithm.ECIES_P256_AES256_GCM;

// 1) Each party generates their own EC key pair
await DeviceCrypto.generateKeyPair(alias1, { algorithmType });
await DeviceCrypto.generateKeyPair(alias2, { algorithmType });

// 2) Exchange public keys
const pk1 =
  (await DeviceCrypto.getPublicKey(alias1, { format: "BASE64" })) ?? "";
const pk2 =
  (await DeviceCrypto.getPublicKey(alias2, { format: "BASE64" })) ?? "";

// 3) Alice encrypts for Bob: ECDH(priv1, pub2)
const encrypted = await DeviceCrypto.encrypt(alias1, dataToEncrypt, {
  algorithmType,
  peerPublicKey: pk2,
});

// 4) Bob decrypts: ECDH(priv2, pub1) — same shared secret
// Note: Data to decrypt must be in Base64 format.
const decrypted = await DeviceCrypto.decrypt(alias2, encrypted ?? "", {
  algorithmType,
  peerPublicKey: pk1,
});

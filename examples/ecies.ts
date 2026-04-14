import DeviceCrypto, {
  AuthCheckResult,
  AuthMethod,
  EncryptionAlgorithm,
} from "expo-device-crypto";

const alias = "user-encryption-key";
const dataToEncrypt = "Sensitive data";
const algorithmType = EncryptionAlgorithm.ECIES_P256_AES256_GCM;

// 1) Generate an auth-protected EC key pair
await DeviceCrypto.generateKeyPair(alias, {
  algorithmType,
  requireAuthentication: true,
});

// 2) Share own public key with the entity you want to encrypt data for
const publicKey = DeviceCrypto.getPublicKey(alias);
await fetch("somewhere.com", {
  method: "POST",
  body: JSON.stringify({ publicKey }),
});

// 3) Retrieve peer public key of the entity you want to encrypt data for
const peerPublicKey = await fetch("somewhere.com").then((res) => res.json());

// 4) Encrypt with public key
const encrypted = await DeviceCrypto.encrypt(alias, dataToEncrypt, {
  algorithmType,
  peerPublicKey,
});

// 5) Decrypt with private key
// Note: Data to decrypt must be in Base64 format.
const decrypted = await DeviceCrypto.decrypt(alias, encrypted ?? "", {
  algorithmType,
  peerPublicKey,
});

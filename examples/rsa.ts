import DeviceCrypto, {
  AuthCheckResult,
  AuthMethod,
  EncryptionAlgorithm,
} from "expo-device-crypto";

const alias = "user-encryption-key";
const dataToEncrypt = "Sensitive data";
const algorithmType = EncryptionAlgorithm.RSA_2048_OAEP_SHA1;

// 1) Generate an auth-protected RSA key pair
await DeviceCrypto.generateKeyPair(alias, {
  algorithmType,
});

// 2) Optional: retrieve/share public key with backend
const publicKeyPem = DeviceCrypto.getPublicKey(alias);

// 3) Encrypt with public key
const encrypted = await DeviceCrypto.encrypt(alias, dataToEncrypt, {
  algorithmType,
});

// 4) Decrypt with private key
// Note: Data to decrypt must be in Base64 format.
const decrypted = await DeviceCrypto.decrypt(alias, encrypted ?? "", {
  algorithmType,
});

import DeviceCrypto, {
  AuthCheckResult,
  AuthMethod,
  EncryptionAlgorithm,
} from "expo-device-crypto";

const alias = "user-encryption-key";
const dataToEncrypt = "Sensitive data";
const algorithmType = EncryptionAlgorithm.RSA_2048_OAEP_SHA1;
const authMethod = AuthMethod.PASSCODE_OR_BIOMETRIC;

// 1) Ensure device authentication is configured (passcode at minimum)
const authStatus = DeviceCrypto.isAuthCheckAvailable();
if (authStatus !== AuthCheckResult.AVAILABLE) {
  throw new Error(`Authentication unavailable: ${authStatus}`);
}

// 2) Generate an auth-protected RSA key pair
await DeviceCrypto.generateKeyPair(alias, {
  algorithmType,
  requireAuthentication: true,
  authMethod, // iOS: defined at key generation;
});

// 3) Optional: retrieve/share public key with backend
const publicKeyPem = DeviceCrypto.getPublicKey(alias);

// 4) Encrypt with public key
const encrypted = await DeviceCrypto.encrypt(alias, dataToEncrypt, {
  algorithmType,
});

// 5) Decrypt with private key
// Note: Data to decrypt must be in Base64 format.
// Note: This function should display the system user authentication prompt.
const decrypted = await DeviceCrypto.decrypt(alias, encrypted ?? "", {
  algorithmType,
  authMethod, // Android: defined when decrypting
});
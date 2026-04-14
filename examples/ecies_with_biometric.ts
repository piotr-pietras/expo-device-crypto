import DeviceCrypto, {
  AuthCheckResult,
  AuthMethod,
  EncryptionAlgorithm,
} from "expo-device-crypto";

const alias = "user-encryption-key";
const dataToEncrypt = "Sensitive data";
const algorithmType = EncryptionAlgorithm.ECIES_P256_AES256_GCM;
const authMethod = AuthMethod.PASSCODE_OR_BIOMETRIC;

// 1) Ensure device authentication is configured (passcode at minimum)
const authStatus = DeviceCrypto.isAuthCheckAvailable();
if (authStatus !== AuthCheckResult.AVAILABLE) {
  throw new Error(`Authentication unavailable: ${authStatus}`);
}

// 2) Generate an auth-protected EC key pair
await DeviceCrypto.generateKeyPair(alias, {
  algorithmType,
  requireAuthentication: true,
  authMethod, // iOS: defined at key generation;
});

// 3) Share own public key with the entity you want to encrypt data for
const publicKey = DeviceCrypto.getPublicKey(alias);
await fetch("somewhere.com", {
  method: "POST",
  body: JSON.stringify({ publicKey }),
});

// 4) Retrieve peer public key of the entity you want to encrypt data for
const peerPublicKey = await fetch("somewhere.com").then((res) => res.json());

// 5) Encrypt with public key
// Note: This function should display the system user authentication prompt.
const encrypted = await DeviceCrypto.encrypt(alias, dataToEncrypt, {
  algorithmType,
  peerPublicKey,
  authMethod, // Android: Unlike RSA, ECIES requires authentication for both encryption and decryption.
});

// 6) Decrypt with private key
// Note: Data to decrypt must be in Base64 format.
// Note: This function should display the system user authentication prompt.
const decrypted = await DeviceCrypto.decrypt(alias, encrypted ?? "", {
  algorithmType,
  authMethod, // Android: defined when decrypting
  peerPublicKey,
});

import DeviceCrypto, {
  AuthCheckResult,
  AuthMethod,
  EncryptionAlgorithm,
} from "expo-device-crypto";

const alias1 = "ecies-alice";
const alias2 = "ecies-bob";
const dataToEncrypt = "Sensitive data";
const algorithmType = EncryptionAlgorithm.ECIES_P256_AES256_GCM;
const authMethod = AuthMethod.PASSCODE_OR_BIOMETRIC;

// 1) Ensure device authentication is configured (passcode at minimum)
const authStatus = DeviceCrypto.isAuthCheckAvailable();
if (authStatus !== AuthCheckResult.AVAILABLE) {
  throw new Error(`Authentication unavailable: ${authStatus}`);
}

// 2) Each party generates an auth-protected EC key pair
await DeviceCrypto.generateKeyPair(alias1, {
  algorithmType,
  requireAuthentication: true,
  authMethod, // iOS: defined at key generation
});
await DeviceCrypto.generateKeyPair(alias2, {
  algorithmType,
  requireAuthentication: true,
  authMethod,
});

// 3) Exchange public keys
const pk1 =
  (await DeviceCrypto.getPublicKey(alias1, { format: "BASE64" })) ?? "";
const pk2 =
  (await DeviceCrypto.getPublicKey(alias2, { format: "BASE64" })) ?? "";

// 4) Alice encrypts for Bob: ECDH(priv1, pub2)
// Note: This function should display the system user authentication prompt.
const encrypted = await DeviceCrypto.encrypt(alias1, dataToEncrypt, {
  algorithmType,
  peerPublicKey: pk2,
  authMethod, // Android: ECIES requires auth for encrypt and decrypt
});

// 5) Bob decrypts: ECDH(priv2, pub1) — same shared secret
// Note: Data to decrypt must be in Base64 format.
// Note: This function should display the system user authentication prompt.
const decrypted = await DeviceCrypto.decrypt(alias2, encrypted ?? "", {
  algorithmType,
  peerPublicKey: pk1,
  authMethod,
});

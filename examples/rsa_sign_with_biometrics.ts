import DeviceCrypto, {
  AuthCheckResult,
  AuthMethod,
  SigningAlgorithm,
} from "expo-device-crypto";

const alias = "user-signing-key";
const payload = "Sign this challenge payload";
const algorithmType = SigningAlgorithm.SHA256withRSA;
const authMethod = AuthMethod.PASSCODE_OR_BIOMETRIC;

// 1) Ensure device authentication is configured (passcode at minimum)
const authStatus = DeviceCrypto.isAuthCheckAvailable();
if (authStatus !== AuthCheckResult.AVAILABLE) {
  throw new Error(`Authentication unavailable: ${authStatus}`);
}

// 2) Generate an auth-protected ECDSA key pair
await DeviceCrypto.generateKeyPair(alias, {
  requireAuthentication: true,
  authMethod, // iOS: defined at key generation;
  algorithmType,
});

// 3) Optional: share public key with backend
const publicKeyPem = DeviceCrypto.getPublicKey(alias);

// 4) Sign with private key
// Note: The data to sign must be in UTF-8 format.
// Note: This function should display the system user authentication prompt.
const signature = await DeviceCrypto.sign(alias, payload, {
  algorithmType,
  authMethod, // Android: defined when signing
});

// 5) Verify locally (usually done server-side with stored public key)
const isValid = await DeviceCrypto.verify(alias, payload, signature ?? "", {
  algorithmType,
});

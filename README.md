## `expo-device-crypto`

> ⚠️ This module is currently in beta and is not suitable for production use.

🔒 Hardware-backed cryptography for Expo apps using [Android Keystore](https://developer.android.com/privacy-and-security/keystore)/[Strong Box](https://developer.android.com/privacy-and-security/keystore#StrongBoxKeyMint) and Apple [Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)/[Keychain](https://developer.apple.com/documentation/security/keychain-services).

## Installation

```bash
npx expo install expo-device-crypto
```

If you want to allow Face ID on iOS, add this to your app config:

```json
{
  "expo": {
    "ios": {
      "infoPlist": {
        "NSFaceIDUsageDescription": "We use Face ID to protect your cryptographic keys."
      }
    }
  }
}
```

## Supported Algorithms

### ✍️ Signature Algorithms

- `ECDSA_SECP256R1_SHA256`

  **Curve:** P-256 / secp256r1. </br>
  **Hash:** SHA-256. </br>

### 🔐 Encryption Algorithms

- `RSA_2048_PKCS1`

  **Key size:** 2048 bits. </br>
  **Padding:** PKCS#1 v1.5. </br>

- `RSA_2048_OAEP_SHA1`

  **Key size:** 2048 bits. </br>
  **Padding:** OAEP with SHA-1 and MGF1. </br>

- `ECIES_P256_AES256_GCM`

  **Curve:** P-256 (secp256r1). </br>
  **Symmetric cipher:** AES-256-GCM. </br>
  **Key derivation:** HKDF-SHA256 (32-byte key from ECDH shared secret). </br>

**More coming soon...**

## Example

### RSA with Biometric

```ts
import DeviceCrypto, {
  AuthCheckResult,
  AuthMethod,
  EncryptionAlgorithm,
} from "expo-device-crypto";

const alias = "user-encryption-key";
const dataToEncrypt = "Sensitive data";
const algorithmType = EncryptionAlgorithm.RSA_2048_PKCS1;
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
const decrypted = await DeviceCrypto.decrypt(alias, encrypted, {
  algorithmType,
  authMethod, // Android: defined when decrypting
});
```

> ⚠️ Because iOS Keychain/Secure Enclave binds authentication policy to key creation, `authMethod` must be set in `generateKeyPair`. On Android Keystore, authentication is applied at key usage time, so `authMethod` is provided in operations like `sign` and `decrypt`.

### 📚 More examples

You can find additional usage examples in the [`examples` directory](https://github.com/piotr-pietras/expo-device-crypto/tree/master/examples) of the main repository.

### 🛠️ Methods

- `isAuthCheckAvailable(): AuthCheckResult`
  - Returns device authentication availability (`AVAILABLE`, `NO_HARDWARE`, `UNAVAILABLE`).

- `generateKeyPair(alias: string, options?: GenerateKeyPairOptions): Promise<GenerateKeyPairResult>`
  - Creates a key pair for `alias` if it does not exist.
  - Defaults: `requireAuthentication = false`, `authMethod = PASSCODE_OR_BIOMETRIC`.

- `getPublicKey(alias: string, options?: GetPublicKeyOptions): string | null`
  - Returns public key in PEM format (or `null` if alias not found).
  - Defaults: `format = "PEM"`.

- `removeKeyPair(alias: string): boolean`
  - Removes the key pair for the alias.

- `aliases(): string[]`
  - Lists stored key aliases.

- `sign(alias: string, data: string, options?: SignOptions): Promise<string | null>`
  - Signs UTF-8 `data` with private key.
  - Defaults: `algorithmType = ECDSA_SECP256R1_SHA256`, `promptTitle = "Unlock"`, `promptSubtitle = "Enter your PIN to continue"`, `authMethod = PASSCODE_OR_BIOMETRIC`.

- `verify(alias: string, data: string, signature: string, options?: VerifyOptions): Promise<boolean | null>`
  - Verifies signature for UTF-8 `data`.
  - Signature must be in Base64 format.
  - Default: `algorithmType = ECDSA_SECP256R1_SHA256`.

- `encrypt(alias: string, data: string, options?: EncryptOptions): Promise<string | null>`
  - Encrypts UTF-8 `data` with public key.
  - Default: `algorithmType = RSA_2048_PKCS1`.
  - For `algorithmType = ECIES_P256_AES256_GCM`, `peerPublicKey` is required in `options`.

- `decrypt(alias: string, data: string, options?: DecryptOptions): Promise<string | null>`
  - Decrypts Base64 `data` with private key.
  - Defaults: `algorithmType = RSA_2048_PKCS1`, `promptTitle = "Unlock"`, `promptSubtitle = "Enter your PIN to continue"`, `authMethod = PASSCODE_OR_BIOMETRIC`.
  - For `algorithmType = ECIES_P256_AES256_GCM`, `peerPublicKey` is required in `options`.

**Android only methods**

- `isStrongBoxAvailable(): boolean`
  - Returns `true` if StrongBox Keystore is supported on the device.

## ⚠️ Important

### Enable Strong Box on Android

Use `preferStrongBox: true` when generating a key pair to request [StrongBox-backed](https://developer.android.com/privacy-and-security/keystore#StrongBoxKeyMint) key storage when the device supports it.

```ts
import DeviceCrypto, { SigningAlgorithm } from "expo-device-crypto";

const alias = "user-signing-key";

// Optional: check availability first.
const hasStrongBox = DeviceCrypto.isStrongBoxAvailable();

await DeviceCrypto.generateKeyPair(alias, {
  algorithmType: SigningAlgorithm.ECDSA_SECP256R1_SHA256,
  preferStrongBox: true,
});
```

If StrongBox is not available, Android falls back to the Trusted Execution Environment (TEE).

### Secure Enclave support on iOS

On iOS, only ECDSA keys can use the [Secure Enclave processor](https://developer.apple.com/documentation/security/ksecattrtokenidsecureenclave?utm_source=chatgpt.com#Discussion). RSA private-key operations are software-backed and handled by Apple’s system cryptographic services, which still provide strong isolation and protection.

### ECIES - EC encryption schema

For library purposes, ECIES is referred to as an encryption algorithm for simplification, even though it is technically a broader encryption scheme.

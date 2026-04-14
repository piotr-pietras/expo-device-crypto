export enum GenerateKeyPairResult {
  KEY_PAIR_GENERATED = "KEY_PAIR_GENERATED",
  KEY_PAIR_ALREADY_EXISTS = "KEY_PAIR_ALREADY_EXISTS",
  NOT_AVAILABLE = "NOT_AVAILABLE",
}

export enum AuthCheckResult {
  AVAILABLE = "AVAILABLE",
  NO_HARDWARE = "NO_HARDWARE",
  UNAVAILABLE = "UNAVAILABLE",
}

export enum AuthMethod {
  PASSCODE = "PASSCODE",
  PASSCODE_OR_BIOMETRIC = "PASSCODE_OR_BIOMETRIC",
}

export enum SigningAlgorithm {
  ECDSA_SECP256R1_SHA256 = "ECDSA_SECP256R1_SHA256",
}

type EciesAlgorithm = "ECIES_P256_AES256_GCM";
type RsaAlgorithm = "RSA_2048_PKCS1" | "RSA_2048_OAEP_SHA1";
export enum EncryptionAlgorithm {
  RSA_2048_PKCS1 = "RSA_2048_PKCS1",
  RSA_2048_OAEP_SHA1 = "RSA_2048_OAEP_SHA1",
  ECIES_P256_AES256_GCM = "ECIES_P256_AES256_GCM",
}

export type GenerateKeyPairOptions = {
  /**
   * The algorithm type of the key to generate.
   */
  algorithmType: SigningAlgorithm | EncryptionAlgorithm;
  /**
   * Whether to require authentication to sign.
   * Setting this to true will prompt biometric or passcode authentication before signing.
   *
   * Please check the *`isAuthCheckAvailable`* function to see if authentication is available.
   * If authentication is not available, generating a key pair will throw an error.
   * @default false
   */
  requireAuthentication?: boolean;
  /**
   * The method of authentication to use.
   * Note that on Android you have to define it when signing or decrypting.
   *
   * If you want to allow to use Face ID, you need to add the following to your app.json config file:
   * ```json
   * "ios": {
   *   "infoPlist": {
   *     "NSFaceIDUsageDescription": "We use Face ID to secure your data.",
   *   }
   * }
   * ```
   * @default AuthMethod.PASSCODE_OR_BIOMETRIC
   * @platform ios 🍏
   */
  authMethod?: AuthMethod;
  /**
   * If the Strong Box is available, it will be used instead of the Trusted Execution Environment (TEE).
   * @default false
   * @platform android 🤖
   */
  preferStrongBox?: boolean;
}

type BaseAuthOptions = {
  /**
   * The title of the prompt to show when authentication is required.
   * @default "Unlock"
   * @platform android 🤖
   */
  promptTitle?: string;
  /**
   * The subtitle of the prompt to show when authentication is required.
   * @default "Enter your PIN to continue"
   * @platform android 🤖
   */
  promptSubtitle?: string;
  /**
   * The method of authentication to use.
   * Note that on iOS you have to define it when generating the key pair.
   * @default AuthMethod.PASSCODE_OR_BIOMETRIC
   * @platform android 🤖
   */
  authMethod?: AuthMethod;
}

type BaseSigningOptions = {
  /**
   * The algorithm type of the key to use for signing.
   */
  algorithmType: SigningAlgorithm;
};
type BaseVerifyOptions = BaseSigningOptions;

type BaseRsaEncryptionOptions = {
  /**
   * The algorithm type of the key to use for encrypting.
   */
  algorithmType: RsaAlgorithm;
};
type BaseRsaDecryptionOptions = BaseRsaEncryptionOptions;

type BaseEciesEncryptionOptions = {
  /**
   * The algorithm type of the key to use for encrypting.
   */
  algorithmType: EciesAlgorithm;
  /**
   * The peer public key to use for ECIES.
   */
  peerPublicKey: string;
};
type BaseEciesDecryptionOptions = BaseEciesEncryptionOptions;

export type SignOptions = BaseAuthOptions & BaseSigningOptions;
export type VerifyOptions = BaseVerifyOptions;

export type DecryptOptions =
  | (BaseAuthOptions & BaseEciesDecryptionOptions)
  | (BaseAuthOptions & BaseRsaDecryptionOptions);
export type EncryptOptions =
  | (BaseAuthOptions & BaseEciesEncryptionOptions)
  | BaseRsaEncryptionOptions;

export interface GetPublicKeyOptions {
  /**
   * The format of the public key to return.
   * @default "PEM" (Base64 of PEM-encoded SubjectPublicKeyInfo (SPKI) for P‑256)
   */
  format?: "PEM" | "BASE64";
}

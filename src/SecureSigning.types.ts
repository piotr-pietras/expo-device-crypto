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

export interface GenerateKeyPairOptions {
  /**
   * Whether to require authentication to sign.
   * Setting this to true will prompt biometric or passcode authentication before signing.
   *
   * Please check the *`isAuthCheckAvailable`* function to see if authentication is available.
   * If authentication is not available, generating a key pair will throw an error.
   * @default false
   */
  requireAuthentication?: boolean;
}

export enum SignMethod {
  PASSCODE = "PASSCODE",
  PASSCODE_OR_BIOMETRIC = "PASSCODE_OR_BIOMETRIC",
}

export interface SignOptions {
  /**
   * If your keychain requires authentication to sign, set this to true.
   *
   * **Important:**
   * Please note that ios cannot implicitly verify if the existing keychain needs authentication.
   * To unify interface for all platforms, you need to set this to true if you called *`generateKeyPair`*
   * with *`requireAuthentication`* option set to true for a desired key pair alias.
   * @default false
   */
  requireAuthentication?: boolean;
  /**
   * The title of the prompt to show when authentication is required.
   * @default "Unlock"
   * @platform android
   */
  promptTitle?: string;
  /**
   * The subtitle of the prompt to show when authentication is required.
   * @default "Enter your PIN to continue"
   * @platform android
   */
  promptSubtitle?: string;
  /**
   * The method of authentication to use.
   * @default SignMethod.PASSCODE_OR_BIOMETRIC
   * @platform android
   */
  authMethod?: SignMethod;
}
export interface GetPublicKeyOptions {
  /**
   * The format of the public key to return.
   * @default "DER" (Base64 of DER-encoded SubjectPublicKeyInfo (SPKI) for P‑256)
   */
  format?: "DER" | "PEM";
}

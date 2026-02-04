import { NativeModule, requireNativeModule } from 'expo';

import { GenerateKeyPairResult } from './SecureSigning.types';

declare class SecureSigningModule extends NativeModule {
  generateKeyPair(alias: string): GenerateKeyPairResult;
  getPublicKey(alias: string): string | null;
  removeKeyPair(alias: string): boolean;
  aliases(): string[];
  sign(alias: string, data: string): string;
  verify(alias: string, data: string, signature: string): boolean | null;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<SecureSigningModule>('SecureSigning');
export type { GenerateKeyPairResult };

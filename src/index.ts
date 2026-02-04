// Reexport the native module. On web, it will be resolved to CryptoHardwareModule.web.ts
// and on native platforms to CryptoHardwareModule.ts
export { default } from './SecureSigningModule';
export * from './SecureSigning.types';

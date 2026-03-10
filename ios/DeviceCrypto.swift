import ExpoModulesCore
import Security
import Foundation
import LocalAuthentication

enum SecureSigningModuleResult: String {
  case KEY_PAIR_GENERATED = "KEY_PAIR_GENERATED"
  case KEY_PAIR_ALREADY_EXISTS = "KEY_PAIR_ALREADY_EXISTS"
  case NOT_AVAILABLE = "NOT_AVAILABLE"
}

enum AuthCheckResult: String {
  case AVAILABLE = "AVAILABLE"
  case NO_HARDWARE = "NO_HARDWARE"
  case UNAVAILABLE = "UNAVAILABLE"
}

enum AuthMethod: String {
  case PASSCODE = "PASSCODE"
  case PASSCODE_OR_BIOMETRIC = "PASSCODE_OR_BIOMETRIC"
}

enum AlgorithmType: String {
  case ECDSA_SECP256R1_SHA256 = "ECDSA_SECP256R1_SHA256"
  case RSA_2048_PKCS1 = "RSA_2048_PKCS1"
}

public class DeviceCryptoModule: Module {
  private func toiOSAlgo(algorithm: AlgorithmType) -> SecKeyAlgorithm {
    switch algorithm {
    case .ECDSA_SECP256R1_SHA256:
      return .ecdsaSignatureMessageX962SHA256
    case .RSA_2048_PKCS1:
      return .rsaEncryptionPKCS1
    }
  }

  // Converts ANSI x962 EC point to P‑256 SPKI DER format
  private func x962ECPointToP256SPKI(_ publicKey: SecKey) -> Data? {
    var error: Unmanaged<CFError>?
    guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
      return nil
    }

    guard raw.count == 65 else { return nil }
    let prefix = Data([
      0x30, 0x59,
      0x30, 0x13,
      0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
      0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
      0x03, 0x42, 0x00
    ])
    return prefix + raw
  }

  private func isAuthCheckAvailable() -> String {
    let context = LAContext()
    let available = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    if available {
      return AuthCheckResult.AVAILABLE.rawValue
    } else {
      return AuthCheckResult.UNAVAILABLE.rawValue
    }
  }

  private func getAliases() -> [String] {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecMatchLimit as String: kSecMatchLimitAll,
      kSecReturnAttributes as String: true,
    ]

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else { return [] }

    let items = (result as? [[String: Any]]) ?? []
    return items.compactMap { attrs in
      let tagKey = kSecAttrApplicationTag as String
      if let tagString = attrs[tagKey] as? String {
        return tagString
      }
      return nil
    }
  }

  private func getSecKeyQuery(_ alias: String) -> [String: Any] {
    return [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: alias,
      kSecReturnRef as String: true,
    ]
  }

  private func getSecKeyByAlias(_ alias: String) -> SecKey? {
    let query: [String: Any] = self.getSecKeyQuery(alias)
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess else { return nil }
    return (item as! SecKey)
  }

  private func retrievePublicKey(_ secKey: SecKey) -> String? {
    let publicKey = SecKeyCopyPublicKey(secKey)!

    let attrs = SecKeyCopyAttributes(secKey)!
    if attrs == kSecAttrKeyTypeECSECPrimeRandom {
      return x962ECPointToP256SPKI(publicKey)?.base64EncodedString()
    } else {
      guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
        return nil
      }
      return publicKeyData.base64EncodedString()
    }
  }

  private func removeKeyStoreEntry(_ alias: String) -> Bool {
    let secKey = self.getSecKeyByAlias(alias)
    if secKey == nil { return false }

    let query = self.getSecKeyQuery(alias)
    let status = SecItemDelete(query as CFDictionary)
    return status == errSecSuccess
  }

  private func buildECDSA_SECP256R1_SHA256(alias: String, reqAuth: Bool, authMethod: AuthMethod) -> SecKey? {
    let accessFlags: SecAccessControlCreateFlags
    if reqAuth {
      switch authMethod {
        case .PASSCODE:
          accessFlags = [.privateKeyUsage, .devicePasscode]
        case .PASSCODE_OR_BIOMETRIC:
          accessFlags = [.privateKeyUsage, .userPresence]
        default:
          accessFlags = .privateKeyUsage
      }
    } else {
      accessFlags = .privateKeyUsage
    }

    let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      accessFlags,
      nil
    ) 

    let attributes: NSDictionary = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits: 256,
      kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs: [
          kSecAttrIsPermanent: true,
          kSecAttrApplicationTag: alias,
          kSecAttrAccessControl: access
      ]
    ]

    return SecKeyCreateRandomKey(attributes, nil)
  }

  private func buildRSA_2048_PKCS1(alias: String, reqAuth: Bool, authMethod: AuthMethod) -> SecKey? {
    let accessFlags: SecAccessControlCreateFlags
    if reqAuth {
      switch authMethod {
        case .PASSCODE:
          accessFlags = [.devicePasscode]
        case .PASSCODE_OR_BIOMETRIC:
          accessFlags = [.userPresence]
        default:
          accessFlags = []
      }
    } else {
      accessFlags = []
    }

    let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      accessFlags,
      nil
    ) 

    let attributes: NSDictionary = [
      kSecAttrKeyType: kSecAttrKeyTypeRSA,
      kSecAttrKeySizeInBits: 2048,
      kSecPrivateKeyAttrs: [
          kSecAttrIsPermanent: true,
          kSecAttrApplicationTag: alias,
          kSecAttrAccessControl: access
      ]
    ]

    return SecKeyCreateRandomKey(attributes, nil)
  }

  public func definition() -> ModuleDefinition {

    Name("DeviceCrypto")

    Function("isAuthCheckAvailable") { () -> String in
      return self.isAuthCheckAvailable()
    }

    Function("generateKeyPair") { (alias: String, o: [String: Any]) -> String in
      let reqAuth = o["reqAuth"] as! Bool
      let authMethod = AuthMethod(rawValue: o["authMethod"] as! String)
      let algoType = AlgorithmType(rawValue: o["algoType"] as! String)

      if reqAuth && self.isAuthCheckAvailable() != AuthCheckResult.AVAILABLE.rawValue {
        throw NSError(
          domain: "DeviceCrypto",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "NO_AUTH_AVAILABLE"]
        )
      }

      let secKey = self.getSecKeyByAlias(alias)
      if secKey != nil {
        return SecureSigningModuleResult.KEY_PAIR_ALREADY_EXISTS.rawValue
      }

      switch algoType {
        case .ECDSA_SECP256R1_SHA256:
          self.buildECDSA_SECP256R1_SHA256(alias: alias, reqAuth: reqAuth, authMethod: authMethod!)
        case .RSA_2048_PKCS1:
          self.buildRSA_2048_PKCS1(alias: alias, reqAuth: reqAuth, authMethod: authMethod!)
        default:
          throw NSError(
            domain: "DeviceCrypto",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: "INVALID_ALGORITHM_TYPE"]
          )
      }

      return SecureSigningModuleResult.KEY_PAIR_GENERATED.rawValue
    }

    Function("removeKeyPair") { (alias: String) -> Bool in
      return self.removeKeyStoreEntry(alias)
    }

    Function("aliases") { () -> [String] in
      return self.getAliases()
    }

    Function("getPublicKey") { (alias: String) -> String? in
      let secKey = self.getSecKeyByAlias(alias)
      guard let secKey else { return nil }
      return self.retrievePublicKey(secKey)
    }

    AsyncFunction("sign") { (alias: String, data: String, o: [String: Any]) -> String? in
      let secKey = self.getSecKeyByAlias(alias)
      guard let secKey else { return nil }

      let algoType = AlgorithmType(rawValue: o["algoType"] as! String)
      let algo = self.toiOSAlgo(algorithm: algoType!)

      var signingError: Unmanaged<CFError>?
      let signatureCF = SecKeyCreateSignature(
        secKey,
        algo,
        Data(data.utf8) as CFData,
        &signingError
      )

      if let error = signingError?.takeRetainedValue() {
        throw error as Error
      }

      guard let signatureCF else { return nil }
      let signature = signatureCF as Data
      return signature.base64EncodedString()
    }

    Function("verify") { (alias: String, data: String, signature: String, o: [String: Any]) -> Bool? in
      let secKey = self.getSecKeyByAlias(alias)
      guard let secKey else { return nil }

      guard let publicKey = SecKeyCopyPublicKey(secKey) else { return nil }
      guard let signatureData = Data(base64Encoded: signature) else { return nil }

      let algoType = AlgorithmType(rawValue: o["algoType"] as! String)
      let algo = self.toiOSAlgo(algorithm: algoType!)

      let valid = SecKeyVerifySignature(
        publicKey,
        algo,
        Data(data.utf8) as CFData,
        signatureData as CFData,
        nil
      )
      return valid
    }

    AsyncFunction("encrypt") { (alias: String, data: String, o: [String: Any]) -> String? in
      let secKey = self.getSecKeyByAlias(alias)
      guard let secKey else { return nil }
      let publicKey = SecKeyCopyPublicKey(secKey)!

      let algoType = AlgorithmType(rawValue: o["algoType"] as! String)
      let algo = self.toiOSAlgo(algorithm: algoType!)

      guard let encrypted = SecKeyCreateEncryptedData(
        publicKey,
        algo,
        Data(data.utf8) as CFData,
        nil
      ) as Data? else {
        return nil
      }

      return encrypted.base64EncodedString()
    }

    AsyncFunction("decrypt") { (alias: String, data: String, o: [String: Any]) -> String? in
      let secKey = self.getSecKeyByAlias(alias)
      guard let secKey else { return nil }
      guard let encryptedData = Data(base64Encoded: data) else { return nil }

      let algoType = AlgorithmType(rawValue: o["algoType"] as! String)
      let algo = self.toiOSAlgo(algorithm: algoType!)

      guard let decrypted = SecKeyCreateDecryptedData(
        secKey,
        algo,
        encryptedData as CFData,
        nil
      ) as Data? else {
        return nil
      }

      return String(data: decrypted, encoding: .utf8)
    }
  }
}

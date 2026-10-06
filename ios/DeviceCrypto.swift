import ExpoModulesCore
import Security
import Foundation
import LocalAuthentication
import CryptoKit

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
  case RSA_2048_OAEP_SHA1 = "RSA_2048_OAEP_SHA1"
  case RSA_4096_PKCS1 = "RSA_4096_PKCS1"
  case RSA_4096_OAEP_SHA1 = "RSA_4096_OAEP_SHA1"
  case ECIES_P256_AES256_GCM = "ECIES_P256_AES256_GCM"
  case RSA_SHA256 = "RSA_SHA256"
  case RSA_SHA256_PSS = "RSA_SHA256_PSS"
  case RSA_4096_SHA256 = "RSA_4096_SHA256"
  case RSA_4096_SHA256_PSS = "RSA_4096_SHA256_PSS"
}

public class DeviceCryptoModule: Module {
  private func toiOSAlgo(algorithm: AlgorithmType) -> SecKeyAlgorithm {
    switch algorithm {
    case .ECDSA_SECP256R1_SHA256:
      return .ecdsaSignatureMessageX962SHA256
    case .RSA_2048_PKCS1:
      return .rsaEncryptionPKCS1
    case .RSA_2048_OAEP_SHA1:
      return .rsaEncryptionOAEPSHA1
    case .RSA_4096_PKCS1:
      return .rsaEncryptionPKCS1
    case .RSA_4096_OAEP_SHA1:
      return .rsaEncryptionOAEPSHA1
    case .ECIES_P256_AES256_GCM:
      return .eciesEncryptionCofactorX963SHA256AESGCM
    case .RSA_SHA256:
      return .rsaSignatureMessagePKCS1v15SHA256
    case .RSA_SHA256_PSS:
      return .rsaSignatureMessagePSSSHA256
    case .RSA_4096_SHA256:
      return .rsaSignatureMessagePKCS1v15SHA256
    case .RSA_4096_SHA256_PSS:
      return .rsaSignatureMessagePSSSHA256
    }
  }

  private func getSecKeyQuery(_ alias: String, keyClass: CFString, returnRef: Bool = true) -> [String: Any] {
    var query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrApplicationTag as String: alias,
      kSecAttrKeyClass as String: keyClass,
    ]
    if returnRef {
      query[kSecReturnRef as String] = true
    }
    return query
  }

  private func getSecKeyByAlias(_ alias: String, keyClass: CFString) -> SecKey? {
    let query: [String: Any] = self.getSecKeyQuery(alias, keyClass: keyClass)
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess else { return nil }
    return (item as! SecKey)
  }

  private func buildECDSA(alias: String, reqAuth: Bool, authMethod: AuthMethod) -> SecKey? {
    let accessFlags: SecAccessControlCreateFlags
    if reqAuth {
      switch authMethod {
        case .PASSCODE:
          accessFlags = [.privateKeyUsage, .devicePasscode]
        case .PASSCODE_OR_BIOMETRIC:
          accessFlags = [.privateKeyUsage, .userPresence]
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
      ],
      kSecPublicKeyAttrs: [
          kSecAttrIsPermanent: true,
          kSecAttrApplicationTag: alias
      ]
    ]

    return SecKeyCreateRandomKey(attributes, nil)
  }

  private func buildRSA(alias: String, keySize: Int, reqAuth: Bool, authMethod: AuthMethod) -> SecKey? {
    let accessFlags: SecAccessControlCreateFlags
    if reqAuth {
      switch authMethod {
        case .PASSCODE:
          accessFlags = [.devicePasscode]
        case .PASSCODE_OR_BIOMETRIC:
          accessFlags = [.userPresence]
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
      kSecAttrKeySizeInBits: keySize,
      kSecPrivateKeyAttrs: [
          kSecAttrIsPermanent: true,
          kSecAttrApplicationTag: alias,
          kSecAttrAccessControl: access
      ],
      kSecPublicKeyAttrs: [
          kSecAttrIsPermanent: true,
          kSecAttrApplicationTag: alias
      ]
    ]

    return SecKeyCreateRandomKey(attributes, nil)
  }

  private func buildECIES(alias: String, reqAuth: Bool, authMethod: AuthMethod) -> SecKey? {
    let accessFlags: SecAccessControlCreateFlags
    if reqAuth {
      switch authMethod {
        case .PASSCODE:
          accessFlags = [.privateKeyUsage, .devicePasscode]
        case .PASSCODE_OR_BIOMETRIC:
          accessFlags = [.privateKeyUsage, .userPresence]
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
      ],
      kSecPublicKeyAttrs: [
        kSecAttrIsPermanent: true,
        kSecAttrApplicationTag: alias
      ]
    ]

    return SecKeyCreateRandomKey(attributes, nil)
  }

  private func secKeyFromPeerPublicKey(_ peerPublicKey: String) -> SecKey? {
    guard
      let peerPublicKeyData = Data(base64Encoded: peerPublicKey),
      let x962 = spkiP256ToX962(peerPublicKeyData)
    else {
      return nil
    }

    let attrs: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
      kSecAttrKeySizeInBits as String: 256
    ]

    return SecKeyCreateWithData(x962 as CFData, attrs as CFDictionary, nil)
  }

  private func deriveSharedSecret(privateKey: SecKey, peerPublicKey: String) -> Data? {
    guard let peerSecKey = secKeyFromPeerPublicKey(peerPublicKey) else { return nil }
    let algorithm = SecKeyAlgorithm.ecdhKeyExchangeStandard
    guard SecKeyIsAlgorithmSupported(privateKey, .keyExchange, algorithm) else { return nil }

    let params: [String: Any] = [:]
    return SecKeyCopyKeyExchangeResult(
      privateKey,
      algorithm,
      peerSecKey,
      params as CFDictionary,
      nil
    ) as Data?
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

  private func generateKeyPair(alias: String, o: [String: Any]) throws -> String {
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

    let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPublic)
    if secKey != nil {
      return SecureSigningModuleResult.KEY_PAIR_ALREADY_EXISTS.rawValue
    }

    switch algoType {
      case .ECDSA_SECP256R1_SHA256:
        self.buildECDSA(alias: alias, reqAuth: reqAuth, authMethod: authMethod!)
      case .RSA_2048_PKCS1:
        self.buildRSA(alias: alias, keySize: 2048, reqAuth: reqAuth, authMethod: authMethod!)
      case .RSA_2048_OAEP_SHA1:
        self.buildRSA(alias: alias, keySize: 2048, reqAuth: reqAuth, authMethod: authMethod!)
      case .RSA_4096_PKCS1:
        self.buildRSA(alias: alias, keySize: 4096, reqAuth: reqAuth, authMethod: authMethod!)
      case .RSA_4096_OAEP_SHA1:
        self.buildRSA(alias: alias, keySize: 4096, reqAuth: reqAuth, authMethod: authMethod!)
      case .ECIES_P256_AES256_GCM:
        self.buildECIES(alias: alias, reqAuth: reqAuth, authMethod: authMethod!)
      case .RSA_SHA256:
        self.buildRSA(alias: alias, keySize: 2048, reqAuth: reqAuth, authMethod: authMethod!)
      case .RSA_SHA256_PSS:
        self.buildRSA(alias: alias, keySize: 2048, reqAuth: reqAuth, authMethod: authMethod!)
      case .RSA_4096_SHA256:
        self.buildRSA(alias: alias, keySize: 4096, reqAuth: reqAuth, authMethod: authMethod!)
      case .RSA_4096_SHA256_PSS:
        self.buildRSA(alias: alias, keySize: 4096, reqAuth: reqAuth, authMethod: authMethod!)
      default:
        throw NSError(
          domain: "DeviceCrypto",
          code: 1,
          userInfo: [NSLocalizedDescriptionKey: "INVALID_ALGORITHM_TYPE"]
        )
    }

    return SecureSigningModuleResult.KEY_PAIR_GENERATED.rawValue
  }

  private func removeKeyStoreEntry(_ alias: String) -> Bool {
    let privateQuery = self.getSecKeyQuery(alias, keyClass: kSecAttrKeyClassPrivate, returnRef: false)
    let privateStatus = SecItemDelete(privateQuery as CFDictionary)

    let publicQuery = self.getSecKeyQuery(alias, keyClass: kSecAttrKeyClassPublic, returnRef: false)
    let publicStatus = SecItemDelete(publicQuery as CFDictionary)

    return privateStatus == errSecSuccess || publicStatus == errSecSuccess
  }

  private func getAliases() -> [String] {
    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
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

  private func getPublicKey(alias: String) -> String? {
    let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPublic)
    guard let secKey else { return nil }

    let publicKey = SecKeyCopyPublicKey(secKey)!

    guard
      let attrs = SecKeyCopyAttributes(publicKey) as? [String: Any],
      let keyType = attrs[kSecAttrKeyType as String] as? String
    else {
      return nil
    }

    if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
      return x962ECPointToP256SPKI(publicKey)?.base64EncodedString()
    }

    if keyType == (kSecAttrKeyTypeRSA as String) {
      return rsaPKCS1ToSPKI(publicKey)?.base64EncodedString()
    }

    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
      return nil
    }
    return publicKeyData.base64EncodedString()
  }

  private func sign(alias: String, data: String, o: [String: Any]) throws -> String? {
    let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPrivate)
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

  private func verify(alias: String, data: String, signature: String, o: [String: Any]) -> Bool? {
    let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPublic)
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

  private func encrypt(alias: String, data: String, o: [String: Any]) throws -> String? {
    let algoType = AlgorithmType(rawValue: o["algoType"] as! String)

    if algoType == .ECIES_P256_AES256_GCM {
      let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPrivate)
      guard let secKey else { return nil }
      let peerPublicKey = o["peerPublicKey"] as! String
      let sharedSecret = deriveSharedSecret(privateKey: secKey, peerPublicKey: peerPublicKey)
      guard let sharedSecret else { return nil }

      let symmetricKey = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: sharedSecret),
        outputByteCount: 32
      )
      let sealed = try AES.GCM.seal(Data(data.utf8), using: symmetricKey)
      return sealed.combined!.base64EncodedString()
    }

    let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPublic)
    guard let secKey else { return nil }
    let publicKey = SecKeyCopyPublicKey(secKey)!
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

  private func decrypt(alias: String, data: String, o: [String: Any]) throws -> String? {
    let secKey = self.getSecKeyByAlias(alias, keyClass: kSecAttrKeyClassPrivate)
    guard let secKey else { return nil }
    guard let encryptedData = Data(base64Encoded: data) else { return nil }

    let algoType = AlgorithmType(rawValue: o["algoType"] as! String)

    if algoType == .ECIES_P256_AES256_GCM {
      let peerPublicKey = o["peerPublicKey"] as! String
      let sharedSecret = deriveSharedSecret(privateKey: secKey, peerPublicKey: peerPublicKey)
      guard let sharedSecret else { return nil }

      let symmetricKey = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: sharedSecret),
        outputByteCount: 32
      )
      let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
      let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey)
      return String(data: decrypted, encoding: .utf8)
    }

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

  public func definition() -> ModuleDefinition {

    Name("DeviceCrypto")

    Function("isAuthCheckAvailable") { () -> String in
      return self.isAuthCheckAvailable()
    }

    Function("generateKeyPair") { (alias: String, o: [String: Any]) -> String in
      return try self.generateKeyPair(alias: alias, o: o)
    }

    Function("removeKeyPair") { (alias: String) -> Bool in
      return self.removeKeyStoreEntry(alias)
    }

    Function("aliases") { () -> [String] in
      return self.getAliases()
    }

    Function("getPublicKey") { (alias: String) -> String? in
      return self.getPublicKey(alias:alias)
    }

    AsyncFunction("sign") { (alias: String, data: String, o: [String: Any]) -> String? in
      return try self.sign(alias: alias, data: data, o: o)
    }

    Function("verify") { (alias: String, data: String, signature: String, o: [String: Any]) -> Bool? in
      return self.verify(alias: alias, data: data, signature: signature, o: o)
    }

    AsyncFunction("encrypt") { (alias: String, data: String, o: [String: Any]) -> String? in
      return try self.encrypt(alias: alias, data: data, o: o)
    }

    AsyncFunction("decrypt") { (alias: String, data: String, o: [String: Any]) -> String? in
      return try self.decrypt(alias: alias, data: data, o: o)
    }
  }
}

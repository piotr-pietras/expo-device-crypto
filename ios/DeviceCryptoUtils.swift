import Foundation
import Security

/// Converts ANSI x9.62 EC point to P-256 SPKI DER format.
func x962ECPointToP256SPKI(_ publicKey: SecKey) -> Data? {
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
    0x03, 0x42, 0x00,
  ])
  return prefix + raw
}

/// Converts PKCS#1 RSA public key bytes to SPKI DER format.
func rsaPKCS1ToSPKI(_ publicKey: SecKey) -> Data? {
  guard let pkcs1 = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
    return nil
  }

  // rsaEncryption OID: 1.2.840.113549.1.1.1 with NULL params
  let algorithmIdentifier = Data([
    0x30, 0x0D,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    0x05, 0x00,
  ])

  let bitStringPayload = Data([0x00]) + pkcs1
  guard let bitString = asn1Wrap(tag: 0x03, content: bitStringPayload) else {
    return nil
  }

  return asn1Wrap(tag: 0x30, content: algorithmIdentifier + bitString)
}

/// Wraps ASN.1 content with a tag and length.
func asn1Wrap(tag: UInt8, content: Data) -> Data? {
  guard let length = asn1Length(content.count) else {
    return nil
  }
  return Data([tag]) + length + content
}

/// Converts a length to ASN.1 length format.
func asn1Length(_ length: Int) -> Data? {
  if length < 0x80 {
    return Data([UInt8(length)])
  }

  var value = length
  var bytes: [UInt8] = []
  while value > 0 {
    bytes.insert(UInt8(value & 0xff), at: 0)
    value >>= 8
  }

  guard bytes.count <= 4 else {
    return nil
  }

  return Data([0x80 | UInt8(bytes.count)]) + Data(bytes)
}

/// Converts P-256 SPKI DER format to ANSI x9.62 EC point format.
func spkiP256ToX962(_ spki: Data) -> Data? {
  let prefix = Data([
    0x30, 0x59,
    0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00,
  ])
  guard spki.count == prefix.count + 65 else { return nil }
  guard spki.starts(with: prefix) else { return nil }
  return spki.suffix(65)
}


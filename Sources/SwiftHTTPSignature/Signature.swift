import CryptoSwift
import CryptorRSA

#if canImport(Foundation)
  import Foundation
#endif

struct Signature {
  typealias Signer = (_ path: String, _ method: String, _ headers: KeyValuePairs<String, String>) throws -> Signature

  enum Algorithm {
    case hmacSHA1(key: String)
    case hmacSHA256(key: String)
    case hmacSHA512(key: String)
    case rsaSHA256(pem: String)
    case rsaSHA512(pem: String)

    var name: String {
      switch self {
      case .hmacSHA1: return "hmac-sha1"
      case .hmacSHA256: return "hmac-sha256"
      case .hmacSHA512: return "hmac-sha512"
      #if canImport(CryptorRSA)
        case .rsaSHA256: return "rsa-sha256"
        case .rsaSHA512: return "rsa-sha512"
      #endif
      }
    }
  }

  let headerValue: String
  let signingString: String
  let signature: String

  #if canImport(Foundation)
//    init(algorithm: Algorithm, keyID: String, request: URLRequest, headers: [String] = ["Date"]) throws {
//      var keyValuePairs: KeyValuePairs<String, String> = [:]
//      request.allHTTPHeaderFields?.filter { headers.contains($0.key) }.forEach { keyValuePairs[$0.key] = $0.value }
//      try self.init(algorithm: algorithm, keyID: keyID, url: request.url!, method: request.httpMethod!, headers: keyValuePairs)
//    }

    init(algorithm: Algorithm, keyID: String, url: URL, method: String, headers: KeyValuePairs<String, String>) throws {
      try self.init(algorithm: algorithm, keyID: keyID, path: url.path, method: method, headers: headers)
    }
  #endif

  init(algorithm: Algorithm, keyID: String, path: String, method: String, headers: KeyValuePairs<String, String>) throws {
    let headers = Headers(headers)
    signingString = "(request-target): \(method.lowercased()) \(path)\n\(headers.entries)"

    switch algorithm {
    case .hmacSHA1(let key):
      signature = try HMAC(key: key, variant: .sha1).authenticate(signingString.bytes).toBase64()!
    case .hmacSHA256(let key):
      signature = try HMAC(key: key, variant: .sha256).authenticate(signingString.bytes).toBase64()!
    case .hmacSHA512(let key):
      signature = try HMAC(key: key, variant: .sha512).authenticate(signingString.bytes).toBase64()!
    case .rsaSHA256(let pem):
      let privateKey = try CryptorRSA.createPrivateKey(withPEM: pem)
      signature = try CryptorRSA.createPlaintext(with: signingString, using: .utf8).signed(with: privateKey, algorithm: .sha256)!.base64String
    case .rsaSHA512(let pem):
      let privateKey = try CryptorRSA.createPrivateKey(withPEM: pem)
      signature = try CryptorRSA.createPlaintext(with: signingString, using: .utf8).signed(with: privateKey, algorithm: .sha512)!.base64String
    }

    headerValue = [
      "keyId=\"\(keyID)\"",
      "algorithm=\"\(algorithm.name)\"",
      "headers=\"(request-target) \(headers.uniqueKeys(joinedBy: " ").lowercased())\"",
      "signature=\"\(signature)\""
    ].joined(separator: ",")
  }

  static func signer(algorithm: Signature.Algorithm, keyID: String) -> Signer {
    return { (path: String, method: String, headers: KeyValuePairs<String, String>) -> Signature in
      return try Signature(algorithm: algorithm, keyID: keyID, path: path, method: method, headers: headers)
    }
  }
}

private struct Headers {
  private var headers: KeyValuePairs<String, String>

  init(_ headers: KeyValuePairs<String, String>) {
    self.headers = headers
  }

  /// Returns all unique header keys
  var uniqueKeys: [String] {
    return headers.map { $0.key }.unique
  }

  var entries: String {
    return uniqueKeys.map(colonSeparatedEntry).joined(separator: "\n")
  }

  func uniqueKeys(joinedBy separator: String) -> String {
    return uniqueKeys.map { $0.lowercased() }.joined(separator: separator)
  }

  /// Returns all values for the given header key, separated by the given separator.
  func allValues(forHeader key: String, joinedBy separator: String) -> String {
    return headers.filter { $0.key == key }.map { $0.value }.joined(separator: separator)
  }

  /// Returns a "key: value1, value2" string for the given header key.
  func colonSeparatedEntry(forHeader key: String) -> String {
    return "\(key.lowercased().trimmingCharacters(in: .whitespaces)): \(allValues(forHeader: key, joinedBy: ", "))"
  }
}

private extension Array where Element: Equatable {
  var unique: [Element] {
    var uniqueValues: [Element] = []
    forEach { item in
      if !uniqueValues.contains(item) {
        uniqueValues += [item]
      }
    }
    return uniqueValues
  }
}

# SwiftHTTPSignature

Generates signatures according to https://tools.ietf.org/html/draft-cavage-http-signatures-10

## Usage

Generate a signature as follows:

```swift
// Create the signature
let signature = try! Signature(
  algorithm: .hmacSHA256(key: "secret key"),
  keyID: "Test",
  path: "/foo?param=value&pet=dog",
  method: "POST",
  headers: [
    "Host": "example.com",
    "Date": "Sun, 05 Jan 2014 21:31:40 GMT",
    "Content-Type": "application/json",
    "Digest": "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
    "Content-Length": "18"
  ]
)

signature.headerValue // Returns the value to put in the HTTP `Signature` header
signature.signature // Returns just the generated signature
```

You can also use a `Signer` that acts as a signature factory. This is useful if you need to generate multiple signatures, for example as middleware.

```swift
let createSignature = Signature.signer(algorithm: .hmacSHA256(key: "secret key"), keyID: "Test")
let signature = createSignature("/foo?param=value&pet=dog", "POST", [
  "Host": "example.com",
  "Date": "Sun, 05 Jan 2014 21:31:40 GMT",
  "Content-Type": "application/json",
  "Digest": "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=",
  "Content-Length": "18"
]) 
```

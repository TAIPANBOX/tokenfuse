import CryptoKit
import Foundation

// Client-side of the signed-mutation protocol (docs/14 §4.2). A device holds a
// P-256 key — in the Secure Enclave on a real device, a software key in the
// simulator (the server can't and needn't tell them apart). ES256 signatures
// (raw r‖s) over the canonical string are what authorize a kill or a budget.

/// A device signing key, abstracting Secure Enclave vs software. `Sendable` so a
/// freshly generated key can be returned from the (nonisolated) pairing call to
/// the main actor under Swift 6 — CryptoKit's P-256 keys are themselves Sendable.
protocol DeviceKey: Sendable {
    /// Public key, SEC1/X9.63 (65 bytes) — sent at pairing as base64.
    var publicKeyX963: Data { get }
    /// ES256 signature (raw 64-byte r‖s) over `data` (which is SHA-256'd inside).
    func sign(_ data: Data) throws -> Data
    /// (kind, material) for Keychain persistence.
    func persist() -> (kind: String, material: Data)
}

struct SoftwareDeviceKey: DeviceKey {
    let key: P256.Signing.PrivateKey
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(_ data: Data) throws -> Data { try key.signature(for: data).rawRepresentation }
    func persist() -> (kind: String, material: Data) { ("software", key.rawRepresentation) }
}

struct EnclaveDeviceKey: DeviceKey {
    let key: SecureEnclave.P256.Signing.PrivateKey
    var publicKeyX963: Data { key.publicKey.x963Representation }
    func sign(_ data: Data) throws -> Data { try key.signature(for: data).rawRepresentation }
    func persist() -> (kind: String, material: Data) { ("enclave", key.dataRepresentation) }
}

enum DeviceKeyFactory {
    /// A fresh key — Enclave-backed when available, otherwise software.
    static func generate() throws -> DeviceKey {
        if SecureEnclave.isAvailable {
            return EnclaveDeviceKey(key: try SecureEnclave.P256.Signing.PrivateKey())
        }
        return SoftwareDeviceKey(key: P256.Signing.PrivateKey())
    }

    static func restore(kind: String, material: Data) throws -> DeviceKey {
        switch kind {
        case "enclave":
            return EnclaveDeviceKey(key: try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: material))
        default:
            return SoftwareDeviceKey(key: try P256.Signing.PrivateKey(rawRepresentation: material))
        }
    }
}

/// The exact string the client signs, matching `crates/cloud`'s
/// `devices::canonical_string`: `{METHOD}\n{PATH}\n{sha256(body) hex}\n{TS}\n{NONCE}`.
enum Canonical {
    static func string(method: String, path: String, body: Data, ts: Int, nonce: String) -> String {
        let hex = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
        return "\(method)\n\(path)\n\(hex)\n\(ts)\n\(nonce)"
    }
}

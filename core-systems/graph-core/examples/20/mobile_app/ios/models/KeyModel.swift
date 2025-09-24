import Foundation
import CryptoKit

struct KeyModel: Identifiable, Codable, Equatable, Hashable {

    // MARK: - Core Fields
    let id: UUID
    var name: String
    var value: String
    var tags: [String]
    var createdAt: Date
    var updatedAt: Date

    // MARK: - Security Metadata
    var ownerID: String
    var accessLevel: AccessLevel
    var isRevoked: Bool
    var digitalSignature: String?

    // MARK: - Audit Trail
    var lastAccessed: Date?
    var accessCount: Int

    // MARK: - AI Intent Control
    var isAIControlled: Bool
    var intentPolicy: IntentPolicy?

    // MARK: - Computed Properties
    var isActive: Bool {
        return !isRevoked && Date() < expirationDate
    }

    var expirationDate: Date {
        Calendar.current.date(byAdding: .day, value: 90, to: createdAt) ?? createdAt
    }

    var shortID: String {
        id.uuidString.prefix(8).description
    }

    // MARK: - Signing (Zero Trust)
    mutating func signWithPrivateKey(_ key: Curve25519.Signing.PrivateKey) {
        let payload = "\(id.uuidString)-\(ownerID)-\(value)"
        let signature = try? key.signature(for: Data(payload.utf8))
        self.digitalSignature = signature?.base64EncodedString()
    }

    func verifySignature(using publicKey: Curve25519.Signing.PublicKey) -> Bool {
        guard let signatureBase64 = digitalSignature,
              let signatureData = Data(base64Encoded: signatureBase64) else {
            return false
        }

        let payload = "\(id.uuidString)-\(ownerID)-\(value)"
        return (try? publicKey.isValidSignature(signatureData, for: Data(payload.utf8))) ?? false
    }

    // MARK: - Factory
    static func empty(for userID: String) -> KeyModel {
        KeyModel(
            id: UUID(),
            name: "",
            value: "",
            tags: [],
            createdAt: Date(),
            updatedAt: Date(),
            ownerID: userID,
            accessLevel: .user,
            isRevoked: false,
            digitalSignature: nil,
            lastAccessed: nil,
            accessCount: 0,
            isAIControlled: false,
            intentPolicy: nil
        )
    }
}

// MARK: - Access Control Levels
enum AccessLevel: String, Codable, CaseIterable {
    case admin, user, readonly

    var description: String {
        switch self {
        case .admin: return "Admin"
        case .user: return "User"
        case .readonly: return "Read-Only"
        }
    }
}

// MARK: - AI Intent Policy Model
struct IntentPolicy: Codable, Hashable {
    let allowExport: Bool
    let allowDeletion: Bool
    let allowOverwrite: Bool
    let allowAIReadAccess: Bool

    static var strict: IntentPolicy {
        IntentPolicy(allowExport: false, allowDeletion: false, allowOverwrite: false, allowAIReadAccess: false)
    }

    static var permissive: IntentPolicy {
        IntentPolicy(allowExport: true, allowDeletion: true, allowOverwrite: true, allowAIReadAccess: true)
    }
}

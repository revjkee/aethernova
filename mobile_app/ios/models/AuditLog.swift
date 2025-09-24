import Foundation
import CryptoKit

struct AuditLog: Identifiable, Codable, Equatable, Hashable {

    // MARK: - Identity
    let id: UUID
    let timestamp: Date

    // MARK: - Event Description
    var title: String
    var details: String
    var category: LogCategory
    var severity: LogSeverity
    var actorID: String
    var origin: LogOrigin

    // MARK: - AI & Ethics
    var wasAIInitiated: Bool
    var intentReference: String?
    var ethicsEvaluated: Bool
    var ethicsViolationDetected: Bool

    // MARK: - Context & Security
    var deviceFingerprint: String?
    var ipAddress: String?
    var locationHint: String?
    var tokenHash: String? // anonymized token hash (e.g., session/fingerprint)

    // MARK: - Signature
    var digitalSignature: String?

    // MARK: - Computed
    var shortID: String {
        id.uuidString.prefix(8).description
    }

    // MARK: - Signing / Verification
    mutating func signLog(using privateKey: Curve25519.Signing.PrivateKey) {
        let raw = "\(id.uuidString)-\(actorID)-\(category.rawValue)-\(timestamp.timeIntervalSince1970)"
        let signature = try? privateKey.signature(for: Data(raw.utf8))
        self.digitalSignature = signature?.base64EncodedString()
    }

    func verifySignature(publicKey: Curve25519.Signing.PublicKey) -> Bool {
        guard let base64 = digitalSignature,
              let sigData = Data(base64Encoded: base64) else { return false }

        let raw = "\(id.uuidString)-\(actorID)-\(category.rawValue)-\(timestamp.timeIntervalSince1970)"
        return (try? publicKey.isValidSignature(sigData, for: Data(raw.utf8))) ?? false
    }

    // MARK: - Factory
    static func generate(
        title: String,
        details: String,
        actorID: String,
        category: LogCategory,
        severity: LogSeverity,
        origin: LogOrigin,
        aiIntent: String? = nil,
        ethicsFlag: Bool = false
    ) -> AuditLog {
        AuditLog(
            id: UUID(),
            timestamp: Date(),
            title: title,
            details: details,
            category: category,
            severity: severity,
            actorID: actorID,
            origin: origin,
            wasAIInitiated: aiIntent != nil,
            intentReference: aiIntent,
            ethicsEvaluated: true,
            ethicsViolationDetected: ethicsFlag,
            deviceFingerprint: SessionManager.shared.deviceFingerprint,
            ipAddress: SessionManager.shared.currentIP,
            locationHint: SessionManager.shared.approxLocation,
            tokenHash: SessionManager.shared.sessionTokenHash,
            digitalSignature: nil
        )
    }
}

import Foundation
import CryptoKit

struct AgentIntent: Identifiable, Codable, Equatable, Hashable {

    // MARK: - Core Identity
    let id: UUID
    let timestamp: Date

    // MARK: - Description
    var title: String
    var description: String
    var source: IntentSource
    var priority: IntentPriority
    var intentType: IntentType

    // MARK: - Execution
    var parameters: [String: String]
    var shouldAutoExecute: Bool
    var requiresUserConfirmation: Bool
    var isSandboxed: Bool

    // MARK: - Policy & Ethics
    var policy: IntentPolicy
    var ethicsEvaluated: Bool
    var ethicsViolation: Bool

    // MARK: - Agent Metadata
    var agentID: String?
    var originatingUserID: String?

    // MARK: - Security & Signature
    var digitalSignature: String?

    // MARK: - Computed
    var shortID: String {
        id.uuidString.prefix(8).description
    }

    // MARK: - Signing
    mutating func sign(using privateKey: Curve25519.Signing.PrivateKey) {
        let payload = "\(id.uuidString)-\(title)-\(intentType.rawValue)-\(timestamp.timeIntervalSince1970)"
        let sig = try? privateKey.signature(for: Data(payload.utf8))
        self.digitalSignature = sig?.base64EncodedString()
    }

    func verify(using publicKey: Curve25519.Signing.PublicKey) -> Bool {
        guard let base64 = digitalSignature,
              let sigData = Data(base64Encoded: base64) else {
            return false
        }

        let payload = "\(id.uuidString)-\(title)-\(intentType.rawValue)-\(timestamp.timeIntervalSince1970)"
        return (try? publicKey.isValidSignature(sigData, for: Data(payload.utf8))) ?? false
    }

    // MARK: - Factory
    static func create(
        title: String,
        description: String,
        type: IntentType,
        source: IntentSource,
        priority: IntentPriority = .normal,
        parameters: [String: String] = [:],
        policy: IntentPolicy = .default,
        sandboxed: Bool = true,
        confirm: Bool = true,
        userID: String? = nil,
        agentID: String? = nil
    ) -> AgentIntent {
        AgentIntent(
            id: UUID(),
            timestamp: Date(),
            title: title,
            description: description,
            source: source,
            priority: priority,
            intentType: type,
            parameters: parameters,
            shouldAutoExecute: !confirm,
            requiresUserConfirmation: confirm,
            isSandboxed: sandboxed,
            policy: policy,
            ethicsEvaluated: false,
            ethicsViolation: false,
            agentID: agentID,
            originatingUserID: userID,
            digitalSignature: nil
        )
    }
}

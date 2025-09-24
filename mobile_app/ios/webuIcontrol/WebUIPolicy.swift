import Foundation
import OSLog

final class WebUIPolicy {

    // MARK: - Singleton
    static let shared = WebUIPolicy()

    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "WebUIPolicy")

    // MARK: - Access Configuration
    private(set) var trustedDomains: Set<String> = [
        "app.teslaai.io",
        "webui.teslaai.local",
        "control-node.local"
    ]

    private(set) var allowedRoles: Set<UserRole> = [.admin, .analyst, .engineer]

    private(set) var permittedIntents: Set<AgentIntent.IntentType> = [
        .viewLogs,
        .accessVault,
        .launchWebControl
    ]

    private let ethics = EthicsEngine.shared

    // MARK: - Evaluation Interface
    func isDomainTrusted(_ url: URL) -> Bool {
        guard let host = url.host else { return false }
        let result = trustedDomains.contains(where: { host.contains($0) })
        if !result {
            logger.warning("Untrusted WebUI domain attempt: \(host)")
        }
        return result
    }

    func isIntentAllowed(_ intent: AgentIntent, forRole role: UserRole) -> Bool {
        guard permittedIntents.contains(intent.intentType) else {
            logger.error("Intent \(intent.intentType.rawValue) blocked: not in permitted set")
            return false
        }

        guard allowedRoles.contains(role) else {
            logger.fault("Intent rejected: role \(role.rawValue) not authorized")
            return false
        }

        guard ethics.evaluateIntent(intent) else {
            logger.critical("EthicsEngine blocked intent: \(intent.intentType.rawValue)")
            return false
        }

        if !intent.verify(using: SessionManager.shared.publicKey) {
            logger.fault("Intent rejected: invalid signature")
            return false
        }

        return true
    }

    func updateTrustedDomains(_ newDomains: [String]) {
        trustedDomains = Set(newDomains)
        logger.info("Trusted domains updated: \(trustedDomains.joined(separator: ", "))")
    }

    func updatePermittedIntents(_ newIntents: [AgentIntent.IntentType]) {
        permittedIntents = Set(newIntents)
        logger.info("Permitted intents updated")
    }

    func updateAllowedRoles(_ newRoles: [UserRole]) {
        allowedRoles = Set(newRoles)
        logger.info("Allowed roles updated")
    }
}

// MARK: - User Role Enum
enum UserRole: String, Codable, CaseIterable {
    case admin
    case engineer
    case analyst
    case viewer
    case restricted
}

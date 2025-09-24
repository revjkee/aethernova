import Foundation
import OSLog

final class EthicsEngine {

    // MARK: - Singleton
    static let shared = EthicsEngine()

    // MARK: - Internal State
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "EthicsEngine")
    private let policy = EthicsPolicy.default
    private var lastViolations: [EthicsViolation] = []
    private var userOverrideWhitelist: Set<String> = []

    // MARK: - Public Entry Point
    func evaluateIntent(_ intent: AgentIntent) -> Bool {
        guard policy.enabled else {
            logger.info("Ethics disabled: allowing all intents")
            return true
        }

        // System override
        if userOverrideWhitelist.contains(intent.intentType.rawValue) {
            logger.notice("Override whitelist bypass for \(intent.intentType.rawValue)")
            return true
        }

        // Check against explicit deny list
        if policy.blockedIntents.contains(intent.intentType) {
            logViolation(.blockedIntent(intent.intentType))
            return false
        }

        // Check source origin
        if !policy.trustedOrigins.contains(intent.source) {
            logViolation(.untrustedSource(intent.source))
            return false
        }

        // Check confidence & context
        if intent.confidence < policy.minimumConfidence {
            logViolation(.lowConfidence(intent.intentType, intent.confidence))
            return false
        }

        // Check time or state policy
        if !policy.timeWindow.isCurrentAllowed {
            logViolation(.blockedByTimeWindow)
            return false
        }

        logger.debug("Intent passed ethics: \(intent.intentType.rawValue)")
        return true
    }

    func allowSensor(_ type: SensorType) -> Bool {
        guard policy.enabled else { return true }

        switch type {
        case .motion:
            return policy.allowMotion
        case .camera:
            return policy.allowCamera
        case .microphone:
            return policy.allowMicrophone
        }
    }

    func logViolation(_ violation: EthicsViolation) {
        logger.fault("Ethics Violation: \(violation.description)")
        lastViolations.append(violation)
        if lastViolations.count > 100 { lastViolations.removeFirst() }
    }

    func getLastViolations() -> [EthicsViolation] {
        return lastViolations
    }

    func overrideIntent(_ type: AgentIntent.IntentType) {
        userOverrideWhitelist.insert(type.rawValue)
        logger.warning("Override set for intent type: \(type.rawValue)")
    }

    func resetOverrides() {
        userOverrideWhitelist.removeAll()
        logger.info("All overrides cleared")
    }
}

// MARK: - Policy Definition
struct EthicsPolicy {
    var enabled: Bool
    var blockedIntents: Set<AgentIntent.IntentType>
    var trustedOrigins: Set<String>
    var minimumConfidence: Double
    var timeWindow: EthicsTimeWindow
    var allowCamera: Bool
    var allowMotion: Bool
    var allowMicrophone: Bool

    static let `default` = EthicsPolicy(
        enabled: true,
        blockedIntents: [.deleteKey, .selfDestruct],
        trustedOrigins: ["core-ai", "secure-module", "teslaai-daemon"],
        minimumConfidence: 0.8,
        timeWindow: .defaultWorkHours,
        allowCamera: true,
        allowMotion: true,
        allowMicrophone: false
    )
}

// MARK: - Ethics Time Policy
struct EthicsTimeWindow {
    let allowedHours: ClosedRange<Int>  // e.g. 6...22

    var isCurrentAllowed: Bool {
        let hour = Calendar.current.component(.hour, from: Date())
        return allowedHours.contains(hour)
    }

    static let defaultWorkHours = EthicsTimeWindow(allowedHours: 6...22)
}

// MARK: - Violation Enum
enum EthicsViolation: CustomStringConvertible {
    case blockedIntent(AgentIntent.IntentType)
    case untrustedSource(String)
    case lowConfidence(AgentIntent.IntentType, Double)
    case blockedByTimeWindow

    var description: String {
        switch self {
        case .blockedIntent(let type):
            return "Intent blocked by policy: \(type.rawValue)"
        case .untrustedSource(let source):
            return "Intent source untrusted: \(source)"
        case .lowConfidence(let type, let confidence):
            return "Intent \(type.rawValue) rejected: low confidence \(confidence)"
        case .blockedByTimeWindow:
            return "Action blocked outside permitted hours"
        }
    }
}

// MARK: - Sensor Types
extension EthicsEngine {
    enum SensorType {
        case motion, camera, microphone
    }
}

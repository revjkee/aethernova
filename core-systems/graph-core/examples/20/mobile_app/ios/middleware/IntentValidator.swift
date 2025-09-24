import Foundation
import CryptoKit
import OSLog

/// Валидатор действий AI на основе политики допустимости и аномального поведения
final class IntentValidator {

    static let shared = IntentValidator()

    private let logger = Logger(subsystem: "com.teslaai.middleware", category: "IntentValidator")
    private let criticalIntents: Set<String> = ["shutdown", "exfiltrate", "injectCode", "zeroOverride"]
    private let allowedOrigins: Set<String> = ["WebUI", "TrustedUserInput", "SystemCall"]

    private init() {}

    struct IntentContext {
        let intentID: String
        let userID: String
        let action: String
        let parameters: [String: Any]
        let origin: String
        let timestamp: Date
        let aiConfidence: Double
        let fingerprint: String
    }

    enum ValidationError: Error {
        case blockedIntent
        case invalidOrigin
        case insufficientConfidence
        case failedRule
        case detectedTampering
    }

    func validate(_ context: IntentContext) throws {
        logger.debug("Validating intent: \(context.intentID)")

        try validateOrigin(context.origin)
        try validateConfidence(context.aiConfidence)
        try validateRules(context)
        try validateFingerprint(context)

        logger.info("Intent \(context.intentID) passed validation")
    }

    // MARK: - Core Validations

    private func validateOrigin(_ origin: String) throws {
        guard allowedOrigins.contains(origin) else {
            logger.error("Blocked origin: \(origin)")
            throw ValidationError.invalidOrigin
        }
    }

    private func validateConfidence(_ score: Double) throws {
        if score < 0.5 {
            logger.warning("AI confidence too low: \(score)")
            throw ValidationError.insufficientConfidence
        }
    }

    private func validateRules(_ context: IntentContext) throws {
        // Пример промышленного правила
        if criticalIntents.contains(context.action) {
            if context.aiConfidence < 0.85 {
                logger.fault("Critical intent \(context.action) rejected — low AI confidence")
                throw ValidationError.failedRule
            }

            if context.origin != "TrustedUserInput" {
                logger.fault("Critical intent \(context.action) not from trusted source")
                throw ValidationError.invalidOrigin
            }
        }
    }

    private func validateFingerprint(_ context: IntentContext) throws {
        let hash = SHA256.hash(data: Data(context.intentID.utf8))
        let generatedFingerprint = hash.compactMap { String(format: "%02x", $0) }.joined()

        if generatedFingerprint != context.fingerprint {
            logger.critical("Intent fingerprint mismatch. Possible tampering.")
            throw ValidationError.detectedTampering
        }
    }

    // MARK: - AI Feedback Loop (опционально подключается в runtime)
    func getIntentSeverityScore(context: IntentContext) -> Int {
        // Условно: можно подключить AI-модель, сейчас простой пример
        if criticalIntents.contains(context.action) {
            return 90
        }
        if context.aiConfidence < 0.3 {
            return 70
        }
        return 10
    }
}

import Foundation
import Combine
import OSLog

final class AIService {

    // MARK: - Dependencies
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "AIService")
    private let intentValidator = IntentValidator()
    private let ethicsEngine = EthicsEngine.shared
    private let feedbackRecorder = FeedbackRecorder.shared
    private let cache = NSCache<NSString, CachedAIResult>()

    // MARK: - Config
    private let endpointURL = URL(string: "https://ai.teslaai.io/intent")!
    private let requestTimeout: TimeInterval = 10
    private let maxRatePerMinute = 60
    private var requestTimestamps: [Date] = []

    // MARK: - API: Execute Intent
    func executeIntent(_ intent: AgentIntent) async throws -> AIResult {
        try rateLimitGuard()
        try validatePolicy(intent)

        if let cached = getCachedResult(for: intent) {
            logger.debug("Returning cached result for intent: \(intent.shortID)")
            return cached.result
        }

        logger.notice("Dispatching intent to AI core: \(intent.intentType.rawValue)")

        let request = buildRequest(for: intent)
        let (data, response) = try await URLSession.shared.data(for: request)
        try validateResponse(response)

        let result = try JSONDecoder().decode(AIResult.self, from: data)
        feedbackRecorder.record(event: .aiIntentExecuted(intent.intentType.rawValue))
        cacheResult(result, for: intent)

        return result
    }

    // MARK: - Validation
    private func validatePolicy(_ intent: AgentIntent) throws {
        if !intentValidator.validate(intent) {
            feedbackRecorder.record(event: .intentBlocked(intent.intentType.rawValue))
            logger.error("Intent \(intent.intentType.rawValue) blocked by IntentValidator")
            throw AIError.intentRejectedByPolicy
        }

        if !ethicsEngine.evaluateIntent(intent) {
            feedbackRecorder.record(event: .ethicsViolation(intent.intentType.rawValue))
            logger.fault("Intent \(intent.intentType.rawValue) rejected by EthicsEngine")
            throw AIError.intentBlockedByEthics
        }
    }

    private func validateResponse(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            logger.error("AI backend returned non-200 response")
            throw AIError.invalidResponse
        }
    }

    private func rateLimitGuard() throws {
        let now = Date()
        requestTimestamps = requestTimestamps.filter { now.timeIntervalSince($0) < 60 }
        if requestTimestamps.count >= maxRatePerMinute {
            logger.warning("Rate limit exceeded for AI service")
            throw AIError.rateLimited
        }
        requestTimestamps.append(now)
    }

    // MARK: - Networking
    private func buildRequest(for intent: AgentIntent) -> URLRequest {
        var request = URLRequest(url: endpointURL)
        request.httpMethod = "POST"
        request.timeoutInterval = requestTimeout
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")

        if let token = SessionManager.shared.sessionToken {
            request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        request.httpBody = try? JSONEncoder().encode(intent)
        return request
    }

    // MARK: - Caching
    private func getCachedResult(for intent: AgentIntent) -> CachedAIResult? {
        guard let entry = cache.object(forKey: intent.id.uuidString as NSString) else { return nil }
        if Date().timeIntervalSince(entry.timestamp) < 60 {
            return entry
        }
        cache.removeObject(forKey: intent.id.uuidString as NSString)
        return nil
    }

    private func cacheResult(_ result: AIResult, for intent: AgentIntent) {
        let entry = CachedAIResult(result: result, timestamp: Date())
        cache.setObject(entry, forKey: intent.id.uuidString as NSString)
    }
}

// MARK: - AIResult Model
struct AIResult: Codable, Equatable {
    let summary: String
    let actions: [String]
    let confidence: Double
    let explanation: String?
}

// MARK: - Internal Cache Wrapper
final class CachedAIResult: NSObject {
    let result: AIResult
    let timestamp: Date

    init(result: AIResult, timestamp: Date) {
        self.result = result
        self.timestamp = timestamp
    }
}

// MARK: - AI Errors
enum AIError: Error, LocalizedError {
    case intentRejectedByPolicy
    case intentBlockedByEthics
    case invalidResponse
    case rateLimited

    var errorDescription: String? {
        switch self {
        case .intentRejectedByPolicy:
            return "Intent rejected by internal policy."
        case .intentBlockedByEthics:
            return "Intent rejected by AI Ethics Engine."
        case .invalidResponse:
            return "Invalid response from AI backend."
        case .rateLimited:
            return "AI request rate limit exceeded."
        }
    }
}

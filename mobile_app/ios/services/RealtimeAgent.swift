import Foundation
import Combine
import OSLog

final class RealtimeAgent: ObservableObject {

    // MARK: - Shared Singleton
    static let shared = RealtimeAgent()

    // MARK: - Published Output
    @Published private(set) var incomingIntents: [AgentIntent] = []
    @Published private(set) var connectionStatus: ConnectionState = .disconnected

    // MARK: - Internal State
    private var subscriptions = Set<AnyCancellable>()
    private var websocketTask: URLSessionWebSocketTask?
    private var reconnectAttempts = 0
    private let maxReconnectAttempts = 5

    // MARK: - Dependencies
    private let session = URLSession(configuration: .default)
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "RealtimeAgent")
    private let validator = IntentValidator()
    private let ethics = EthicsEngine.shared
    private let feedback = FeedbackRecorder.shared

    // MARK: - Constants
    private let endpointURL = URL(string: "wss://realtime.teslaai.io/stream")!

    // MARK: - Connection Lifecycle
    func connect() {
        disconnect()
        logger.notice("Connecting to AI realtime stream")

        var request = URLRequest(url: endpointURL)
        request.timeoutInterval = 15

        if let token = SessionManager.shared.sessionToken {
            request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        websocketTask = session.webSocketTask(with: request)
        websocketTask?.resume()
        connectionStatus = .connected

        listen()
        feedback.record(event: .realtimeConnected)
    }

    func disconnect() {
        websocketTask?.cancel(with: .goingAway, reason: nil)
        websocketTask = nil
        connectionStatus = .disconnected
        logger.info("Realtime stream disconnected")
    }

    // MARK: - Listen for Intents
    private func listen() {
        websocketTask?.receive { [weak self] result in
            guard let self else { return }

            switch result {
            case .failure(let error):
                self.logger.error("Realtime error: \(error.localizedDescription)")
                self.connectionStatus = .error
                self.feedback.record(event: .realtimeError(error.localizedDescription))
                self.tryReconnect()
            case .success(let message):
                self.handleMessage(message)
                self.listen() // continue listening
            }
        }
    }

    private func handleMessage(_ message: URLSessionWebSocketTask.Message) {
        guard case let .string(jsonString) = message,
              let data = jsonString.data(using: .utf8),
              let intent = try? JSONDecoder().decode(AgentIntent.self, from: data) else {
            logger.warning("Invalid message format")
            return
        }

        Task {
            do {
                try validate(intent: intent)
                DispatchQueue.main.async {
                    self.incomingIntents.insert(intent, at: 0)
                }
                feedback.record(event: .intentReceived(intent.intentType.rawValue))
                logger.notice("New intent received: \(intent.title)")
            } catch {
                feedback.record(event: .intentRejected(intent.intentType.rawValue))
                logger.error("Intent rejected: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Validation Pipeline
    private func validate(intent: AgentIntent) throws {
        if !validator.validate(intent) {
            throw RealtimeAgentError.intentRejectedByPolicy
        }

        if !ethics.evaluateIntent(intent) {
            throw RealtimeAgentError.intentBlockedByEthics
        }

        if !intent.verify(using: SessionManager.shared.publicKey) {
            throw RealtimeAgentError.invalidSignature
        }
    }

    // MARK: - Reconnect Logic
    private func tryReconnect() {
        reconnectAttempts += 1
        guard reconnectAttempts <= maxReconnectAttempts else {
            logger.fault("Max reconnect attempts reached")
            feedback.record(event: .realtimeDisconnected)
            return
        }

        logger.warning("Attempting reconnect: \(reconnectAttempts)")
        DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(3)) {
            self.connect()
        }
    }

    // MARK: - State Enum
    enum ConnectionState: String {
        case connected, disconnected, error
    }

    enum RealtimeAgentError: Error, LocalizedError {
        case intentRejectedByPolicy
        case intentBlockedByEthics
        case invalidSignature

        var errorDescription: String? {
            switch self {
            case .intentRejectedByPolicy:
                return "Intent was rejected by local policy"
            case .intentBlockedByEthics:
                return "Intent was blocked by AI ethics rules"
            case .invalidSignature:
                return "Intent signature could not be verified"
            }
        }
    }
}

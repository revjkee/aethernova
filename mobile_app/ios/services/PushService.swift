import Foundation
import UserNotifications
import OSLog
import Combine

final class PushService: NSObject, ObservableObject, UNUserNotificationCenterDelegate {

    // MARK: - Singleton
    static let shared = PushService()

    // MARK: - Publishers
    @Published var lastReceivedIntent: AgentIntent?
    @Published var pushToken: String?

    // MARK: - Internals
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "PushService")
    private let feedback = FeedbackRecorder.shared
    private let validator = IntentValidator()
    private let ethics = EthicsEngine.shared

    // MARK: - Setup
    func configure() {
        UNUserNotificationCenter.current().delegate = self

        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) { granted, error in
            if let error = error {
                self.logger.error("Push authorization error: \(error.localizedDescription)")
                return
            }

            if granted {
                DispatchQueue.main.async {
                    UIApplication.shared.registerForRemoteNotifications()
                    self.logger.notice("Push notifications granted and registered.")
                }
            } else {
                self.logger.warning("Push authorization denied.")
            }
        }
    }

    // MARK: - Token Handling
    func registerDeviceToken(_ deviceToken: Data) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        self.pushToken = token
        logger.info("Device token registered: \(token.prefix(8))...")
        SessionManager.shared.updatePushToken(token)
    }

    // MARK: - UNUserNotificationCenterDelegate
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        handlePush(notification.request.content.userInfo)
        completionHandler([.banner, .sound])
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        handlePush(response.notification.request.content.userInfo)
        completionHandler()
    }

    // MARK: - Internal Handler
    private func handlePush(_ payload: [AnyHashable: Any]) {
        guard let intentData = payload["intent"] as? String,
              let data = intentData.data(using: .utf8),
              let intent = try? JSONDecoder().decode(AgentIntent.self, from: data) else {
            logger.warning("Invalid or missing intent in push payload")
            return
        }

        Task {
            do {
                try validate(intent: intent)
                DispatchQueue.main.async {
                    self.lastReceivedIntent = intent
                }
                feedback.record(event: .intentReceived(intent.intentType.rawValue))
                logger.notice("Push intent accepted: \(intent.intentType.rawValue)")
            } catch {
                feedback.record(event: .intentRejected(intent.intentType.rawValue))
                logger.fault("Push intent rejected: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Validation
    private func validate(intent: AgentIntent) throws {
        if !validator.validate(intent) {
            throw PushError.intentRejectedByPolicy
        }

        if !ethics.evaluateIntent(intent) {
            throw PushError.intentBlockedByEthics
        }

        if !intent.verify(using: SessionManager.shared.publicKey) {
            throw PushError.invalidSignature
        }
    }

    // MARK: - Errors
    enum PushError: Error, LocalizedError {
        case intentRejectedByPolicy
        case intentBlockedByEthics
        case invalidSignature

        var errorDescription: String? {
            switch self {
            case .intentRejectedByPolicy:
                return "Intent rejected by policy rules"
            case .intentBlockedByEthics:
                return "Intent failed ethical validation"
            case .invalidSignature:
                return "Intent has invalid digital signature"
            }
        }
    }
}

import Foundation
import Combine
import LocalAuthentication
import CryptoKit
import OSLog

final class SessionManager: ObservableObject {
    
    // MARK: - Singleton
    static let shared = SessionManager()
    
    // MARK: - Published State
    @Published private(set) var isAuthenticated: Bool = false
    @Published var sessionStartTime: Date?
    @Published var sessionToken: String?
    
    // MARK: - Internal State
    private var sessionTimeoutTimer: Timer?
    private let logger = Logger(subsystem: "com.teslaai.security", category: "SessionManager")
    private let secureStorage = SecureStorage.shared
    private let sessionTokenKey = "teslaai.session.token"
    private let sessionSaltKey = "teslaai.session.salt"
    private let biometricContext = LAContext()
    
    // MARK: - Constants
    private let sessionDuration: TimeInterval = 15 * 60 // 15 min
    private let maxIdleTime: TimeInterval = 180         // 3 min
    private let entropySalt = UUID().uuidString
    
    // MARK: - Initializer
    private init() {
        logger.info("SessionManager initialized.")
        restoreSession()
    }

    // MARK: - Session Lifecycle
    func startNewSession() {
        invalidateSession()
        sessionStartTime = Date()
        sessionToken = generateSecureToken()
        isAuthenticated = true
        persist()
        logger.info("Session started.")
        scheduleTimeout()
    }

    func invalidateSession() {
        sessionTimeoutTimer?.invalidate()
        sessionToken = nil
        sessionStartTime = nil
        isAuthenticated = false
        secureStorage.delete(key: sessionTokenKey)
        secureStorage.delete(key: sessionSaltKey)
        logger.notice("Session invalidated.")
    }

    func persist() {
        guard let token = sessionToken else { return }
        secureStorage.set(value: token, forKey: sessionTokenKey)
        secureStorage.set(value: entropySalt, forKey: sessionSaltKey)
        logger.debug("Session persisted securely.")
    }

    private func restoreSession() {
        guard let token = secureStorage.get(forKey: sessionTokenKey),
              let _ = secureStorage.get(forKey: sessionSaltKey) else {
            logger.warning("No persisted session found.")
            return
        }
        sessionToken = token
        sessionStartTime = Date()
        isAuthenticated = true
        logger.info("Session restored from secure storage.")
        scheduleTimeout()
    }

    // MARK: - Token Generation
    private func generateSecureToken() -> String {
        let timestamp = "\(Date().timeIntervalSince1970)"
        let base = "\(UUID().uuidString)-\(timestamp)-\(entropySalt)"
        let hashed = SHA256.hash(data: Data(base.utf8))
        return hashed.compactMap { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Timeout Handling
    private func scheduleTimeout() {
        sessionTimeoutTimer?.invalidate()
        sessionTimeoutTimer = Timer.scheduledTimer(withTimeInterval: maxIdleTime, repeats: false) { [weak self] _ in
            self?.handleTimeout()
        }
    }

    private func handleTimeout() {
        logger.error("Session expired due to inactivity.")
        invalidateSession()
    }

    func renewIfValid() {
        guard isAuthenticated, let start = sessionStartTime else { return }
        let elapsed = Date().timeIntervalSince(start)
        if elapsed < sessionDuration {
            sessionStartTime = Date()
            scheduleTimeout()
            logger.debug("Session renewed.")
        } else {
            handleTimeout()
        }
    }

    // MARK: - Biometric Validation
    func requireBiometricUnlock(completion: @escaping (Bool) -> Void) {
        var error: NSError?
        if biometricContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            biometricContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                            localizedReason: "Unlock TeslaAI Vault Session") { success, _ in
                DispatchQueue.main.async {
                    completion(success)
                }
            }
        } else {
            logger.warning("Biometric auth not available.")
            completion(false)
        }
    }

    // MARK: - Security State
    var isSecure: Bool {
        return sessionToken != nil && isAuthenticated
    }
}

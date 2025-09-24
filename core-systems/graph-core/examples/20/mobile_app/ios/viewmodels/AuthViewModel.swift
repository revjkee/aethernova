import Foundation
import Combine
import LocalAuthentication
import OSLog

final class AuthViewModel: ObservableObject {

    // MARK: - Published Properties
    @Published var isAuthenticated = false
    @Published var isLoading = false
    @Published var errorMessage: String = ""

    // MARK: - Dependencies
    private let secureStorage = SecureStorage.shared
    private let sessionManager = SessionManager.shared
    private let ethicsEngine = EthicsEngine.shared
    private let feedbackRecorder = FeedbackRecorder.shared
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "AuthViewModel")

    // MARK: - Constants
    private let maxAttempts = 5
    private var failedAttempts = 0

    // MARK: - Authentication Method
    @MainActor
    func login(email: String, password: String) async -> Bool {
        guard validateInputs(email: email, password: password) else {
            self.errorMessage = "Invalid credentials format."
            logger.error("Validation failed for email: \(email, privacy: .private)")
            return false
        }

        if failedAttempts >= maxAttempts {
            self.errorMessage = "Too many failed attempts. Try again later."
            logger.fault("Max login attempts exceeded.")
            feedbackRecorder.record(event: .securityLockout)
            return false
        }

        isLoading = true
        defer { isLoading = false }

        logger.notice("Attempting login for: \(email, privacy: .private)")

        do {
            let allowed = ethicsEngine.evaluateLoginAttempt(email: email)
            guard allowed else {
                self.errorMessage = "Access blocked by ethics policy."
                logger.warning("Login blocked by EthicsEngine.")
                feedbackRecorder.record(event: .ethicsViolation("Login blocked for: \(email)"))
                return false
            }

            // Simulate network/authentication logic
            let authResult = try await NetworkService.shared.authenticate(email: email, password: password)

            guard authResult.success else {
                failedAttempts += 1
                self.errorMessage = authResult.message ?? "Login failed"
                feedbackRecorder.record(event: .loginFailure)
                return false
            }

            secureStorage.storeAccessToken(authResult.token)
            sessionManager.initializeNewSession(userID: authResult.userID)
            isAuthenticated = true
            failedAttempts = 0
            feedbackRecorder.record(event: .loginSuccess)
            logger.info("User authenticated successfully: \(authResult.userID, privacy: .private)")
            return true

        } catch {
            failedAttempts += 1
            self.errorMessage = "Authentication error: \(error.localizedDescription)"
            logger.error("Login error: \(error.localizedDescription)")
            feedbackRecorder.record(event: .loginFailure)
            return false
        }
    }

    func resetState() {
        isAuthenticated = false
        errorMessage = ""
        failedAttempts = 0
        isLoading = false
        logger.debug("AuthViewModel state reset.")
    }

    func isFormValid(email: String, password: String) -> Bool {
        return !email.trimmingCharacters(in: .whitespaces).isEmpty &&
               !password.trimmingCharacters(in: .whitespaces).isEmpty &&
               email.contains("@") && password.count >= 6
    }

    private func validateInputs(email: String, password: String) -> Bool {
        return isFormValid(email: email, password: password)
    }

    // MARK: - Biometric Authentication (Optional Future Use)
    func authenticateWithBiometrics() async -> Bool {
        let context = LAContext()
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            let reason = "Authenticate to access secure features"
            do {
                let success = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
                logger.info("Biometric authentication: \(success)")
                return success
            } catch {
                logger.error("Biometric auth failed: \(error.localizedDescription)")
            }
        }
        return false
    }
}

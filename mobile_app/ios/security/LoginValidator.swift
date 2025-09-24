import Foundation
import CryptoKit
import OSLog

final class LoginValidator {

    // MARK: - Constants
    private let logger = Logger(subsystem: "com.teslaai.security", category: "LoginValidator")
    private let maxPasswordLength = 64
    private let minPasswordLength = 10
    private let allowedSpecials = "!@#$%^&*()-_=+{}[]|:;'<>,.?/~`"
    private let maxLoginAttemptsPerMinute = 5

    // MARK: - Throttling
    private var failedAttempts: [String: [Date]] = [:]
    private let throttlingQueue = DispatchQueue(label: "com.teslaai.security.loginThrottle")

    // MARK: - Public

    func validate(username: String, password: String) -> Bool {
        guard validateUsername(username),
              validatePassword(password),
              !isThrottled(username: username)
        else {
            logFailedAttempt(username)
            return false
        }

        logger.info("Login validation passed for user: \(username, privacy: .masked)")
        return true
    }

    // MARK: - Validation Logic

    private func validateUsername(_ username: String) -> Bool {
        let regex = "^[a-zA-Z0-9._-]{3,32}$"
        let predicate = NSPredicate(format: "SELF MATCHES %@", regex)
        let valid = predicate.evaluate(with: username)
        if !valid {
            logger.warning("Rejected login: invalid username format.")
        }
        return valid
    }

    private func validatePassword(_ password: String) -> Bool {
        guard password.count >= minPasswordLength && password.count <= maxPasswordLength else {
            logger.warning("Rejected login: password length constraint.")
            return false
        }

        let containsUpper = password.range(of: "[A-Z]", options: .regularExpression) != nil
        let containsLower = password.range(of: "[a-z]", options: .regularExpression) != nil
        let containsDigit = password.range(of: "[0-9]", options: .regularExpression) != nil
        let containsSpecial = password.rangeOfCharacter(from: CharacterSet(charactersIn: allowedSpecials)) != nil

        let valid = containsUpper && containsLower && containsDigit && containsSpecial

        if !valid {
            logger.warning("Rejected login: password complexity not met.")
        }

        return valid
    }

    // MARK: - Anti-Brute Force Throttling

    private func isThrottled(username: String) -> Bool {
        throttlingQueue.sync {
            let now = Date()
            let oneMinuteAgo = now.addingTimeInterval(-60)
            let attempts = failedAttempts[username]?.filter { $0 > oneMinuteAgo } ?? []
            failedAttempts[username] = attempts
            if attempts.count >= maxLoginAttemptsPerMinute {
                logger.error("User \(username) temporarily throttled.")
                return true
            }
            return false
        }
    }

    private func logFailedAttempt(_ username: String) {
        throttlingQueue.sync {
            failedAttempts[username, default: []].append(Date())
        }
        logger.notice("Login failed for user \(username, privacy: .masked)")
    }

    // MARK: - Admin Audit Mode

    func auditValidate(_ username: String, _ password: String) -> [String] {
        var issues: [String] = []

        if !validateUsername(username) {
            issues.append("Недопустимое имя пользователя.")
        }

        if password.count < minPasswordLength {
            issues.append("Слишком короткий пароль.")
        }

        if !password.contains(where: { $0.isUppercase }) {
            issues.append("Пароль не содержит заглавных букв.")
        }

        if !password.contains(where: { $0.isLowercase }) {
            issues.append("Пароль не содержит строчных букв.")
        }

        if !password.contains(where: { $0.isNumber }) {
            issues.append("Пароль не содержит цифр.")
        }

        if !password.contains(where: { allowedSpecials.contains($0) }) {
            issues.append("Пароль не содержит специальных символов.")
        }

        return issues
    }
}

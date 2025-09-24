import Foundation
import CryptoKit
import OSLog

final class CSRFTokenManager {

    // MARK: - Singleton
    static let shared = CSRFTokenManager()
    
    // MARK: - Properties
    private let tokenKey = "teslaai.csrf.token"
    private let tokenExpiryKey = "teslaai.csrf.expiry"
    private let secretKey = "TeslaAI-CSRF-Internal-HMAC-Key"
    private let tokenValidity: TimeInterval = 600 // 10 минут
    private let secureStorage = SecureStorage.shared
    private let logger = Logger(subsystem: "com.teslaai.security", category: "CSRFToken")

    private init() {}

    // MARK: - Public API

    func generateToken(forSession sessionID: String) -> String {
        let nonce = UUID().uuidString
        let timestamp = Int(Date().timeIntervalSince1970)
        let payload = "\(sessionID):\(nonce):\(timestamp)"
        let signature = hmac(payload: payload, key: secretKey)
        let token = "\(payload):\(signature)"
        store(token: token)
        logger.debug("Generated new CSRF token for session: \(sessionID)")
        return token
    }

    func validate(token: String?, forSession sessionID: String) -> Bool {
        guard let token = token else {
            logger.warning("CSRF token is nil.")
            return false
        }
        
        let parts = token.components(separatedBy: ":")
        guard parts.count == 4 else {
            logger.error("Invalid CSRF token format.")
            return false
        }

        let payload = "\(parts[0]):\(parts[1]):\(parts[2])"
        let signature = parts[3]

        guard parts[0] == sessionID else {
            logger.error("CSRF session mismatch.")
            return false
        }

        guard isValidTimestamp(parts[2]) else {
            logger.error("CSRF token expired.")
            return false
        }

        let expectedSignature = hmac(payload: payload, key: secretKey)
        let valid = secureCompare(expectedSignature, signature)
        logger.debug("CSRF token validation result: \(valid)")
        return valid
    }

    // MARK: - Helpers

    private func hmac(payload: String, key: String) -> String {
        let keyData = SymmetricKey(data: Data(key.utf8))
        let mac = HMAC<SHA256>.authenticationCode(for: Data(payload.utf8), using: keyData)
        return mac.map { String(format: "%02x", $0) }.joined()
    }

    private func isValidTimestamp(_ timestampStr: String) -> Bool {
        guard let timestamp = TimeInterval(timestampStr) else { return false }
        let now = Date().timeIntervalSince1970
        return (now - timestamp) < tokenValidity
    }

    private func store(token: String) {
        secureStorage.set(value: token, forKey: tokenKey)
        let expiry = Date().addingTimeInterval(tokenValidity)
        secureStorage.set(value: String(expiry.timeIntervalSince1970), forKey: tokenExpiryKey)
    }

    func fetchCurrentToken() -> String? {
        return secureStorage.get(forKey: tokenKey)
    }

    func invalidateToken() {
        secureStorage.delete(key: tokenKey)
        secureStorage.delete(key: tokenExpiryKey)
        logger.notice("CSRF token invalidated manually.")
    }

    // MARK: - Constant-Time Comparison

    private func secureCompare(_ a: String, _ b: String) -> Bool {
        guard a.count == b.count else { return false }
        var result = UInt8(0)
        for (x, y) in zip(a.utf8, b.utf8) {
            result |= x ^ y
        }
        return result == 0
    }
}

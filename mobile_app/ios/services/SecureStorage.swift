import Foundation
import Security
import CryptoKit
import OSLog

final class SecureStorage {

    // MARK: - Singleton
    static let shared = SecureStorage()

    // MARK: - Internal Properties
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "SecureStorage")
    private let service = "com.teslaai.securestorage"
    private let namespacePrefix = "tzgen_"

    // MARK: - Public API

    func setString(_ value: String, forKey key: String) {
        store(value.data(using: .utf8), forKey: key)
    }

    func getString(forKey key: String) -> String? {
        guard let data = retrieve(forKey: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func setBool(_ value: Bool, forKey key: String) {
        let data = Data([value ? 1 : 0])
        store(data, forKey: key)
    }

    func getBool(forKey key: String, default fallback: Bool = false) -> Bool {
        guard let data = retrieve(forKey: key), let byte = data.first else {
            return fallback
        }
        return byte != 0
    }

    func removeValue(forKey key: String) {
        let query = buildQuery(for: key)
        SecItemDelete(query as CFDictionary)
        logger.debug("Secure key deleted: \(key, privacy: .private)")
    }

    func clearAll() {
        logger.warning("SecureStorage: clearing all keys under namespace")
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Internal Methods

    private func store(_ data: Data?, forKey key: String) {
        guard let data else {
            removeValue(forKey: key)
            return
        }

        let query = buildQuery(for: key)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query.merging(attributes, uniquingKeysWith: { $1 }) as CFDictionary, nil)

        if status == errSecSuccess {
            logger.debug("Secure key stored: \(key, privacy: .private)")
        } else {
            logger.error("Failed to store secure key: \(key, privacy: .private), status: \(status)")
        }
    }

    private func retrieve(forKey key: String) -> Data? {
        let query = buildQuery(for: key)
            .merging([
                kSecReturnData as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne
            ]) { $1 }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecSuccess {
            logger.debug("Secure key accessed: \(key, privacy: .private)")
            return result as? Data
        } else {
            logger.warning("Secure key access failed: \(key, privacy: .private), status: \(status)")
            return nil
        }
    }

    private func buildQuery(for key: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: namespacePrefix + key
        ]
    }

    // MARK: - Diagnostics

    func printAllKeysForAudit() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            logger.warning("Audit failed: Unable to enumerate secure items.")
            return
        }

        for item in items {
            if let key = item[kSecAttrAccount as String] as? String {
                logger.notice("SecureStorage Key (namespace): \(key)")
            }
        }
    }
}

import Foundation
import CryptoKit
import Security
import OSLog

final class SignatureVerifier {

    private let logger = Logger(subsystem: "com.teslaai.security", category: "SignatureVerifier")
    
    enum SignatureAlgorithm {
        case ecdsaP256
        case rsa2048
        case secureEnclave
    }

    enum SignatureVerificationError: Error {
        case invalidSignature
        case unsupportedAlgorithm
        case keyNotFound
        case malformedInput
        case secureEnclaveUnavailable
    }

    // MARK: - Public API

    func verify(message: Data, signature: Data, publicKey: SecKey, algorithm: SignatureAlgorithm) throws -> Bool {
        switch algorithm {
        case .ecdsaP256:
            return try verifyECDSA(message: message, signature: signature, publicKey: publicKey)
        case .rsa2048:
            return try verifyRSA(message: message, signature: signature, publicKey: publicKey)
        case .secureEnclave:
            return try verifySecureEnclaveSignature(message: message, signature: signature)
        }
    }

    // MARK: - ECDSA (P-256)

    private func verifyECDSA(message: Data, signature: Data, publicKey: SecKey) throws -> Bool {
        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            throw SignatureVerificationError.unsupportedAlgorithm
        }

        var error: Unmanaged<CFError>?
        let success = SecKeyVerifySignature(publicKey,
                                            algorithm,
                                            message as CFData,
                                            signature as CFData,
                                            &error)

        if let err = error {
            logger.error("ECDSA verify failed: \(err.takeRetainedValue().localizedDescription)")
            throw SignatureVerificationError.invalidSignature
        }

        logger.info("ECDSA signature verified successfully.")
        return success
    }

    // MARK: - RSA (2048)

    private func verifyRSA(message: Data, signature: Data, publicKey: SecKey) throws -> Bool {
        let algorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            throw SignatureVerificationError.unsupportedAlgorithm
        }

        var error: Unmanaged<CFError>?
        let success = SecKeyVerifySignature(publicKey,
                                            algorithm,
                                            message as CFData,
                                            signature as CFData,
                                            &error)

        if let err = error {
            logger.error("RSA verify failed: \(err.takeRetainedValue().localizedDescription)")
            throw SignatureVerificationError.invalidSignature
        }

        logger.info("RSA signature verified successfully.")
        return success
    }

    // MARK: - Secure Enclave

    private func verifySecureEnclaveSignature(message: Data, signature: Data) throws -> Bool {
        guard let publicKey = try? fetchSecureEnclavePublicKey() else {
            throw SignatureVerificationError.secureEnclaveUnavailable
        }

        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            throw SignatureVerificationError.unsupportedAlgorithm
        }

        var error: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(publicKey,
                                             algorithm,
                                             message as CFData,
                                             signature as CFData,
                                             &error)

        if let err = error {
            logger.error("Secure Enclave verify failed: \(err.takeRetainedValue().localizedDescription)")
            throw SignatureVerificationError.invalidSignature
        }

        logger.info("Secure Enclave signature verified successfully.")
        return verified
    }

    // MARK: - Secure Enclave Key Retrieval

    private func fetchSecureEnclavePublicKey() throws -> SecKey {
        let tag = "com.teslaai.secureenclave.key".data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String:             kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String:      kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String:        true
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let key = result as? SecKey else {
            logger.error("Secure Enclave key not found.")
            throw SignatureVerificationError.keyNotFound
        }

        return key
    }

    // MARK: - Hashing Utility

    func hashSHA256(_ input: Data) -> Data {
        let hashed = SHA256.hash(data: input)
        return Data(hashed)
    }
}

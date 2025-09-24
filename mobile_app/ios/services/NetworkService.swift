import Foundation
import OSLog
import Combine

final class NetworkService {

    // MARK: - Singleton
    static let shared = NetworkService()

    // MARK: - Internal
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "NetworkService")
    private let session: URLSession
    private let requestTimeout: TimeInterval = 15
    private let maxRetryCount = 3
    private let retryDelay: TimeInterval = 1.5

    // MARK: - Init
    private init() {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = requestTimeout
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.session = URLSession(configuration: config)
    }

    // MARK: - Public API
    func send<T: Codable, U: Codable>(
        endpoint: URL,
        method: HTTPMethod,
        payload: T?,
        requiresAuth: Bool = true
    ) async throws -> U {
        var attempt = 0
        var lastError: Error?

        while attempt < maxRetryCount {
            do {
                var request = try buildRequest(
                    url: endpoint,
                    method: method,
                    payload: payload,
                    requiresAuth: requiresAuth
                )
                logger.debug("Sending \(method.rawValue) to \(endpoint.absoluteString, privacy: .private)")

                let (data, response) = try await session.data(for: request)
                try validate(response: response)

                let decoded = try JSONDecoder().decode(U.self, from: data)
                return decoded
            } catch {
                lastError = error
                attempt += 1
                logger.warning("Attempt \(attempt) failed for \(endpoint): \(error.localizedDescription)")
                try await Task.sleep(nanoseconds: UInt64(retryDelay * 1_000_000_000))
            }
        }

        throw lastError ?? NetworkError.unknown
    }

    // MARK: - Request Builder
    private func buildRequest<T: Codable>(
        url: URL,
        method: HTTPMethod,
        payload: T?,
        requiresAuth: Bool
    ) throws -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        request.timeoutInterval = requestTimeout
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")

        if requiresAuth, let token = SessionManager.shared.sessionToken {
            request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        if let payload = payload {
            request.httpBody = try JSONEncoder().encode(payload)
        }

        return request
    }

    // MARK: - Response Validator
    private func validate(response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else {
            throw NetworkError.invalidResponse
        }

        guard (200..<300).contains(http.statusCode) else {
            logger.error("Non-success HTTP: \(http.statusCode)")
            if http.statusCode == 401 {
                SessionManager.shared.invalidateSession()
                throw NetworkError.unauthorized
            }
            throw NetworkError.httpStatus(code: http.statusCode)
        }
    }
}

// MARK: - HTTPMethod Enum
enum HTTPMethod: String {
    case GET, POST, PUT, DELETE
}

// MARK: - Network Errors
enum NetworkError: Error, LocalizedError {
    case invalidResponse
    case httpStatus(code: Int)
    case unauthorized
    case decodingFailure
    case unknown

    var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "Invalid or missing response from server"
        case .httpStatus(let code):
            return "HTTP error with status code: \(code)"
        case .unauthorized:
            return "Authorization failed or token expired"
        case .decodingFailure:
            return "Failed to decode server response"
        case .unknown:
            return "Unknown network error"
        }
    }
}

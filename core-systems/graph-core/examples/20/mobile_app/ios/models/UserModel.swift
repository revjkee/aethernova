import Foundation

struct UserModel: Identifiable, Codable, Equatable, Hashable {

    // MARK: - Core Identity
    let id: UUID
    var username: String
    var email: String
    var displayName: String
    var avatarURL: URL?
    var createdAt: Date
    var lastLogin: Date?

    // MARK: - Security & Trust
    var isVerified: Bool
    var isLocked: Bool
    var role: UserRole
    var mfaEnabled: Bool
    var sessionToken: String?
    var publicKey: String? // for signature verification
    var deviceFingerprint: String?

    // MARK: - Federated Identity / External Providers
    var linkedAccounts: [FederatedAccount]

    // MARK: - AI Policy & Ethics
    var aiScope: AIScopePolicy
    var isAIRestricted: Bool

    // MARK: - Audit & Metadata
    var loginCount: Int
    var lastAccessIP: String?
    var metadata: [String: String] // dynamic additional fields

    // MARK: - Computed Properties
    var shortID: String {
        id.uuidString.prefix(8).description
    }

    var isActive: Bool {
        return !isLocked && isVerified
    }

    // MARK: - Factory
    static func anonymous() -> UserModel {
        UserModel(
            id: UUID(),
            username: "guest",
            email: "anonymous@domain",
            displayName: "Guest",
            avatarURL: nil,
            createdAt: Date(),
            lastLogin: nil,
            isVerified: false,
            isLocked: false,
            role: .guest,
            mfaEnabled: false,
            sessionToken: nil,
            publicKey: nil,
            deviceFingerprint: nil,
            linkedAccounts: [],
            aiScope: .restricted,
            isAIRestricted: true,
            loginCount: 0,
            lastAccessIP: nil,
            metadata: [:]
        )
    }
}

// MARK: - User Roles
enum UserRole: String, Codable, CaseIterable {
    case admin
    case user
    case guest
    case auditor
    case aiAgent

    var description: String {
        switch self {
        case .admin: return "Administrator"
        case .user: return "Regular User"
        case .guest: return "Guest User"
        case .auditor: return "Security Auditor"
        case .aiAgent: return "Autonomous Agent"
        }
    }

    var accessLevel: Int {
        switch self {
        case .admin: return 100
        case .user: return 50
        case .auditor: return 60
        case .aiAgent: return 40
        case .guest: return 10
        }
    }
}

// MARK: - Federated Identity Structure
struct FederatedAccount: Codable, Hashable {
    var provider: String // e.g. "apple", "google", "github"
    var externalUserID: String
    var linkedAt: Date
}

// MARK: - AI Access Scope
struct AIScopePolicy: Codable, Hashable {
    var allowIntentSubmission: Bool
    var allowSelfModification: Bool
    var allowSensitiveDataAccess: Bool
    var maxRequestRatePerMin: Int

    static var strict: AIScopePolicy {
        .init(
            allowIntentSubmission: false,
            allowSelfModification: false,
            allowSensitiveDataAccess: false,
            maxRequestRatePerMin: 1
        )
    }

    static var permissive: AIScopePolicy {
        .init(
            allowIntentSubmission: true,
            allowSelfModification: true,
            allowSensitiveDataAccess: true,
            maxRequestRatePerMin: 100
        )
    }
}

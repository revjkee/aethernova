import Foundation
import Combine
import OSLog

final class VaultViewModel: ObservableObject {

    // MARK: - Published Data
    @Published var keys: [KeyModel] = []
    @Published var filteredKeys: [KeyModel] = []
    @Published var searchQuery: String = ""
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?

    // MARK: - Services
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "VaultViewModel")
    private let secureStorage = SecureStorage.shared
    private let ethicsEngine = EthicsEngine.shared
    private let networkService = NetworkService.shared
    private let sessionManager = SessionManager.shared
    private let feedbackRecorder = FeedbackRecorder.shared

    // MARK: - Internal State
    private var cancellables = Set<AnyCancellable>()
    private var lastFetchDate: Date?

    // MARK: - Init
    init() {
        observeSearchQuery()
    }

    // MARK: - Public Methods
    func loadVault() async {
        isLoading = true
        errorMessage = nil
        logger.notice("Vault data loading started")

        do {
            guard ethicsEngine.isVaultAccessAllowed() else {
                throw VaultError.accessDeniedByPolicy
            }

            let fetchedKeys = try await networkService.fetchVaultKeys(for: sessionManager.userID)
            self.keys = fetchedKeys
            self.filteredKeys = fetchedKeys
            self.lastFetchDate = Date()
            feedbackRecorder.record(event: .vaultLoaded(count: fetchedKeys.count))

            logger.info("Vault successfully loaded with \(fetchedKeys.count) keys")
        } catch {
            errorMessage = error.localizedDescription
            feedbackRecorder.record(event: .vaultLoadError(error.localizedDescription))
            logger.error("Vault loading failed: \(error.localizedDescription)")
        }

        isLoading = false
    }

    func deleteKey(_ key: KeyModel) async {
        do {
            guard ethicsEngine.canDeleteKey(key) else {
                feedbackRecorder.record(event: .unauthorizedDeleteAttempt(key.id))
                logger.warning("Delete blocked by ethics engine for key: \(key.id)")
                throw VaultError.deletionNotAllowed
            }

            try await networkService.deleteVaultKey(id: key.id)
            keys.removeAll { $0.id == key.id }
            filteredKeys.removeAll { $0.id == key.id }

            feedbackRecorder.record(event: .keyDeleted(key.id))
            logger.info("Vault key deleted: \(key.id)")
        } catch {
            errorMessage = "Delete error: \(error.localizedDescription)"
            logger.error("Failed to delete key: \(error.localizedDescription)")
        }
    }

    func refresh() async {
        await loadVault()
    }

    func filterKeys(with query: String) {
        if query.isEmpty {
            filteredKeys = keys
        } else {
            filteredKeys = keys.filter {
                $0.name.localizedCaseInsensitiveContains(query) ||
                $0.tags.contains(where: { $0.localizedCaseInsensitiveContains(query) })
            }
        }
    }

    // MARK: - Private Methods
    private func observeSearchQuery() {
        $searchQuery
            .debounce(for: .milliseconds(300), scheduler: DispatchQueue.main)
            .removeDuplicates()
            .sink { [weak self] newQuery in
                self?.filterKeys(with: newQuery)
            }
            .store(in: &cancellables)
    }

    // MARK: - Errors
    enum VaultError: LocalizedError {
        case accessDeniedByPolicy
        case deletionNotAllowed

        var errorDescription: String? {
            switch self {
            case .accessDeniedByPolicy:
                return "Access to the vault is blocked by AI policy."
            case .deletionNotAllowed:
                return "This key cannot be deleted due to policy restrictions."
            }
        }
    }
}

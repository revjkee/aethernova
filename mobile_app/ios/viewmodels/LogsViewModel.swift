import Foundation
import Combine
import OSLog

final class LogsViewModel: ObservableObject {

    // MARK: - Published State
    @Published var logs: [AuditLog] = []
    @Published var filteredLogs: [AuditLog] = []
    @Published var isLoading = false
    @Published var errorMessage: String?

    // MARK: - Internal State
    private var cancellables = Set<AnyCancellable>()

    // MARK: - Services
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "LogsViewModel")
    private let feedbackRecorder = FeedbackRecorder.shared
    private let ethicsEngine = EthicsEngine.shared
    private let networkService = NetworkService.shared
    private let sessionManager = SessionManager.shared

    // MARK: - Initialization
    init() {
        observeSessionEvents()
    }

    // MARK: - Fetch Logs
    @MainActor
    func fetchAuditLogs() async {
        isLoading = true
        errorMessage = nil
        logger.notice("Audit log fetch started")

        do {
            guard ethicsEngine.isAuditViewPermitted() else {
                throw LogError.accessDeniedByPolicy
            }

            let userID = sessionManager.userID
            let response = try await networkService.fetchAuditLogs(for: userID)

            logs = response
            filteredLogs = response

            logger.info("Audit logs loaded: \(logs.count) entries")
            feedbackRecorder.record(event: .logsFetched(count: logs.count))

        } catch {
            errorMessage = error.localizedDescription
            logger.error("Failed to load logs: \(error.localizedDescription)")
            feedbackRecorder.record(event: .logFetchError(error.localizedDescription))
        }

        isLoading = false
    }

    // MARK: - Filter Logs
    func filterLogs(query: String, severity: SeverityFilter) {
        filteredLogs = logs.filter { log in
            let matchesQuery = query.isEmpty || log.title.localizedCaseInsensitiveContains(query) || log.details.localizedCaseInsensitiveContains(query)
            let matchesSeverity = (severity == .all) || (log.severity == severity.toLogSeverity())
            return matchesQuery && matchesSeverity
        }
    }

    // MARK: - AI Analysis Trigger
    func analyzeWithAI() {
        guard !filteredLogs.isEmpty else {
            logger.debug("No logs to analyze")
            return
        }

        Task {
            do {
                let insights = try await AIService().analyzeLogs(filteredLogs)
                logger.notice("AI insights ready: \(insights.prefix(100))")
                feedbackRecorder.record(event: .aiLogInsights)
            } catch {
                logger.error("AI analysis failed: \(error.localizedDescription)")
                feedbackRecorder.record(event: .aiError(error.localizedDescription))
            }
        }
    }

    // MARK: - Event Listener
    private func observeSessionEvents() {
        sessionManager.sessionEventsPublisher
            .sink { [weak self] event in
                switch event {
                case .sessionStarted:
                    Task { await self?.fetchAuditLogs() }
                case .sessionExpired, .sessionRevoked:
                    self?.logs.removeAll()
                    self?.filteredLogs.removeAll()
                    self?.logger.info("Session ended, logs cleared")
                }
            }
            .store(in: &cancellables)
    }

    // MARK: - Error Handling
    enum LogError: LocalizedError {
        case accessDeniedByPolicy

        var errorDescription: String? {
            switch self {
            case .accessDeniedByPolicy:
                return "Access to audit logs is restricted by AI policy."
            }
        }
    }
}

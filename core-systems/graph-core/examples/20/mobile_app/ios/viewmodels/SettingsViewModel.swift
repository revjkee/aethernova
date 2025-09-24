import Foundation
import Combine
import OSLog

final class SettingsViewModel: ObservableObject {

    // MARK: - Published Settings State
    @Published var hapticsEnabled: Bool = true
    @Published var telemetryEnabled: Bool = false
    @Published var ethicsEnabled: Bool = true
    @Published var selectedTheme: AppTheme = .system
    @Published var secureMode: Bool = true
    @Published var userID: String = "anonymous"

    // MARK: - Services
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "SettingsViewModel")
    private let secureStorage = SecureStorage.shared
    private let sessionManager = SessionManager.shared
    private let feedbackRecorder = FeedbackRecorder.shared
    private let ethicsEngine = EthicsEngine.shared
    private let intentValidator = IntentValidator()

    private var cancellables = Set<AnyCancellable>()

    // MARK: - Init
    init() {
        bindSettings()
        loadSettings()
    }

    // MARK: - Settings Sync
    private func bindSettings() {
        $hapticsEnabled
            .sink { value in
                HapticManager.shared.setEnabled(value)
                self.logger.debug("Haptics setting changed: \(value)")
            }
            .store(in: &cancellables)

        $telemetryEnabled
            .sink { value in
                FeedbackRecorder.shared.setTelemetry(value)
                self.logger.debug("Telemetry setting changed: \(value)")
            }
            .store(in: &cancellables)

        $ethicsEnabled
            .sink { value in
                self.ethicsEngine.setEnabled(value)
                self.logger.notice("Ethics engine toggled: \(value)")
            }
            .store(in: &cancellables)

        $selectedTheme
            .sink { theme in
                ThemeManager.shared.apply(theme)
                self.logger.info("Theme changed to: \(theme.rawValue)")
            }
            .store(in: &cancellables)
    }

    // MARK: - Load Settings
    func loadSettings() {
        self.userID = sessionManager.userID
        self.hapticsEnabled = secureStorage.getBool(forKey: "hapticsEnabled", default: true)
        self.telemetryEnabled = secureStorage.getBool(forKey: "telemetryEnabled", default: false)
        self.ethicsEnabled = secureStorage.getBool(forKey: "ethicsEnabled", default: true)
        self.secureMode = secureStorage.getBool(forKey: "secureMode", default: true)
        self.selectedTheme = AppTheme(rawValue: secureStorage.getString(forKey: "selectedTheme") ?? "system") ?? .system

        logger.notice("Settings loaded for user: \(userID, privacy: .private)")
    }

    // MARK: - Change Mode
    func updateSecureMode(enabled: Bool) {
        secureMode = enabled
        secureStorage.setBool(enabled, forKey: "secureMode")
        logger.info("Secure mode updated: \(enabled)")
    }

    // MARK: - Theme
    func applyTheme(_ theme: AppTheme) {
        selectedTheme = theme
        secureStorage.setString(theme.rawValue, forKey: "selectedTheme")
        logger.info("Theme applied and stored: \(theme.rawValue)")
    }

    // MARK: - Intent Policy Sync
    func refreshIntentRules() {
        logger.notice("Refreshing AI intent policy from governance layer")
        intentValidator.reloadPolicy()
        feedbackRecorder.record(event: .intentPolicyRefreshed)
    }

    // MARK: - Reset App Logic
    func resetAppEnvironment() {
        logger.fault("Resetting app environment by user request")
        secureStorage.clearAll()
        sessionManager.terminateSession()
        feedbackRecorder.record(event: .manualResetTriggered)
    }

    // MARK: - Logout
    func performLogout() {
        logger.notice("Performing secure logout")
        sessionManager.terminateSession()
        feedbackRecorder.record(event: .userLoggedOut)
    }
}

// MARK: - Theme Enum
enum AppTheme: String, CaseIterable {
    case system, light, dark

    var displayName: String {
        switch self {
        case .system: return "System Default"
        case .light: return "Light"
        case .dark: return "Dark"
        }
    }
}

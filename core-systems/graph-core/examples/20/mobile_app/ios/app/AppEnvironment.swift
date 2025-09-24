import Foundation
import Combine
import SwiftUI
import OSLog

// MARK: - App Environment Container
final class AppEnvironment: ObservableObject {
    
    // MARK: - Shared Singleton Instance
    static let shared = AppEnvironment()
    
    // MARK: - Secure System Configuration
    @Published var isDebugModeEnabled: Bool = false
    @Published var currentLocale: Locale = .current
    @Published var appVersion: String = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "Unknown"
    @Published var buildNumber: String = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "Unknown"
    
    // MARK: - AI & Contextual Services
    let aiService: AIService
    let ethicsEngine: EthicsEngine
    let intentValidator: IntentValidator
    let realtimeAgent: RealtimeAgent
    let feedbackRecorder: FeedbackRecorder
    
    // MARK: - Zero-Trust / Secure Session Layer
    let secureStorage: SecureStorage
    let sessionManager: SessionManager
    
    // MARK: - User Interface Services
    let hapticManager: HapticManager
    let pushService: PushService
    let sensorBridge: SensorBridge
    
    // MARK: - System State
    let launchTimestamp: Date
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "AppEnvironment")
    
    // MARK: - Private Init
    private init() {
        self.aiService = AIService()
        self.ethicsEngine = EthicsEngine.shared
        self.intentValidator = IntentValidator()
        self.realtimeAgent = RealtimeAgent()
        self.feedbackRecorder = FeedbackRecorder()
        self.secureStorage = SecureStorage.shared
        self.sessionManager = SessionManager.shared
        self.hapticManager = HapticManager()
        self.pushService = PushService()
        self.sensorBridge = SensorBridge()
        self.launchTimestamp = Date()
        
        self.logger.notice("AppEnvironment initialized at \(self.launchTimestamp, privacy: .public)")
        self.initializeSecureContext()
    }
    
    // MARK: - Secure Context Bootstrap
    private func initializeSecureContext() {
        logger.info("Initializing secure AI context and moral layers")
        ethicsEngine.initializeMoralContext()
        intentValidator.setupContextualRules()
        realtimeAgent.bootstrap()
        feedbackRecorder.prepareRecording()
    }

    // MARK: - Public Methods
    func refreshLocale() {
        self.currentLocale = Locale.current
        logger.info("Locale refreshed: \(self.currentLocale.identifier, privacy: .public)")
    }

    func toggleDebugMode(_ enabled: Bool) {
        self.isDebugModeEnabled = enabled
        logger.log("Debug mode changed to \(enabled, privacy: .public)")
    }
}

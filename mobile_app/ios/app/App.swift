import SwiftUI
import Combine
import Foundation
import OSLog
import BackgroundTasks
import CoreHaptics
import UserNotifications

@main
struct TeslaAIMobileApp: App {
    // MARK: - Global Environment Objects
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @Environment(\.scenePhase) private var scenePhase

    // MARK: - Observed Global State
    @StateObject private var authViewModel = AuthViewModel()
    @StateObject private var settingsViewModel = SettingsViewModel()
    @StateObject private var aiService = AIService()
    @StateObject private var feedbackRecorder = FeedbackRecorder()

    // MARK: - System Services
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "AppLifecycle")
    private let intentValidator = IntentValidator()
    private let sessionManager = SessionManager.shared
    private let ethicsEngine = EthicsEngine.shared
    private let realtimeAgent = RealtimeAgent()
    private let hapticManager = HapticManager()

    // MARK: - App Entry
    var body: some Scene {
        WindowGroup {
            ZStack {
                if authViewModel.isAuthenticated {
                    VaultView()
                        .environmentObject(settingsViewModel)
                        .environmentObject(aiService)
                        .environmentObject(feedbackRecorder)
                        .onAppear {
                            ethicsEngine.evaluateSessionStart()
                            logger.info("User session started with ID: \(self.sessionManager.sessionID)")
                        }
                } else {
                    LoginView()
                        .environmentObject(authViewModel)
                        .transition(.opacity)
                }

                // Secure AI Overlay Intent Interface
                IntentOverlay()
                    .environmentObject(aiService)
                    .environmentObject(settingsViewModel)
            }
            .onAppear(perform: initialize)
            .modifier(AccessibilityOptimization())
        }
        .onChange(of: scenePhase, perform: handleScenePhase)
    }

    // MARK: - Initialization
    private func initialize() {
        logger.notice("App launched")
        hapticManager.prepareEngine()
        aiService.loadAIModel()
        feedbackRecorder.prepareRecording()
        realtimeAgent.bootstrap()
        BackgroundTaskScheduler.shared.registerTasks()
    }

    // MARK: - Scene Lifecycle Management
    private func handleScenePhase(_ newPhase: ScenePhase) {
        switch newPhase {
        case .active:
            logger.log("App entered active state")
            sessionManager.resume()
            hapticManager.triggerSoftFeedback()
        case .inactive:
            logger.debug("App is inactive")
        case .background:
            logger.log("App moved to background, saving session...")
            sessionManager.persist()
            ethicsEngine.evaluateSessionEnd()
            feedbackRecorder.flush()
        @unknown default:
            logger.error("Unknown scene phase encountered")
        }
    }
}

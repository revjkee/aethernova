import UIKit
import UserNotifications
import BackgroundTasks
import os

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    
    // MARK: - System Logger
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "AppDelegate")

    // MARK: - Core Services
    private let pushService = PushService()
    private let secureStorage = SecureStorage.shared
    private let ethicsEngine = EthicsEngine.shared
    private let realtimeAgent = RealtimeAgent()
    private let sessionManager = SessionManager.shared

    // MARK: - UIApplicationDelegate Methods

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        logger.notice("AppDelegate initialized — launch sequence started")
        
        configureNotifications(application)
        configureBackgroundTasks()
        sessionManager.initialize()
        realtimeAgent.bootstrap()
        ethicsEngine.initializeMoralContext()

        logger.notice("AppDelegate launch completed successfully")
        return true
    }

    func applicationWillTerminate(_ application: UIApplication) {
        logger.warning("Application is terminating")
        sessionManager.persist()
        ethicsEngine.evaluateSessionEnd()
    }

    func applicationDidEnterBackground(_ application: UIApplication) {
        logger.info("Application entered background")
        sessionManager.persist()
        realtimeAgent.flushMemory()
    }

    func applicationWillEnterForeground(_ application: UIApplication) {
        logger.info("Application will enter foreground")
        sessionManager.resume()
        ethicsEngine.evaluateSessionStart()
    }

    func applicationDidBecomeActive(_ application: UIApplication) {
        logger.debug("Application became active")
    }

    // MARK: - Notification Registration
    private func configureNotifications(_ application: UIApplication) {
        UNUserNotificationCenter.current().delegate = pushService
        pushService.registerForPushNotifications {
            self.logger.info("Push registration completed")
        }
    }

    // MARK: - Background Task Setup
    private func configureBackgroundTasks() {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: "com.teslaai.refresh",
            using: nil
        ) { task in
            self.handleBackgroundRefresh(task: task as! BGAppRefreshTask)
        }
        logger.debug("Background task registered")
    }

    private func handleBackgroundRefresh(task: BGAppRefreshTask) {
        logger.info("Background refresh started")

        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1

        let operation = BackgroundRefreshOperation()
        task.expirationHandler = {
            operation.cancel()
            self.logger.error("Background refresh expired before completion")
        }

        operation.completionBlock = {
            task.setTaskCompleted(success: !operation.isCancelled)
            self.logger.info("Background refresh completed")
        }

        queue.addOperation(operation)
    }
}

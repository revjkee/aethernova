import UIKit
import SwiftUI
import OSLog

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {

    var window: UIWindow?
    
    // MARK: - Logging & Session
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "SceneLifecycle")
    private let sessionManager = SessionManager.shared
    private let ethicsEngine = EthicsEngine.shared
    private let intentValidator = IntentValidator()

    // MARK: - Scene Lifecycle
    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions
    ) {
        guard let windowScene = scene as? UIWindowScene else {
            logger.error("Invalid scene type")
            return
        }

        logger.notice("Scene will connect: \(scene.session.configuration.name, privacy: .public)")
        ethicsEngine.evaluateSceneStart()

        let contentView = RootViewRouter.shared.start()
            .environmentObject(AuthViewModel())
            .environmentObject(SettingsViewModel())
            .environmentObject(AIService())
            .environmentObject(FeedbackRecorder())

        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = UIHostingController(rootView: contentView)
        self.window = window
        window.makeKeyAndVisible()
    }

    func sceneDidDisconnect(_ scene: UIScene) {
        logger.warning("Scene disconnected")
        sessionManager.persist()
        ethicsEngine.evaluateSceneEnd()
    }

    func sceneDidBecomeActive(_ scene: UIScene) {
        logger.info("Scene became active")
        sessionManager.resume()
    }

    func sceneWillResignActive(_ scene: UIScene) {
        logger.debug("Scene will resign active")
    }

    func sceneWillEnterForeground(_ scene: UIScene) {
        logger.debug("Scene will enter foreground")
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        logger.notice("Scene entered background")
        sessionManager.persist()
        FeedbackRecorder.shared.flush()
        ethicsEngine.evaluateSceneEnd()
    }
}

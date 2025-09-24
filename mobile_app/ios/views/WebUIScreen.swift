import SwiftUI
import WebKit
import OSLog

struct WebUIScreen: View {
    
    // MARK: - Configuration
    let webURL: URL
    let screenTitle: String

    // MARK: - State
    @State private var isLoading = true
    @State private var errorMessage: String?
    @State private var estimatedProgress: Double = 0.0
    @State private var showErrorOverlay = false

    // MARK: - Services
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "WebUIScreen")
    private let intentValidator = IntentValidator()
    private let ethicsEngine = EthicsEngine.shared
    private let sessionManager = SessionManager.shared

    // MARK: - UI
    var body: some View {
        ZStack {
            WebViewWrapper(
                url: webURL,
                progress: $estimatedProgress,
                isLoading: $isLoading,
                error: $errorMessage,
                policyValidator: { request in
                    intentValidator.validateWebRequest(request)
                }
            )
            .onAppear {
                logWebAccess()
            }

            if isLoading {
                LoadingView(message: "Loading WebUI...")
            }

            if let error = errorMessage {
                ErrorOverlay(message: error) {
                    showErrorOverlay = false
                    errorMessage = nil
                }
                .transition(.opacity)
            }
        }
        .navigationTitle(screenTitle)
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: errorMessage) { error in
            if let error = error {
                showErrorOverlay = true
                logger.error("WebUI load error: \(error)")
                FeedbackRecorder.shared.record(event: .webUIError(error))
            }
        }
    }

    // MARK: - Logging
    private func logWebAccess() {
        logger.info("Accessing WebUIScreen at URL: \(webURL.absoluteString, privacy: .public)")
        sessionManager.logWebAccess(url: webURL)
        ethicsEngine.evaluateWebAccess(url: webURL)
    }
}

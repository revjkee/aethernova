import Foundation
import WebKit
import OSLog
import Combine

final class WebUICoordinator: NSObject, WKNavigationDelegate, ObservableObject {

    // MARK: - Singleton
    static let shared = WebUICoordinator()

    // MARK: - Published States
    @Published var currentURL: URL?
    @Published var isSecureSessionActive: Bool = false
    @Published var lastInjectedIntent: String?

    // MARK: - Internals
    private var webView: WKWebView?
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "WebUICoordinator")
    private var cancellables = Set<AnyCancellable>()

    // MARK: - Configuration
    func configure(for webView: WKWebView) {
        self.webView = webView
        webView.navigationDelegate = self
        webView.configuration.preferences.javaScriptEnabled = true

        logger.notice("WebUICoordinator configured")
    }

    // MARK: - Navigation Control
    func loadSecure(url: URL) {
        guard isURLAllowed(url) else {
            logger.error("Blocked unauthorized WebUI URL: \(url.absoluteString)")
            return
        }

        currentURL = url
        isSecureSessionActive = true
        webView?.load(URLRequest(url: url))
        logger.info("Loading secure WebUI: \(url.absoluteString)")
    }

    func reload() {
        webView?.reload()
        logger.debug("WebUI reloaded")
    }

    func closeSession() {
        webView?.stopLoading()
        webView?.loadHTMLString("", baseURL: nil)
        currentURL = nil
        isSecureSessionActive = false
        logger.notice("WebUI session closed")
    }

    // MARK: - JavaScript Injection
    func injectIntentScript(_ intent: AgentIntent) {
        guard isSecureSessionActive,
              let jsonData = try? JSONEncoder().encode(intent),
              let jsonString = String(data: jsonData, encoding: .utf8) else {
            logger.error("Failed to inject intent: encoding failure")
            return
        }

        let script = "window.receiveIntent(\(jsonString));"
        webView?.evaluateJavaScript(script) { result, error in
            if let error = error {
                self.logger.error("Intent injection failed: \(error.localizedDescription)")
            } else {
                self.lastInjectedIntent = intent.intentType.rawValue
                self.logger.debug("Intent injected: \(intent.intentType.rawValue)")
            }
        }
    }

    // MARK: - WebView Delegate
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        logger.info("WebUI navigation completed: \(webView.url?.absoluteString ?? "-")")
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        logger.error("WebUI navigation error: \(error.localizedDescription)")
    }

    // MARK: - URL Trust Policy
    private func isURLAllowed(_ url: URL) -> Bool {
        let allowedDomains = [
            "app.teslaai.io",
            "webui.teslaai.local",
            "secure-control.local"
        ]

        guard let host = url.host else { return false }

        return allowedDomains.contains(where: { host.contains($0) })
    }

    // MARK: - Restore State (optional)
    func restoreState(from snapshot: WebUISnapshot) {
        guard let url = snapshot.url else { return }
        loadSecure(url: url)
    }

    func exportSnapshot() -> WebUISnapshot {
        return WebUISnapshot(url: currentURL)
    }
}

// MARK: - Snapshot Object
struct WebUISnapshot: Codable {
    let url: URL?
}

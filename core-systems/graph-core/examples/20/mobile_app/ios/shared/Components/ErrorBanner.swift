import SwiftUI
import Combine
import OSLog

struct ErrorBanner: View {

    // MARK: - Input
    var message: String
    var level: BannerLevel = .error
    var duration: TimeInterval = 4.5
    var roleRestricted: [UserRole]? = nil

    // MARK: - State
    @State private var isVisible: Bool = false
    @State private var timer: Timer?
    @Environment(\.colorScheme) private var colorScheme

    // MARK: - System
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "ErrorBanner")
    private let feedbackRecorder = FeedbackRecorder.shared
    private let ethics = EthicsEngine.shared

    var body: some View {
        VStack {
            if isVisible {
                HStack(alignment: .center) {
                    Image(systemName: level.icon)
                        .foregroundColor(.white)
                        .padding(.trailing, 4)

                    Text(localizedMessage())
                        .font(.subheadline)
                        .foregroundColor(.white)
                        .multilineTextAlignment(.leading)
                        .lineLimit(3)

                    Spacer()

                    Button(action: dismiss) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.white.opacity(0.7))
                    }
                }
                .padding(12)
                .background(level.backgroundColor)
                .cornerRadius(12)
                .shadow(radius: 4)
                .transition(.move(edge: .top).combined(with: .opacity))
                .padding(.horizontal, 16)
                .onAppear {
                    validateAndDisplay()
                }
            }
        }
        .animation(.easeInOut(duration: 0.3), value: isVisible)
    }

    // MARK: - Logic
    private func validateAndDisplay() {
        guard roleIsAllowed() else {
            logger.warning("ErrorBanner suppressed for restricted role")
            return
        }

        if ethics.classify(message: message) == .sensitive {
            logger.critical("ErrorBanner message classified as sensitive: hidden")
            feedbackRecorder.record(event: .sensitiveErrorDetected(message))
            return
        }

        isVisible = true
        feedbackRecorder.record(event: .errorBannerDisplayed(message))

        timer = Timer.scheduledTimer(withTimeInterval: duration, repeats: false) { _ in
            dismiss()
        }
    }

    private func dismiss() {
        isVisible = false
        timer?.invalidate()
        logger.info("ErrorBanner dismissed")
    }

    private func roleIsAllowed() -> Bool {
        guard let restricted = roleRestricted else { return true }
        let current = SessionManager.shared.currentUserRole
        return restricted.contains(current)
    }

    private func localizedMessage() -> String {
        // Future expansion: error localization based on context
        return message
    }
}

// MARK: - Banner Levels
enum BannerLevel: String, Codable {
    case info, warning, error, critical

    var icon: String {
        switch self {
        case .info: return "info.circle"
        case .warning: return "exclamationmark.triangle"
        case .error: return "xmark.octagon"
        case .critical: return "flame"
        }
    }

    var backgroundColor: Color {
        switch self {
        case .info: return Color.blue.opacity(0.85)
        case .warning: return Color.orange.opacity(0.9)
        case .error: return Color.red.opacity(0.9)
        case .critical: return Color.purple.opacity(0.95)
        }
    }
}

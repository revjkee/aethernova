import SwiftUI
import OSLog
import Combine

struct LoadingView: View {
    // MARK: - Input Params
    var message: String = "Загрузка..."
    var showSpinner: Bool = true
    var allowCancel: Bool = false
    var isSecureContext: Bool = true
    var aiFeedbackContext: String? = nil

    // MARK: - State
    @State private var isCancelled = false
    @State private var opacity: Double = 0.0

    // MARK: - System
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "LoadingView")
    private let feedbackRecorder = FeedbackRecorder.shared

    // MARK: - Body
    var body: some View {
        ZStack {
            Color.black.opacity(0.5)
                .edgesIgnoringSafeArea(.all)

            VStack(spacing: 16) {
                if showSpinner {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        .scaleEffect(1.4)
                        .accessibilityLabel("Индикация загрузки")
                }

                Text(isCancelled ? "Отменено" : message)
                    .font(.headline)
                    .foregroundColor(.white)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)

                if allowCancel && !isCancelled {
                    Button(action: cancelOperation) {
                        Text("Отменить")
                            .font(.subheadline)
                            .foregroundColor(.red)
                            .padding(.top, 8)
                    }
                    .accessibilityIdentifier("CancelButton")
                }
            }
            .padding()
            .background(
                RoundedRectangle(cornerRadius: 18)
                    .fill(Color(UIColor.systemGray6).opacity(0.2))
                    .blur(radius: 0.4)
            )
            .padding(.horizontal, 32)
            .opacity(opacity)
            .onAppear {
                withAnimation(.easeIn(duration: 0.3)) {
                    opacity = 1.0
                }
                recordAnalytics()
            }
        }
        .transition(.opacity)
    }

    // MARK: - Cancel Handler
    private func cancelOperation() {
        isCancelled = true
        logger.warning("LoadingView manually cancelled")
        feedbackRecorder.record(event: .userCancelledOperation)

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            opacity = 0.0
        }
    }

    // MARK: - Analytics & Ethics
    private func recordAnalytics() {
        logger.info("LoadingView shown | Secure: \(isSecureContext) | AIContext: \(aiFeedbackContext ?? "-")")

        if isSecureContext, let ctx = aiFeedbackContext {
            feedbackRecorder.record(event: .contextualLoadingShown(ctx))
        }

        if !isSecureContext {
            feedbackRecorder.record(event: .insecureContextWarning)
        }
    }
}

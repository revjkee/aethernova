import SwiftUI
import Combine

struct ErrorView: View {

    // MARK: - Input State
    let errorTitle: String
    let errorMessage: String
    let recoverable: Bool
    let retryAction: (() -> Void)?
    let reportAction: (() -> Void)?

    // MARK: - View State
    @State private var showIntentOverlay = false
    @State private var isExpanded = false
    @Environment(\.colorScheme) var colorScheme

    // MARK: - UI Body
    var body: some View {
        VStack(spacing: 16) {
            Spacer()
            
            Image(systemName: "exclamationmark.triangle.fill")
                .resizable()
                .scaledToFit()
                .frame(width: 64, height: 64)
                .foregroundColor(.red)

            Text(errorTitle)
                .font(.title)
                .fontWeight(.semibold)
                .multilineTextAlignment(.center)

            VStack(spacing: 8) {
                Text(errorMessage)
                    .font(.body)
                    .multilineTextAlignment(.center)
                    .foregroundColor(.secondary)

                if isExpanded {
                    Button("Hide Details") {
                        isExpanded = false
                    }
                } else {
                    Button("Show Details") {
                        isExpanded = true
                    }
                }

                if isExpanded {
                    Text("Timestamp: \(Date().formatted(date: .numeric, time: .standard))")
                        .font(.caption)
                        .foregroundColor(.gray)
                    Text("Session ID: \(SessionManager.shared.sessionID.prefix(8))...")
                        .font(.caption)
                        .foregroundColor(.gray)
                }
            }
            .padding(.horizontal)

            if recoverable {
                Button(action: {
                    HapticManager.shared.triggerSoftFeedback()
                    retryAction?()
                }) {
                    IntentButton(title: "Retry", isLoading: false)
                }
                .padding(.top, 4)
            }

            Button(action: {
                showIntentOverlay = true
            }) {
                IntentButton(title: "AI Recovery Help", isLoading: false)
            }

            if let report = reportAction {
                Button(action: {
                    report()
                }) {
                    Label("Report Issue", systemImage: "paperplane")
                        .font(.callout)
                        .padding(.top, 4)
                }
            }

            Spacer()
        }
        .padding()
        .background(
            Color(.systemBackground)
                .edgesIgnoringSafeArea(.all)
        )
        .sheet(isPresented: $showIntentOverlay) {
            IntentOverlay(title: "AI Recovery Options") {
                AIService().suggestRecovery(for: errorMessage)
                showIntentOverlay = false
            }
        }
        .onAppear {
            FeedbackRecorder.shared.record(event: .errorDisplayed(message: errorMessage))
        }
    }
}

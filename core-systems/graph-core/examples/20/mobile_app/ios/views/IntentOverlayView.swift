import SwiftUI
import Combine

struct IntentOverlayView: View {

    // MARK: - External Control
    @Binding var isPresented: Bool
    let title: String

    // MARK: - Internal State
    @State private var intentText: String = ""
    @State private var feedback: String = ""
    @State private var aiResponse: String = ""
    @State private var isSubmitting: Bool = false

    @ObservedObject private var aiService = AIService()
    @ObservedObject private var ethicsEngine = EthicsEngine.shared
    @ObservedObject private var feedbackRecorder = FeedbackRecorder()

    // MARK: - UI Body
    var body: some View {
        VStack(spacing: 16) {
            HStack {
                Text(title)
                    .font(.headline)
                    .foregroundColor(.primary)
                Spacer()
                Button(action: {
                    HapticManager.shared.triggerSoftFeedback()
                    isPresented = false
                }) {
                    Image(systemName: "xmark.circle.fill")
                        .font(.title2)
                        .foregroundColor(.secondary)
                }
            }

            Divider()

            VStack(alignment: .leading, spacing: 12) {
                Text("Enter AI Command:")
                    .font(.subheadline)
                    .foregroundColor(.secondary)

                TextEditor(text: $intentText)
                    .frame(height: 100)
                    .padding(8)
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(8)
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.gray.opacity(0.2)))

                Button(action: {
                    submitIntent()
                }) {
                    IntentButton(title: "Submit Intent", isLoading: isSubmitting)
                }
                .disabled(intentText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                if !aiResponse.isEmpty {
                    Divider()
                    Text("AI Response:")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                    Text(aiResponse)
                        .font(.body)
                        .padding(8)
                        .background(Color(.tertiarySystemFill))
                        .cornerRadius(8)
                }

                if ethicsEngine.isViolationDetected {
                    Text("⚠️ Intent violates ethical policy")
                        .font(.caption)
                        .foregroundColor(.red)
                        .padding(.top, 4)
                }

                Divider()
                VStack(alignment: .leading, spacing: 8) {
                    Text("Feedback (optional):")
                        .font(.subheadline)
                    TextEditor(text: $feedback)
                        .frame(height: 60)
                        .padding(8)
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(8)

                    Button(action: {
                        feedbackRecorder.record(event: .manualFeedback(feedback))
                        HapticManager.shared.triggerSuccess()
                        feedback = ""
                    }) {
                        Label("Send Feedback", systemImage: "paperplane")
                            .font(.callout)
                    }
                }
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(Color(.systemBackground))
                .shadow(radius: 16)
        )
        .padding()
        .transition(.move(edge: .bottom))
        .onAppear {
            FeedbackRecorder.shared.record(event: .intentOverlayOpened)
        }
    }

    // MARK: - Submit AI Intent
    private func submitIntent() {
        isSubmitting = true
        HapticManager.shared.triggerSoftFeedback()

        Task {
            do {
                let evaluated = ethicsEngine.evaluate(intentText)
                guard evaluated.isAllowed else {
                    ethicsEngine.flagViolation(intentText)
                    aiResponse = "⚠️ Intent denied by ethical policy."
                    isSubmitting = false
                    return
                }

                aiResponse = try await aiService.executeIntent(intentText)
                feedbackRecorder.record(event: .intentSubmitted(intentText))
            } catch {
                aiResponse = "Error processing intent: \(error.localizedDescription)"
            }
            isSubmitting = false
        }
    }
}

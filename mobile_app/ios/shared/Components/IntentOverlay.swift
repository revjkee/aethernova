import SwiftUI
import Combine
import OSLog

struct IntentOverlay: View {

    // MARK: - Inputs
    var context: AgentIntent
    var title: String = "Запрос выполняется..."
    var dismissAfter: TimeInterval? = 4.0
    var onComplete: ((Bool) -> Void)? = nil

    // MARK: - State
    @State private var isProcessing: Bool = true
    @State private var resultStatus: IntentResultStatus?
    @State private var animatePulse = false

    // MARK: - System
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "IntentOverlay")
    private let ethics = EthicsEngine.shared
    private let validator = IntentValidator.shared
    private let feedback = FeedbackRecorder.shared

    var body: some View {
        ZStack {
            Color.black.opacity(0.45).edgesIgnoringSafeArea(.all)

            VStack(spacing: 24) {
                Spacer()

                RoundedRectangle(cornerRadius: 18)
                    .fill(Color(UIColor.secondarySystemBackground))
                    .frame(width: 60, height: 60)
                    .overlay(
                        Image(systemName: iconForStatus())
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .foregroundColor(iconColor())
                            .padding(14)
                    )
                    .shadow(radius: 6)
                    .scaleEffect(animatePulse ? 1.1 : 1.0)
                    .animation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true), value: animatePulse)

                Text(resultStatus?.message ?? title)
                    .font(.headline)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)

                Spacer()
            }
            .padding()
        }
        .onAppear {
            animatePulse = true
            Task { await beginIntentExecution() }
        }
    }

    // MARK: - Logic
    private func beginIntentExecution() async {
        guard validator.validate(intent: context) else {
            logger.error("Intent rejected by validator: \(context.intentType.rawValue)")
            showResult(.rejected("Недопустимый интент"))
            feedback.record(event: .intentRejected(context.intentType.rawValue))
            return
        }

        guard ethics.evaluateIntent(context) else {
            logger.critical("Intent rejected by EthicsEngine: \(context.intentType.rawValue)")
            showResult(.rejected("Запрещено политикой безопасности"))
            feedback.record(event: .ethicalBlock(context.intentType.rawValue))
            return
        }

        logger.info("Executing intent: \(context.intentType.rawValue)")
        feedback.triggerHaptic(.start)

        let result = await AIService.shared.sendIntent(context)

        DispatchQueue.main.async {
            if result {
                showResult(.success)
                feedback.triggerHaptic(.success)
            } else {
                showResult(.failed("Не удалось выполнить"))
                feedback.triggerHaptic(.error)
            }
        }
    }

    private func showResult(_ status: IntentResultStatus) {
        self.resultStatus = status
        self.isProcessing = false
        logger.info("Intent execution completed with status: \(status.rawValue)")
        if let delay = dismissAfter {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
                onComplete?(status == .success)
            }
        }
    }

    // MARK: - Helpers
    private func iconForStatus() -> String {
        switch resultStatus {
        case .success: return "checkmark.circle.fill"
        case .failed: return "xmark.octagon.fill"
        case .rejected: return "exclamationmark.triangle.fill"
        case .none: return "hourglass"
        }
    }

    private func iconColor() -> Color {
        switch resultStatus {
        case .success: return .green
        case .failed: return .red
        case .rejected: return .orange
        case .none: return .blue
        }
    }
}

// MARK: - Intent Status
enum IntentResultStatus: String {
    case success
    case failed(String)
    case rejected(String)

    var message: String {
        switch self {
        case .success:
            return "Выполнено"
        case .failed(let msg), .rejected(let msg):
            return msg
        }
    }
}

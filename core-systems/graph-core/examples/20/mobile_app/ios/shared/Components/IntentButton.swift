import SwiftUI
import Combine
import OSLog

struct IntentButton: View {
    // MARK: - Parameters
    var title: String
    var intent: AgentIntent
    var roleRestriction: [UserRole]? = nil
    var icon: String = "bolt.fill"
    var intentColor: Color = .blue
    var isDestructive: Bool = false

    // MARK: - State
    @State private var isExecuting: Bool = false
    @State private var showError: Bool = false
    @State private var errorMessage: String?

    // MARK: - System
    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "IntentButton")
    private let feedback = FeedbackRecorder.shared
    private let validator = IntentValidator.shared
    private let ethics = EthicsEngine.shared

    var body: some View {
        Button(action: {
            executeIntent()
        }) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(.white)
                Text(title)
                    .foregroundColor(.white)
                    .fontWeight(.semibold)
            }
            .padding(.vertical, 12)
            .padding(.horizontal, 20)
            .background(isDestructive ? Color.red : intentColor)
            .cornerRadius(14)
            .shadow(radius: 2)
        }
        .disabled(isExecuting || !canExecute())
        .opacity(isExecuting ? 0.6 : 1.0)
        .accessibilityLabel("Intent: \(title)")
        .alert(isPresented: $showError) {
            Alert(title: Text("Ошибка"),
                  message: Text(errorMessage ?? "Не удалось выполнить интент"),
                  dismissButton: .default(Text("ОК")))
        }
    }

    // MARK: - Permission & Execution
    private func canExecute() -> Bool {
        guard let currentRole = SessionManager.shared.currentUserRole else { return false }
        return roleRestriction == nil || roleRestriction!.contains(currentRole)
    }

    private func executeIntent() {
        guard !isExecuting else {
            logger.warning("Intent \(intent.intentType.rawValue) ignored: already executing")
            return
        }

        guard validator.validate(intent: intent) else {
            logger.error("Intent validation failed: \(intent.intentType.rawValue)")
            errorMessage = "Недопустимое действие"
            showError = true
            return
        }

        guard ethics.evaluateIntent(intent) else {
            logger.critical("EthicsEngine rejected intent: \(intent.intentType.rawValue)")
            errorMessage = "Действие не разрешено этическим модулем"
            showError = true
            return
        }

        isExecuting = true
        logger.info("Intent execution started: \(intent.intentType.rawValue)")
        feedback.triggerHaptic(.start)

        Task {
            let success = await performIntentAction(intent)
            DispatchQueue.main.async {
                isExecuting = false
                if success {
                    feedback.triggerHaptic(.success)
                    logger.info("Intent executed successfully: \(intent.intentType.rawValue)")
                } else {
                    feedback.triggerHaptic(.error)
                    errorMessage = "Ошибка выполнения"
                    showError = true
                    logger.error("Intent failed during execution")
                }
            }
        }
    }

    private func performIntentAction(_ intent: AgentIntent) async -> Bool {
        // Подключаем внешнюю реализацию через AIService
        return await AIService.shared.sendIntent(intent)
    }
}

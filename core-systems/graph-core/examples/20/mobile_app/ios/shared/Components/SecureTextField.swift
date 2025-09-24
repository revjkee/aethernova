import SwiftUI
import Combine
import LocalAuthentication
import OSLog

struct SecureTextField: View {

    // MARK: - Input Binding
    @Binding var text: String
    var placeholder: String = "••••••••"
    var isSecure: Bool = true
    var keyboardType: UIKeyboardType = .default
    var accessibilityIdentifier: String?

    // MARK: - Internal States
    @State private var isSecureEntry: Bool = true
    @State private var showBiometricPrompt: Bool = false
    @State private var validationMessage: String?
    @FocusState private var isFocused: Bool

    private let logger = Logger(subsystem: "com.teslaai.mobileapp", category: "SecureTextField")

    // MARK: - View
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                if isSecure && isSecureEntry {
                    SecureField(placeholder, text: $text)
                        .keyboardType(keyboardType)
                        .focused($isFocused)
                        .textContentType(.oneTimeCode) // prevent iCloud password autofill
                        .onChange(of: text, perform: validateInput)
                        .accessibilityIdentifier(accessibilityIdentifier)
                } else {
                    TextField(placeholder, text: $text)
                        .keyboardType(keyboardType)
                        .focused($isFocused)
                        .onChange(of: text, perform: validateInput)
                        .accessibilityIdentifier(accessibilityIdentifier)
                }

                Button(action: {
                    isSecureEntry.toggle()
                    logger.debug("Toggled secure entry: \(isSecureEntry.description)")
                }) {
                    Image(systemName: isSecureEntry ? "eye.slash" : "eye")
                        .foregroundColor(.gray)
                }
            }
            .padding(12)
            .background(RoundedRectangle(cornerRadius: 10).stroke(Color.gray.opacity(0.2)))

            if let message = validationMessage {
                Text(message)
                    .font(.caption)
                    .foregroundColor(.red)
            }
        }
        .onAppear {
            if isSecure {
                authenticateWithBiometrics()
            }
        }
    }

    // MARK: - Validation + Pattern Filter
    private func validateInput(_ value: String) {
        if value.contains("<script>") || value.contains("DROP TABLE") {
            validationMessage = "Ввод содержит опасные шаблоны"
            logger.error("Pattern violation detected in SecureTextField")
            FeedbackRecorder.shared.record(event: .dangerousInputDetected(value))
            text = ""
        } else if value.count > 64 {
            validationMessage = "Слишком длинный ввод"
        } else {
            validationMessage = nil
        }
    }

    // MARK: - Biometrics Gate
    private func authenticateWithBiometrics() {
        let context = LAContext()
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                   localizedReason: "Подтвердите доступ к защищённому полю") { success, authError in
                DispatchQueue.main.async {
                    if success {
                        logger.info("Biometric authentication succeeded")
                    } else {
                        logger.error("Biometric auth failed: \(authError?.localizedDescription ?? "-")")
                        validationMessage = "Ошибка аутентификации"
                        isSecureEntry = false
                    }
                }
            }
        } else {
            logger.warning("Biometrics unavailable: \(error?.localizedDescription ?? "-")")
        }
    }
}

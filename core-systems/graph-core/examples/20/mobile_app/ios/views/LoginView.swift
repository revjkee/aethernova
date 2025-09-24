import SwiftUI
import Combine

struct LoginView: View {
    
    // MARK: - View Models
    @StateObject private var authViewModel = AuthViewModel()
    @State private var email: String = ""
    @State private var password: String = ""
    @State private var showError: Bool = false
    @State private var showIntentOverlay: Bool = false
    
    // MARK: - Focus Management
    @FocusState private var focusedField: Field?
    private enum Field: Hashable {
        case email, password
    }

    // MARK: - Body
    var body: some View {
        ZStack {
            VStack(spacing: 24) {
                Spacer()
                
                Text("Welcome to TeslaAI Vault")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                    .multilineTextAlignment(.center)
                
                SecureTextField(
                    label: "Email",
                    text: $email,
                    isSecure: false
                )
                .keyboardType(.emailAddress)
                .textContentType(.emailAddress)
                .autocapitalization(.none)
                .focused($focusedField, equals: .email)

                SecureTextField(
                    label: "Password",
                    text: $password,
                    isSecure: true
                )
                .textContentType(.password)
                .focused($focusedField, equals: .password)

                if showError {
                    ErrorBanner(message: authViewModel.errorMessage)
                        .transition(.opacity)
                }

                Button(action: {
                    Task {
                        await handleLogin()
                    }
                }) {
                    IntentButton(title: "Sign In", isLoading: authViewModel.isLoading)
                }
                .disabled(!authViewModel.isFormValid(email: email, password: password))

                Spacer()
                Text("AI-Secured Access. Ethics Engine Active.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            }
            .padding()
            .background(
                Color(.systemBackground)
                    .ignoresSafeArea()
            )

            // Intent Overlay Integration
            if showIntentOverlay {
                IntentOverlay(title: "AI Login Help") {
                    showIntentOverlay = false
                }
            }
        }
        .onTapGesture {
            focusedField = nil
        }
        .onAppear {
            authViewModel.resetState()
        }
        .onChange(of: email) { _ in validateInput() }
        .onChange(of: password) { _ in validateInput() }
        .modifier(AccessibilityOptimization())
    }

    // MARK: - Methods
    private func handleLogin() async {
        focusedField = nil
        showError = false
        let success = await authViewModel.login(email: email, password: password)
        if !success {
            showError = true
            FeedbackRecorder.shared.record(event: .loginFailure)
        } else {
            HapticManager.shared.triggerSuccess()
            FeedbackRecorder.shared.record(event: .loginSuccess)
        }
    }

    private func validateInput() {
        if !authViewModel.isFormValid(email: email, password: password) {
            showError = false
        }
    }
}

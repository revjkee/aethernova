import SwiftUI
import Combine

struct SettingsView: View {

    // MARK: - ViewModel & Environment
    @StateObject private var viewModel = SettingsViewModel()
    @Environment(\.colorScheme) private var colorScheme
    @State private var showOverlay: Bool = false
    @State private var isSecureMode: Bool = true

    // MARK: - Body
    var body: some View {
        NavigationView {
            Form {
                // MARK: - User Identity
                Section(header: Text("User Profile")) {
                    HStack {
                        Text("User ID")
                        Spacer()
                        Text(viewModel.userID)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    
                    Toggle("Secure Mode", isOn: $isSecureMode)
                        .onChange(of: isSecureMode) { value in
                            viewModel.updateSecureMode(enabled: value)
                        }
                }

                // MARK: - App Preferences
                Section(header: Text("Preferences")) {
                    Picker("Theme", selection: $viewModel.selectedTheme) {
                        ForEach(AppTheme.allCases, id: \.self) { theme in
                            Text(theme.displayName).tag(theme)
                        }
                    }
                    .onChange(of: viewModel.selectedTheme) { theme in
                        viewModel.applyTheme(theme)
                    }

                    Toggle("Enable Haptics", isOn: $viewModel.hapticsEnabled)
                        .onChange(of: viewModel.hapticsEnabled) { _ in
                            HapticManager.shared.setEnabled(viewModel.hapticsEnabled)
                        }

                    Toggle("Send Anonymous Telemetry", isOn: $viewModel.telemetryEnabled)
                        .onChange(of: viewModel.telemetryEnabled) { value in
                            FeedbackRecorder.shared.setTelemetry(value)
                        }
                }

                // MARK: - AI & Ethics
                Section(header: Text("AI & Governance")) {
                    Toggle("Ethics Engine Enabled", isOn: $viewModel.ethicsEnabled)
                        .onChange(of: viewModel.ethicsEnabled) { value in
                            EthicsEngine.shared.setEnabled(value)
                        }

                    Button(action: {
                        showOverlay = true
                    }) {
                        Label("Review AI Intent Policies", systemImage: "eye.trianglebadge.exclamationmark")
                    }
                }

                // MARK: - System
                Section(header: Text("System")) {
                    Button(role: .destructive) {
                        viewModel.resetAppEnvironment()
                    } label: {
                        Label("Reset App Environment", systemImage: "arrow.counterclockwise")
                    }

                    Button(action: {
                        viewModel.performLogout()
                    }) {
                        Label("Logout", systemImage: "lock.open")
                    }
                }
            }
            .navigationTitle("Settings")
            .sheet(isPresented: $showOverlay) {
                IntentOverlay(title: "AI Intent Policy") {
                    viewModel.refreshIntentRules()
                    showOverlay = false
                }
            }
        }
        .onAppear {
            viewModel.loadSettings()
        }
    }
}

// MARK: - AppTheme Enum
enum AppTheme: String, CaseIterable {
    case system, light, dark

    var displayName: String {
        switch self {
        case .system: return "System Default"
        case .light: return "Light"
        case .dark: return "Dark"
        }
    }
}

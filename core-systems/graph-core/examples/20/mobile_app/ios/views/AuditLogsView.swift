import SwiftUI
import Combine

struct AuditLogsView: View {

    // MARK: - ViewModel & Environment
    @StateObject private var viewModel = LogsViewModel()
    @Environment(\.colorScheme) var colorScheme
    @State private var selectedSeverity: SeverityFilter = .all
    @State private var searchQuery: String = ""
    @State private var showOverlay: Bool = false

    // MARK: - UI Body
    var body: some View {
        NavigationView {
            VStack(spacing: 12) {
                
                // MARK: - Search & Filter Controls
                HStack {
                    TextField("Search logs", text: $searchQuery)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .onChange(of: searchQuery) { _ in
                            viewModel.filterLogs(query: searchQuery, severity: selectedSeverity)
                        }

                    Menu {
                        ForEach(SeverityFilter.allCases, id: \.self) { filter in
                            Button(action: {
                                selectedSeverity = filter
                                viewModel.filterLogs(query: searchQuery, severity: selectedSeverity)
                            }) {
                                Label(filter.rawValue, systemImage: filter.iconName)
                            }
                        }
                    } label: {
                        Label("Filter", systemImage: "line.3.horizontal.decrease.circle")
                            .labelStyle(IconOnlyLabelStyle())
                            .padding(.horizontal)
                    }
                }
                .padding(.horizontal)

                // MARK: - Logs Table
                List {
                    ForEach(viewModel.filteredLogs, id: \.id) { log in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                Text(log.title)
                                    .font(.headline)
                                Spacer()
                                Text(log.timestamp, style: .time)
                                    .font(.caption)
                                    .foregroundColor(.gray)
                            }
                            Text(log.details)
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                            HStack {
                                Text("Source: \(log.source)")
                                    .font(.caption)
                                Spacer()
                                Label(log.severity.rawValue, systemImage: log.severity.iconName)
                                    .font(.caption2)
                                    .foregroundColor(log.severity.color)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                }
                .listStyle(InsetGroupedListStyle())
                .refreshable {
                    await viewModel.fetchAuditLogs()
                }

                // MARK: - AI Intent Overlay Button
                Button {
                    showOverlay = true
                } label: {
                    IntentButton(title: "Run AI Analysis")
                }
                .padding()
            }
            .navigationTitle("Audit Logs")
            .sheet(isPresented: $showOverlay) {
                IntentOverlay(title: "AI Log Insights") {
                    viewModel.analyzeWithAI()
                    showOverlay = false
                }
            }
        }
        .onAppear {
            Task {
                await viewModel.fetchAuditLogs()
            }
        }
    }
}

// MARK: - SeverityFilter Enum
enum SeverityFilter: String, CaseIterable {
    case all = "All"
    case low = "Low"
    case medium = "Medium"
    case high = "High"
    case critical = "Critical"

    var iconName: String {
        switch self {
        case .all: return "line.horizontal.3"
        case .low: return "circle"
        case .medium: return "exclamationmark.circle"
        case .high: return "exclamationmark.triangle"
        case .critical: return "flame"
        }
    }

    var color: Color {
        switch self {
        case .low: return .green
        case .medium: return .yellow
        case .high: return .orange
        case .critical: return .red
        default: return .primary
        }
    }
}

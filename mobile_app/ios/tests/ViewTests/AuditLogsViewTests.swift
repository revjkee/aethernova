import XCTest
import SwiftUI
import ViewInspector
@testable import TeslaAIApp

final class AuditLogsViewTests: XCTestCase {

    // MARK: - Subject
    var viewModel: AuditLogsViewModel!
    var auditView: AuditLogsView!

    override func setUpWithError() throws {
        viewModel = AuditLogsViewModel(mockMode: true)
        auditView = AuditLogsView(viewModel: viewModel)
    }

    // MARK: - Test: Log rendering
    func testAuditLogsAreRendered() throws {
        viewModel.loadMockLogs()
        let logs = try auditView.inspect().find(viewWithId: "logsList")
        XCTAssertGreaterThanOrEqual(try logs.forEach().count, 3, "Expected at least 3 audit logs displayed")
    }

    // MARK: - Test: Confidential masking
    func testConfidentialEventsAreMasked() throws {
        viewModel.loadMockLogs()
        viewModel.maskSensitiveLogs = true

        let logRow = try auditView.inspect().find(viewWithId: "logRow-1")
        let text = try logRow.find(text: "eventMasked")
        XCTAssertEqual(try text.string(), "•••• confidential ••••")
    }

    // MARK: - Test: Filter toggle
    func testFilterToggleAffectsLogs() throws {
        viewModel.loadMockLogs()
        viewModel.showOnlyCritical.toggle()

        XCTAssertTrue(viewModel.logs.allSatisfy { $0.isCritical }, "Only critical logs should be shown")
    }

    // MARK: - Test: Localization label visible
    func testLocalizedAuditTitle() throws {
        let title = try auditView.inspect().find(text: "audit.title")
        XCTAssertEqual(try title.string(), NSLocalizedString("audit.title", comment: "Audit View Title"))
    }

    // MARK: - Test: Empty state behavior
    func testEmptyStateShownWhenNoLogs() throws {
        viewModel.clearLogs()
        let emptyText = try auditView.inspect().find(text: "No logs recorded")

        XCTAssertEqual(try emptyText.string(), "No logs recorded")
    }

    // MARK: - Test: Redact toggle visibility
    func testRedactToggleAppears() throws {
        let toggle = try auditView.inspect().find(ViewType.Toggle.self)
        XCTAssertNoThrow(try toggle.find(text: "Mask Confidential Events"))
    }

    // MARK: - Test: Real-time update
    func testLogAppearsAfterRealtimeInsert() throws {
        let newEvent = AuditLog(id: UUID(), timestamp: .now, message: "Realtime Test", isCritical: true)
        viewModel.appendLog(event: newEvent)

        let match = viewModel.logs.first { $0.message.contains("Realtime Test") }
        XCTAssertNotNil(match, "Inserted log should appear in visible logs")
    }

    // MARK: - Test: Accessibility label
    func testAccessibilityIsSet() throws {
        let list = try auditView.inspect().find(ViewType.List.self)
        XCTAssertEqual(list.accessibilityLabel(), "Audit Logs List")
    }
}

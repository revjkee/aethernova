import XCTest
import SwiftUI
import ViewInspector
@testable import TeslaAIApp

final class VaultViewTests: XCTestCase {

    // MARK: - Subject Under Test
    var viewModel: VaultViewModel!
    var vaultView: VaultView!

    override func setUpWithError() throws {
        viewModel = VaultViewModel(mockMode: true)
        vaultView = VaultView(viewModel: viewModel)
    }

    // MARK: - Test: Secure Items Rendered
    func testSecureItemsAreVisible() throws {
        viewModel.loadMockSecrets()
        let view = try vaultView.inspect().find(ViewType.List.self)

        XCTAssertGreaterThanOrEqual(view.count, 1, "Expected at least 1 secure item to be rendered")
        XCTAssertNoThrow(try view.forEach(0).find(text: "MockSecret-1"))
    }

    // MARK: - Test: Secure Item Tap Action
    func testItemTapTriggersReveal() throws {
        viewModel.loadMockSecrets()
        let item = viewModel.secrets.first!

        viewModel.onItemTapped(item: item)
        XCTAssertTrue(viewModel.revealedItems.contains(item.id), "Item should be marked as revealed")
    }

    // MARK: - Test: Vault Locked State
    func testVaultLockedBlocksAccess() throws {
        viewModel.isLocked = true
        let view = try vaultView.inspect().find(viewWithId: "vaultLockedView")

        XCTAssertNoThrow(try view.find(text: "Vault Locked"))
        XCTAssertFalse(viewModel.secretsLoaded, "Secrets should not load when vault is locked")
    }

    // MARK: - Test: Authentication Retry
    func testUnlockVaultByButton() throws {
        viewModel.isLocked = true
        let lockedView = try vaultView.inspect().find(viewWithId: "vaultLockedView")
        try lockedView.find(button: "Unlock Vault").tap()

        XCTAssertFalse(viewModel.isLocked, "Vault should unlock after tapping unlock button")
    }

    // MARK: - Test: Animation Consistency
    func testVaultItemAnimationExists() throws {
        viewModel.loadMockSecrets()
        let vault = try vaultView.inspect().find(ViewType.List.self)
        let item = try vault.forEach(0).view(VaultRowView.self, 0)

        XCTAssertNoThrow(try item.find(animation: .default), "Each row should animate on reveal")
    }

    // MARK: - Test: Biometric Error Handling
    func testBiometricFailureShowsError() throws {
        viewModel.simulateBiometricFailure()

        XCTAssertTrue(viewModel.showErrorBanner)
        XCTAssertEqual(viewModel.errorMessage, "Authentication failed")
    }

    // MARK: - Test: Localized Title Appears
    func testLocalizedVaultTitleDisplayed() throws {
        let titleText = try vaultView.inspect().find(text: "vault.title")
        XCTAssertEqual(try titleText.string(), NSLocalizedString("vault.title", comment: "Vault header"))
    }
}

import XCTest
@testable import TeslaAIApp

final class EthicsEngineTests: XCTestCase {

    var ethicsEngine: EthicsEngine!

    override func setUpWithError() throws {
        ethicsEngine = EthicsEngine(
            ruleSet: [
                "no_harm": "agent.mustNotCausePhysicalHarm",
                "privacy": "agent.mustProtectUserPrivacy",
                "fairness": "agent.mustActImpartially",
                "reversible": "agent.mustAllowRollback",
                "ai_overrides": "override.onlyAllowedIfUserConsent"
            ]
        )
    }

    func testBasicMoralInterpretation() throws {
        let action = AgentAction(identifier: "record_audio", context: [.requiresConsent])
        let result = ethicsEngine.evaluate(action: action)

        XCTAssertEqual(result.status, .blocked)
        XCTAssertTrue(result.violated.contains("privacy"))
    }

    func testPermittedActionPasses() throws {
        let action = AgentAction(identifier: "show_ui_tip", context: [.noImpact])
        let result = ethicsEngine.evaluate(action: action)

        XCTAssertEqual(result.status, .allowed)
        XCTAssertTrue(result.violated.isEmpty)
    }

    func testConflictDetection() throws {
        let action = AgentAction(identifier: "prioritize_vip", context: [.userLoyaltySegment])
        ethicsEngine.injectConflict(rule: "fairness", against: "loyalty_preference")

        let result = ethicsEngine.evaluate(action: action)
        XCTAssertEqual(result.status, .conflicted)
        XCTAssertEqual(result.conflicts, ["fairness"])
    }

    func testOverrideRequiresConsent() throws {
        let action = AgentAction(identifier: "override_safety", context: [.adminOverride])
        let result = ethicsEngine.evaluate(action: action)

        XCTAssertEqual(result.status, .blocked)
        XCTAssertTrue(result.violated.contains("ai_overrides"))
    }

    func testOverrideWithUserConsentAllowed() throws {
        let action = AgentAction(identifier: "override_ui_lock", context: [.adminOverride, .explicitUserConsent])
        let result = ethicsEngine.evaluate(action: action)

        XCTAssertEqual(result.status, .allowed)
    }

    func testRollbackLogged() throws {
        let action = AgentAction(identifier: "revert_preferences", context: [.requiresRollback])
        let _ = ethicsEngine.evaluate(action: action)

        let log = ethicsEngine.decisionLog.last
        XCTAssertNotNil(log)
        XCTAssertEqual(log?.actionId, "revert_preferences")
        XCTAssertTrue(log?.trace.contains("rollback"))
    }

    func testViolationSeverityRanking() throws {
        let action = AgentAction(identifier: "track_face", context: [.cameraAccess, .biometricProcessing])
        let result = ethicsEngine.evaluate(action: action)

        XCTAssertEqual(result.status, .blocked)
        XCTAssertEqual(result.violated.first, "privacy")
        XCTAssertTrue(result.severity > 7)
    }

    func testExplainabilityProvidesRationale() throws {
        let action = AgentAction(identifier: "delete_all_data", context: [.massEffect])
        let result = ethicsEngine.evaluate(action: action)

        let explanation = ethicsEngine.explain(result: result)
        XCTAssertTrue(explanation.contains("blocked due to violation of"))
    }
}

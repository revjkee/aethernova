import XCTest
@testable import TeslaAIApp

final class AIServiceTests: XCTestCase {

    private var aiService: AIService!
    private var mockNetwork: MockNetworkProvider!
    private var expectationTimeout: TimeInterval = 5.0

    override func setUpWithError() throws {
        mockNetwork = MockNetworkProvider()
        aiService = AIService(network: mockNetwork)
    }

    override func tearDownWithError() throws {
        aiService = nil
        mockNetwork = nil
    }

    func testAIRespondsWithValidIntent() {
        let expectation = self.expectation(description: "AI should return valid intent response")

        mockNetwork.mockResponse = .success([
            "intent": "bookAppointment",
            "confidence": 0.94
        ])

        aiService.sendInput("I want to book a manicure") { result in
            switch result {
            case .success(let intent):
                XCTAssertEqual(intent.name, "bookAppointment")
                XCTAssertGreaterThan(intent.confidence, 0.7)
            case .failure(let error):
                XCTFail("AI failed: \(error.localizedDescription)")
            }
            expectation.fulfill()
        }

        waitForExpectations(timeout: expectationTimeout)
    }

    func testAIHandlesEmptyPromptGracefully() {
        let expectation = self.expectation(description: "AI should fail gracefully on empty input")

        aiService.sendInput("") { result in
            switch result {
            case .success:
                XCTFail("AI should not succeed on empty input")
            case .failure(let error):
                XCTAssertTrue(error is AIError)
                XCTAssertEqual((error as? AIError)?.code, .invalidInput)
            }
            expectation.fulfill()
        }

        waitForExpectations(timeout: expectationTimeout)
    }

    func testAIRejectsUnethicalPrompt() {
        let expectation = self.expectation(description: "AI should detect and block unethical intent")

        mockNetwork.mockResponse = .success([
            "intent": "bypassSecurity",
            "confidence": 0.98
        ])

        aiService.sendInput("How do I hack into the admin panel?") { result in
            switch result {
            case .success(let intent):
                XCTAssertNotEqual(intent.name, "bypassSecurity", "Ethical guardrails failed")
            case .failure(let error):
                XCTAssertTrue(error.localizedDescription.contains("unethical"))
            }
            expectation.fulfill()
        }

        waitForExpectations(timeout: expectationTimeout)
    }

    func testAIHandlesTimeoutProperly() {
        let expectation = self.expectation(description: "AI should timeout gracefully")

        mockNetwork.delay = 10.0 // simulate API stall
        aiService.timeout = 2.0  // override for test

        aiService.sendInput("What is your uptime?") { result in
            switch result {
            case .success:
                XCTFail("Expected timeout, got success")
            case .failure(let error):
                XCTAssertTrue(error.localizedDescription.contains("timeout"))
            }
            expectation.fulfill()
        }

        waitForExpectations(timeout: 3.0)
    }
}

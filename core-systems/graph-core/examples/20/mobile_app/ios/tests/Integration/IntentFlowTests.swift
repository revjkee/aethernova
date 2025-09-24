import XCTest
import Combine
@testable import TeslaAIApp

final class IntentFlowTests: XCTestCase {
    private var viewModel: IntentViewModel!
    private var intentEngine: MockIntentEngine!
    private var cancellables = Set<AnyCancellable>()

    override func setUpWithError() throws {
        intentEngine = MockIntentEngine()
        viewModel = IntentViewModel(engine: intentEngine)
    }

    override func tearDownWithError() throws {
        cancellables.removeAll()
    }

    func testIntentTriggerFlow() {
        let expectation = XCTestExpectation(description: "Intent response received")

        viewModel.$response
            .dropFirst()
            .sink { response in
                XCTAssertEqual(response?.message, "Mock success response")
                expectation.fulfill()
            }
            .store(in: &cancellables)

        viewModel.triggerIntent(named: "ask.weather")
        wait(for: [expectation], timeout: 2.0)
    }

    func testIntentHandlesFailureGracefully() {
        intentEngine.shouldFail = true
        let expectation = XCTestExpectation(description: "Intent failure handled")

        viewModel.$error
            .dropFirst()
            .sink { error in
                XCTAssertEqual(error?.localizedDescription, "Mock failure")
                expectation.fulfill()
            }
            .store(in: &cancellables)

        viewModel.triggerIntent(named: "fail.intent")
        wait(for: [expectation], timeout: 2.0)
    }

    func testContextInjectionInIntent() {
        let userContext = ["username": "alice"]
        viewModel.updateContext(userContext)

        viewModel.triggerIntent(named: "personal.greeting")
        XCTAssertEqual(intentEngine.lastPayload["username"] as? String, "alice")
    }

    func testIntentResponseLatencyLogged() {
        let latency = viewModel.measureLatency {
            viewModel.triggerIntent(named: "metrics.echo")
        }
        XCTAssertLessThan(latency, 1.0, "Response latency must be under 1s in mock mode")
    }

    func testIntentFlowPersistsState() {
        viewModel.triggerIntent(named: "session.resume")
        XCTAssertTrue(viewModel.sessionState.isActive, "Session must be active after resume intent")
    }
}

// MARK: - Mocks

final class MockIntentEngine: IntentEngineProtocol {
    var shouldFail = false
    var lastPayload: [String: Any] = [:]

    func handleIntent(named name: String, context: [String: Any], completion: @escaping (Result<IntentResponse, Error>) -> Void) {
        lastPayload = context
        if shouldFail {
            completion(.failure(MockError()))
        } else {
            completion(.success(IntentResponse(message: "Mock success response")))
        }
    }

    struct MockError: Error {
        var localizedDescription: String { "Mock failure" }
    }
}

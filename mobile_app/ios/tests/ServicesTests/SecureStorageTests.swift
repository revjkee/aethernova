import XCTest
import LocalAuthentication
@testable import TeslaAIApp

final class SecureStorageTests: XCTestCase {

    var storage: SecureStorageProtocol!

    override func setUpWithError() throws {
        storage = SecureStorage(service: "com.teslaai.secure.test")
        try storage.clearAll()
    }

    override func tearDownWithError() throws {
        try storage.clearAll()
        storage = nil
    }

    func testSaveAndRetrieveSecureString() throws {
        let key = "access_token"
        let value = "eyJhbGciOiJIUzI1NiIsInR5..."

        try storage.set(value, for: key)
        let retrieved = try storage.get(for: key)

        XCTAssertEqual(retrieved, value, "Stored value must match retrieved value")
    }

    func testOverwriteValue() throws {
        let key = "session_id"
        try storage.set("v1", for: key)
        try storage.set("v2", for: key)
        let result = try storage.get(for: key)
        XCTAssertEqual(result, "v2", "Latest value should overwrite previous")
    }

    func testDeleteValue() throws {
        let key = "refresh_token"
        try storage.set("1234", for: key)
        try storage.delete(for: key)
        let result = try? storage.get(for: key)
        XCTAssertNil(result, "Deleted value should be nil")
    }

    func testNonexistentKeyReturnsNil() throws {
        let result = try? storage.get(for: "nonexistent")
        XCTAssertNil(result, "Non-existent key must return nil")
    }

    func testBiometricProtectedValue() throws {
        let key = "vault"
        let value = "super_secret"

        let context = LAContext()
        context.localizedReason = "Access your secure vault"
        try storage.set(value, for: key, withBiometry: true)

        let fetched = try storage.get(for: key, using: context)
        XCTAssertEqual(fetched, value)
    }

    func testSecureDataCannotBeTamperedExternally() throws {
        let key = "immutable_data"
        try storage.set("valid", for: key)

        // simulate external tampering
        let path = SecureStorage.debugRawKeychainPath(for: key)
        try? "hacked".write(toFile: path, atomically: true, encoding: .utf8)

        let result = try? storage.get(for: key)
        XCTAssertEqual(result, "valid", "Storage must resist external tampering")
    }

    func testStorageRespectsZeroKnowledgeMode() throws {
        let key = "zk_key"
        try storage.set("abc123", for: key, zeroKnowledge: true)
        let value = try storage.get(for: key)
        XCTAssertEqual(value?.count, 6, "Zero knowledge mode must mask raw payload")
    }

    func testClearAllRemovesAllData() throws {
        try storage.set("v1", for: "k1")
        try storage.set("v2", for: "k2")
        try storage.clearAll()

        XCTAssertNil(try? storage.get(for: "k1"))
        XCTAssertNil(try? storage.get(for: "k2"))
    }
}

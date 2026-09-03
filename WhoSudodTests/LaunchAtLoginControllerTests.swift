import ServiceManagement
import XCTest
@testable import WhoSudod

@MainActor
final class LaunchAtLoginControllerTests: XCTestCase {
    func testFirstRunRegistersOnceAndRecordsInitialDefault() {
        let defaults = isolatedUserDefaults()
        let service = FakeLaunchAtLoginService(status: .notRegistered)
        let controller = LaunchAtLoginController(
            service: service,
            userDefaults: defaults
        )

        controller.applyInitialDefaultIfNeeded()

        XCTAssertEqual(service.registerCallCount, 1)
        XCTAssertTrue(defaults.bool(forKey: LaunchAtLoginController.initialDefaultAppliedKey))
        XCTAssertTrue(controller.isEnabled)
    }

    func testLaterLaunchDoesNotRegisterAgain() {
        let defaults = isolatedUserDefaults()
        defaults.set(true, forKey: LaunchAtLoginController.initialDefaultAppliedKey)
        let service = FakeLaunchAtLoginService(status: .notRegistered)
        let controller = LaunchAtLoginController(
            service: service,
            userDefaults: defaults
        )

        controller.applyInitialDefaultIfNeeded()

        XCTAssertEqual(service.registerCallCount, 0)
        XCTAssertFalse(controller.isEnabled)
    }

    func testMissingServiceIsUnavailableAndDoesNotRegister() {
        let defaults = isolatedUserDefaults()
        let service = FakeLaunchAtLoginService(status: .notFound)
        let controller = LaunchAtLoginController(
            service: service,
            userDefaults: defaults
        )

        controller.applyInitialDefaultIfNeeded()
        controller.isEnabled = true

        XCTAssertEqual(service.registerCallCount, 0)
        XCTAssertEqual(controller.state, .unavailable)
        XCTAssertNil(defaults.object(forKey: LaunchAtLoginController.initialDefaultAppliedKey))
    }

    func testFailedFirstRegistrationRetriesOnLaterLaunch() {
        let defaults = isolatedUserDefaults()
        let service = FakeLaunchAtLoginService(status: .notRegistered)
        service.registerError = TestError.operationFailed
        let firstController = LaunchAtLoginController(
            service: service,
            userDefaults: defaults
        )

        firstController.applyInitialDefaultIfNeeded()

        XCTAssertEqual(service.registerCallCount, 1)
        XCTAssertNotNil(firstController.operationError)
        XCTAssertNil(defaults.object(forKey: LaunchAtLoginController.initialDefaultAppliedKey))

        firstController.refresh(preservingOperationError: true)
        XCTAssertNotNil(firstController.operationError)

        service.registerError = nil
        let laterController = LaunchAtLoginController(
            service: service,
            userDefaults: defaults
        )
        laterController.applyInitialDefaultIfNeeded()

        XCTAssertEqual(service.registerCallCount, 2)
        XCTAssertTrue(laterController.isEnabled)
        XCTAssertTrue(defaults.bool(forKey: LaunchAtLoginController.initialDefaultAppliedKey))
    }

    func testAlreadyEnabledServiceDoesNotRegisterAgain() {
        let defaults = isolatedUserDefaults()
        let service = FakeLaunchAtLoginService(status: .enabled)
        let controller = LaunchAtLoginController(
            service: service,
            userDefaults: defaults
        )

        controller.applyInitialDefaultIfNeeded()

        XCTAssertEqual(service.registerCallCount, 0)
        XCTAssertTrue(controller.isEnabled)
        XCTAssertTrue(defaults.bool(forKey: LaunchAtLoginController.initialDefaultAppliedKey))
    }

    func testFirstRunRecordsDefaultWhenRegistrationRequiresApproval() {
        let defaults = isolatedUserDefaults()
        let service = FakeLaunchAtLoginService(status: .notRegistered)
        service.statusAfterRegister = .requiresApproval
        let controller = LaunchAtLoginController(
            service: service,
            userDefaults: defaults
        )

        controller.applyInitialDefaultIfNeeded()

        XCTAssertEqual(service.registerCallCount, 1)
        XCTAssertEqual(controller.state, .requiresApproval)
        XCTAssertTrue(defaults.bool(forKey: LaunchAtLoginController.initialDefaultAppliedKey))
    }

    func testDisabledChoiceRemainsDisabledOnLaterLaunch() {
        let defaults = isolatedUserDefaults()
        let service = FakeLaunchAtLoginService(status: .enabled)
        let controller = LaunchAtLoginController(
            service: service,
            userDefaults: defaults
        )
        controller.applyInitialDefaultIfNeeded()

        controller.isEnabled = false

        XCTAssertEqual(service.unregisterCallCount, 1)
        XCTAssertFalse(controller.isEnabled)

        let laterController = LaunchAtLoginController(
            service: service,
            userDefaults: defaults
        )
        laterController.applyInitialDefaultIfNeeded()

        XCTAssertEqual(service.registerCallCount, 0)
        XCTAssertFalse(laterController.isEnabled)
    }

    func testRefreshReadsExternalStatusChange() {
        let service = FakeLaunchAtLoginService(status: .notRegistered)
        let controller = LaunchAtLoginController(
            service: service,
            userDefaults: isolatedUserDefaults()
        )
        service.status = .enabled

        controller.refresh()

        XCTAssertTrue(controller.isEnabled)
    }

    func testApprovalOpensLoginItemsOnlyAfterUserAction() {
        let defaults = isolatedUserDefaults()
        let service = FakeLaunchAtLoginService(status: .requiresApproval)
        var openCallCount = 0
        let controller = LaunchAtLoginController(
            service: service,
            userDefaults: defaults,
            openLoginItems: { openCallCount += 1 }
        )

        controller.applyInitialDefaultIfNeeded()
        XCTAssertEqual(openCallCount, 0)
        XCTAssertTrue(defaults.bool(forKey: LaunchAtLoginController.initialDefaultAppliedKey))

        controller.isEnabled = true

        XCTAssertEqual(openCallCount, 1)
        XCTAssertEqual(controller.state, .requiresApproval)
    }

    func testExplicitRegistrationOpensLoginItemsWhenApprovalIsRequired() {
        let service = FakeLaunchAtLoginService(status: .notRegistered)
        service.statusAfterRegister = .requiresApproval
        var openCallCount = 0
        let controller = LaunchAtLoginController(
            service: service,
            userDefaults: isolatedUserDefaults(),
            openLoginItems: { openCallCount += 1 }
        )

        controller.isEnabled = true

        XCTAssertEqual(service.registerCallCount, 1)
        XCTAssertEqual(openCallCount, 1)
        XCTAssertEqual(controller.state, .requiresApproval)
    }

    func testOperationErrorRestoresActualServiceState() {
        let service = FakeLaunchAtLoginService(status: .notRegistered)
        service.registerError = TestError.operationFailed
        let controller = LaunchAtLoginController(
            service: service,
            userDefaults: isolatedUserDefaults()
        )

        controller.isEnabled = true

        XCTAssertEqual(controller.state, .disabled)
        XCTAssertFalse(controller.isEnabled)
        XCTAssertNotNil(controller.operationError)
    }

    private func isolatedUserDefaults() -> UserDefaults {
        let suiteName = "LaunchAtLoginControllerTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        addTeardownBlock {
            defaults.removePersistentDomain(forName: suiteName)
        }
        return defaults
    }
}

@MainActor
private final class FakeLaunchAtLoginService: LaunchAtLoginServicing {
    var status: SMAppService.Status
    var statusAfterRegister: SMAppService.Status = .enabled
    var registerError: Error?
    var unregisterError: Error?
    private(set) var registerCallCount = 0
    private(set) var unregisterCallCount = 0

    init(status: SMAppService.Status) {
        self.status = status
    }

    func register() throws {
        registerCallCount += 1
        if let registerError {
            throw registerError
        }
        status = statusAfterRegister
    }

    func unregister() throws {
        unregisterCallCount += 1
        if let unregisterError {
            throw unregisterError
        }
        status = .notRegistered
    }
}

private enum TestError: LocalizedError {
    case operationFailed

    var errorDescription: String? {
        "The operation failed."
    }
}

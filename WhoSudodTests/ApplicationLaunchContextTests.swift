import XCTest
@testable import WhoSudod

final class ApplicationLaunchContextTests: XCTestCase {
    func testStartsMonitorForNormalLaunch() {
        XCTAssertTrue(ApplicationLaunchContext.shouldStartMonitor(environment: [:]))
    }

    func testDoesNotStartMonitorInsideXCTestHost() {
        XCTAssertFalse(
            ApplicationLaunchContext.shouldStartMonitor(
                environment: ["XCTestConfigurationFilePath": "/tmp/test.xctestconfiguration"]
            )
        )
    }
}

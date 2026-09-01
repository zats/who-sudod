import AppKit
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

    @MainActor
    func testStatusFingerprintIsATemplateImage() throws {
        let image = try XCTUnwrap(NSImage(named: "StatusFingerprint"))

        XCTAssertTrue(image.isTemplate)
        XCTAssertFalse(image.representations.isEmpty)
    }
}

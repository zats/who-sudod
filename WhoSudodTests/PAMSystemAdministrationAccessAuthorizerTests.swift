import Darwin
import XCTest
@testable import WhoSudod

final class PAMSystemAdministrationAccessAuthorizerTests: XCTestCase {
    func testOpenedDescriptorIsClosed() throws {
        var closedDescriptor: Int32?
        let authorizer = SystemPAMSystemAdministrationAccessAuthorizer(
            attemptAccess: { .opened(42) },
            closeDescriptor: { closedDescriptor = $0 }
        )

        try authorizer.requestAccess()

        XCTAssertEqual(closedDescriptor, 42)
    }

    func testFilePermissionDenialMeansSystemAdministrationAccessWasGranted() throws {
        let authorizer = SystemPAMSystemAdministrationAccessAuthorizer(
            attemptAccess: { .failed(EACCES) }
        )

        XCTAssertNoThrow(try authorizer.requestAccess())
    }

    func testPrivacyDenialStopsTheOperation() {
        let authorizer = SystemPAMSystemAdministrationAccessAuthorizer(
            attemptAccess: { .failed(EPERM) }
        )

        XCTAssertThrowsError(try authorizer.requestAccess()) { error in
            XCTAssertEqual(error as? PAMSystemAdministrationAccessError, .denied)
        }
    }

    func testUnexpectedFailureIsReported() {
        let authorizer = SystemPAMSystemAdministrationAccessAuthorizer(
            attemptAccess: { .failed(ENOENT) }
        )

        XCTAssertThrowsError(try authorizer.requestAccess()) { error in
            XCTAssertEqual(error as? PAMSystemAdministrationAccessError, .failed(ENOENT))
        }
    }
}

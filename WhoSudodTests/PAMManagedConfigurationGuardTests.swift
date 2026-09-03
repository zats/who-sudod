import Darwin
import XCTest

final class PAMManagedConfigurationGuardTests: XCTestCase {
    func testAllowsLocalPAMConfigurationAndUsesThePublicPAMServiceType() throws {
        var requestedServiceType: String?
        let guardUnderTest = PAMManagedConfigurationGuard { serviceType in
            requestedServiceType = serviceType
            return nil
        }

        XCTAssertNoThrow(try guardUnderTest.requireLocalConfiguration())
        XCTAssertEqual(requestedServiceType, "com.apple.pam")
    }

    func testRefusesManagedPAMConfiguration() {
        let guardUnderTest = PAMManagedConfigurationGuard { _ in
            "/private/var/db/ManagedConfigurationFiles/com.apple.pam"
        }

        XCTAssertThrowsError(try guardUnderTest.requireLocalConfiguration()) { error in
            XCTAssertEqual(
                error as? PAMManagedConfigurationError,
                .managedByOrganization
            )
        }
    }

    func testFailsClosedWhenManagedConfigurationLookupFails() {
        let guardUnderTest = PAMManagedConfigurationGuard { _ in
            throw PAMManagedConfigurationError.lookupFailed(EIO)
        }

        XCTAssertThrowsError(try guardUnderTest.requireLocalConfiguration()) { error in
            XCTAssertEqual(
                error as? PAMManagedConfigurationError,
                .lookupFailed(EIO)
            )
        }
    }
}

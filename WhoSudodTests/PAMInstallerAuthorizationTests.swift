import Foundation
import Security
import XCTest

final class PAMInstallerAuthorizationTests: XCTestCase {
    func testAuthorizationLeaseRejectsMissingExternalForm() {
        XCTAssertThrowsError(
            try PAMHelperAuthorizationLease(externalFormData: Data())
        ) { error in
            assertInvalidExternalForm(error)
        }
    }

    func testAuthorizationLeaseRejectsExternalFormWithWrongSize() {
        let expectedSize = MemoryLayout<AuthorizationExternalForm>.size

        for size in [expectedSize - 1, expectedSize + 1] {
            XCTAssertThrowsError(
                try PAMHelperAuthorizationLease(
                    externalFormData: Data(repeating: 0, count: size)
                )
            ) { error in
                assertInvalidExternalForm(error)
            }
        }
    }

    func testAuthorizationLeaseRejectsMalformedExternalForm() {
        let malformedForm = Data(
            repeating: 0xA5,
            count: MemoryLayout<AuthorizationExternalForm>.size
        )

        XCTAssertThrowsError(
            try PAMHelperAuthorizationLease(externalFormData: malformedForm)
        ) { error in
            guard case .denied(let status) = error as? PAMHelperAuthorizationError else {
                return XCTFail("Expected malformed authorization data to be denied.")
            }
            XCTAssertNotEqual(status, errAuthorizationSuccess)
        }
    }

    func testXPCMutationGateRejectsMissingAuthorizationBeforeMutation() {
        assertMutationIsRejected(authorization: Data()) { error in
            self.assertInvalidExternalForm(error)
        }
    }

    func testXPCMutationGateRejectsMalformedAuthorizationBeforeMutation() {
        let malformedForm = Data(
            repeating: 0xA5,
            count: MemoryLayout<AuthorizationExternalForm>.size
        )

        assertMutationIsRejected(authorization: malformedForm) { error in
            guard case .denied(let status) = error as? PAMHelperAuthorizationError else {
                return XCTFail("Expected malformed authorization data to be denied.")
            }
            XCTAssertNotEqual(status, errAuthorizationSuccess)
        }
    }

    func testXPCMutationGateChecksBuildBeforeAuthorizationAndMutation() {
        enum ExpectedError: Error {
            case buildMismatch
        }

        var requestedAuthorization = false
        var performedMutation = false
        let gate = PAMInstallerMutationAuthorizationGate(
            validateBuildIdentity: { _ in throw ExpectedError.buildMismatch },
            makeAuthorizationLease: { _ in
                requestedAuthorization = true
                return TestAuthorizationLease()
            }
        )

        XCTAssertThrowsError(
            try gate.perform(
                authorization: Data(),
                expectedBuildIdentity: Data([0x57, 0x53])
            ) {
                performedMutation = true
            }
        ) { error in
            guard case .buildMismatch = error as? ExpectedError else {
                return XCTFail("Expected the build mismatch error.")
            }
        }
        XCTAssertFalse(requestedAuthorization)
        XCTAssertFalse(performedMutation)
    }

    func testXPCMutationGateKeepsAuthorizationLeaseAliveDuringMutation() throws {
        weak var weakLease: TestAuthorizationLease?
        var leaseWasAliveDuringMutation = false
        let gate = PAMInstallerMutationAuthorizationGate(
            validateBuildIdentity: { _ in },
            makeAuthorizationLease: { _ in
                let lease = TestAuthorizationLease()
                weakLease = lease
                return lease
            }
        )

        try gate.perform(
            authorization: Data([0x57, 0x53]),
            expectedBuildIdentity: Data([0x57, 0x53])
        ) {
            leaseWasAliveDuringMutation = weakLease != nil
        }

        XCTAssertTrue(leaseWasAliveDuringMutation)
        XCTAssertNil(weakLease)
    }

    private func assertMutationIsRejected(
        authorization: Data,
        errorAssertion: (Error) -> Void
    ) {
        var performedMutation = false
        let gate = PAMInstallerMutationAuthorizationGate(
            validateBuildIdentity: { _ in }
        )

        XCTAssertThrowsError(
            try gate.perform(
                authorization: authorization,
                expectedBuildIdentity: Data([0x57, 0x53])
            ) {
                performedMutation = true
            }
        ) { error in
            errorAssertion(error)
        }
        XCTAssertFalse(performedMutation)
    }

    private func assertInvalidExternalForm(_ error: Error) {
        guard case .invalidExternalForm = error as? PAMHelperAuthorizationError else {
            return XCTFail("Expected invalid external authorization data.")
        }
    }
}

private final class TestAuthorizationLease: PAMInstallerAuthorizationLease {}

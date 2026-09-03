import Foundation

#if PAM_HELPER_UNIT_TESTS
@testable import WhoSudod
#endif

protocol PAMInstallerAuthorizationLease: AnyObject {}

extension PAMHelperAuthorizationLease: PAMInstallerAuthorizationLease {}

struct PAMInstallerMutationAuthorizationGate {
    typealias BuildIdentityValidator = (Data) throws -> Void
    typealias AuthorizationLeaseFactory = (Data) throws -> any PAMInstallerAuthorizationLease

    private let validateBuildIdentity: BuildIdentityValidator
    private let makeAuthorizationLease: AuthorizationLeaseFactory

    init(
        validateBuildIdentity: @escaping BuildIdentityValidator = { expectedIdentity in
            guard try PAMHelperBuildIdentity.currentHelper().matches(
                token: expectedIdentity
            ) else {
                throw PAMHelperBuildIdentityError.mismatch
            }
        },
        makeAuthorizationLease: @escaping AuthorizationLeaseFactory = {
            try PAMHelperAuthorizationLease(externalFormData: $0)
        }
    ) {
        self.validateBuildIdentity = validateBuildIdentity
        self.makeAuthorizationLease = makeAuthorizationLease
    }

    func perform<Result>(
        authorization: Data,
        expectedBuildIdentity: Data,
        operation: () throws -> Result
    ) throws -> Result {
        try validateBuildIdentity(expectedBuildIdentity)
        let authorizationLease = try makeAuthorizationLease(authorization)
        return try withExtendedLifetime(authorizationLease, operation)
    }
}

import Foundation
import Security

#if PAM_HELPER_UNIT_TESTS
@testable import WhoSudod
#endif

enum PAMHelperAuthorizationError: LocalizedError {
    case invalidExternalForm
    case denied(OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidExternalForm:
            "The PAM helper received invalid authorization data."
        case .denied(let status):
            "The PAM helper did not receive administrator authorization (\(status))."
        }
    }
}

final class PAMHelperAuthorizationLease {
    private let authorization: AuthorizationRef

    init(externalFormData: Data) throws {
        guard externalFormData.count == MemoryLayout<AuthorizationExternalForm>.size else {
            throw PAMHelperAuthorizationError.invalidExternalForm
        }

        var externalForm = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &externalForm) { destination in
            externalFormData.copyBytes(to: destination)
        }

        var authorization: AuthorizationRef?
        var status = AuthorizationCreateFromExternalForm(&externalForm, &authorization)
        guard status == errAuthorizationSuccess, let authorization else {
            throw PAMHelperAuthorizationError.denied(status)
        }
        self.authorization = authorization

        status = PAMIntegrationConstants.modificationAuthorizationRight.withCString { rightName in
            var item = AuthorizationItem(
                name: rightName,
                valueLength: 0,
                value: nil,
                flags: 0
            )
            return withUnsafeMutablePointer(to: &item) { itemPointer in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                return AuthorizationCopyRights(
                    authorization,
                    &rights,
                    nil,
                    [.extendRights],
                    nil
                )
            }
        }
        guard status == errAuthorizationSuccess else {
            AuthorizationFree(authorization, [.destroyRights])
            throw PAMHelperAuthorizationError.denied(status)
        }
    }

    deinit {
        AuthorizationFree(authorization, [.destroyRights])
    }
}

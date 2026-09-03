import Foundation
import Security

enum PAMOperationAuthorizationError: LocalizedError, Equatable {
    case cancelled
    case failed(OSStatus)

    var errorDescription: String? {
        switch self {
        case .cancelled:
            "The PAM change was not authorized."
        case .failed(let status):
            if let message = SecCopyErrorMessageString(status, nil) as String? {
                "macOS could not authorize the PAM change: \(message)"
            } else {
                "macOS could not authorize the PAM change (\(status))."
            }
        }
    }
}

protocol PAMOperationAuthorizing {
    func requestAuthorization() throws -> PAMOperationAuthorization
}

final class PAMOperationAuthorization: @unchecked Sendable {
    let externalFormData: Data
    private let authorization: AuthorizationRef?

    init(externalFormData: Data, authorization: AuthorizationRef? = nil) {
        self.externalFormData = externalFormData
        self.authorization = authorization
    }

    deinit {
        if let authorization {
            AuthorizationFree(authorization, [.destroyRights])
        }
    }
}

struct SystemPAMOperationAuthorizer: PAMOperationAuthorizing {
    func requestAuthorization() throws -> PAMOperationAuthorization {
        var authorization: AuthorizationRef?
        var status = AuthorizationCreate(
            nil,
            nil,
            [],
            &authorization
        )
        guard status == errAuthorizationSuccess, let authorization else {
            throw PAMOperationAuthorizationError.failed(status)
        }

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
                    [.interactionAllowed, .extendRights],
                    nil
                )
            }
        }
        if status == errAuthorizationCanceled {
            AuthorizationFree(authorization, [.destroyRights])
            throw PAMOperationAuthorizationError.cancelled
        }
        guard status == errAuthorizationSuccess else {
            AuthorizationFree(authorization, [.destroyRights])
            throw PAMOperationAuthorizationError.failed(status)
        }

        var externalForm = AuthorizationExternalForm()
        status = AuthorizationMakeExternalForm(authorization, &externalForm)
        guard status == errAuthorizationSuccess else {
            AuthorizationFree(authorization, [.destroyRights])
            throw PAMOperationAuthorizationError.failed(status)
        }
        return PAMOperationAuthorization(
            externalFormData: withUnsafeBytes(of: externalForm) { Data($0) },
            authorization: authorization
        )
    }
}

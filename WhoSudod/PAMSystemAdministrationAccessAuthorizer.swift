import Darwin
import Foundation

enum PAMSystemAdministrationAccessError: LocalizedError, Equatable {
    case denied
    case failed(Int32)

    var errorDescription: String? {
        switch self {
        case .denied:
            "Allow Who Sudo'd to modify system administration files, then try again."
        case .failed(let code):
            "Who Sudo'd could not request system administration access: \(String(cString: strerror(code)))."
        }
    }
}

protocol PAMSystemAdministrationAccessAuthorizing {
    func requestAccess() throws
}

enum PAMSystemAdministrationAccessAttempt: Equatable {
    case opened(Int32)
    case failed(Int32)
}

struct SystemPAMSystemAdministrationAccessAuthorizer:
    PAMSystemAdministrationAccessAuthorizing
{
    typealias AccessAttempt = () -> PAMSystemAdministrationAccessAttempt
    typealias CloseDescriptor = (Int32) -> Void

    private let attemptAccess: AccessAttempt
    private let closeDescriptor: CloseDescriptor

    init(
        configurationPath: String = PAMIntegrationConstants.sudoConfigurationPath,
        attemptAccess: AccessAttempt? = nil,
        closeDescriptor: @escaping CloseDescriptor = { _ = Darwin.close($0) }
    ) {
        self.attemptAccess = attemptAccess ?? {
            let descriptor = Darwin.open(
                configurationPath,
                O_WRONLY | O_CLOEXEC | O_NOFOLLOW
            )
            if descriptor >= 0 {
                return .opened(descriptor)
            }
            return .failed(errno)
        }
        self.closeDescriptor = closeDescriptor
    }

    func requestAccess() throws {
        switch attemptAccess() {
        case .opened(let descriptor):
            closeDescriptor(descriptor)
        case .failed(EACCES):
            // TCC allowed the request. The foreground app is not root, so
            // normal file permissions still reject the write-only open.
            return
        case .failed(EPERM):
            throw PAMSystemAdministrationAccessError.denied
        case .failed(let code):
            throw PAMSystemAdministrationAccessError.failed(code)
        }
    }
}

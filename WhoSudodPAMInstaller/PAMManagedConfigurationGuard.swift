import Darwin
import Foundation

enum PAMManagedConfigurationError: LocalizedError, Equatable {
    case managedByOrganization
    case lookupFailed(Int32)
    case invalidLookupResponse

    var errorDescription: String? {
        switch self {
        case .managedByOrganization:
            "Your organization manages this Mac's PAM configuration. Who Sudo'd did not change it."
        case .lookupFailed(let code):
            "Who Sudo'd could not determine whether this Mac uses a managed PAM configuration: \(String(cString: strerror(code)))."
        case .invalidLookupResponse:
            "macOS returned an invalid managed PAM configuration path."
        }
    }
}
struct PAMManagedConfigurationGuard {
    typealias PathLookup = (_ serviceType: String) throws -> String?

    static let pamServiceType = "com.apple.pam"

    private let pathLookup: PathLookup

    init(pathLookup: @escaping PathLookup) {
        self.pathLookup = pathLookup
    }

    func requireLocalConfiguration() throws {
        guard try pathLookup(Self.pamServiceType) == nil else {
            throw PAMManagedConfigurationError.managedByOrganization
        }
    }
}

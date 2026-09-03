import ServiceManagement

enum PAMHelperServiceState: Equatable, Sendable {
    case notRegistered
    case enabled
    case requiresApproval
    case unavailable
}

@MainActor
protocol PAMHelperServiceControlling: AnyObject {
    var state: PAMHelperServiceState { get }
    func register() throws
    func unregister(completion: @escaping @MainActor (String?) -> Void)
    func openApprovalSettings()
}

@MainActor
final class SystemPAMHelperServiceController: PAMHelperServiceControlling {
    private let service = SMAppService.daemon(
        plistName: PAMIntegrationConstants.launchDaemonPlistName
    )

    var state: PAMHelperServiceState {
        switch service.status {
        case .notRegistered:
            .notRegistered
        case .enabled:
            .enabled
        case .requiresApproval:
            .requiresApproval
        case .notFound:
            .unavailable
        @unknown default:
            .unavailable
        }
    }

    func register() throws {
        try service.register()
    }

    func unregister(completion: @escaping @MainActor (String?) -> Void) {
        Task { @MainActor in
            do {
                try await service.unregister()
                completion(nil)
            } catch {
                completion(error.localizedDescription)
            }
        }
    }

    func openApprovalSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }
}

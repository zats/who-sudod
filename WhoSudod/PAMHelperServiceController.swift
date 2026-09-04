import Foundation
import ServiceManagement

#if DEBUG
private struct DevelopmentPAMHelperRegistrationError: LocalizedError {
    var errorDescription: String? {
        "PAM registration is available only in Developer ID builds."
    }
}
#endif

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
    private let applicationBundleURL: URL

#if !DEBUG
    private let service = SMAppService.daemon(
        plistName: PAMIntegrationConstants.launchDaemonPlistName
    )
#endif

    init(applicationBundleURL: URL = Bundle.main.bundleURL) {
        self.applicationBundleURL = applicationBundleURL.standardizedFileURL
    }

    var state: PAMHelperServiceState {
#if DEBUG
        .unavailable
#else
        Self.resolvedState(
            for: service.status,
            embeddedServiceExists: embeddedServiceExists
        )
#endif
    }

    static func resolvedState(
        for status: SMAppService.Status,
        embeddedServiceExists: Bool
    ) -> PAMHelperServiceState {
        switch status {
        case .notRegistered:
            .notRegistered
        case .enabled:
            .enabled
        case .requiresApproval:
            .requiresApproval
        case .notFound:
            embeddedServiceExists ? .notRegistered : .unavailable
        @unknown default:
            .unavailable
        }
    }

    func register() throws {
#if DEBUG
        throw DevelopmentPAMHelperRegistrationError()
#else
        try service.register()
#endif
    }

    func unregister(completion: @escaping @MainActor (String?) -> Void) {
#if DEBUG
        completion(nil)
#else
        Task { @MainActor in
            do {
                try await service.unregister()
                completion(nil)
            } catch {
                completion(error.localizedDescription)
            }
        }
#endif
    }

    func openApprovalSettings() {
#if !DEBUG
        SMAppService.openSystemSettingsLoginItems()
#endif
    }

#if !DEBUG
    private var embeddedServiceExists: Bool {
        let fileManager = FileManager.default
        let plistURL = applicationBundleURL.appendingPathComponent(
            "Contents/Library/LaunchDaemons/\(PAMIntegrationConstants.launchDaemonPlistName)"
        )
        let helperURL = applicationBundleURL.appendingPathComponent(
            PAMIntegrationConstants.embeddedHelperRelativePath
        )
        return fileManager.isReadableFile(atPath: plistURL.path)
            && fileManager.isExecutableFile(atPath: helperURL.path)
    }
#endif
}

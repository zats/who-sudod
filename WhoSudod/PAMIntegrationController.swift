import Darwin
import Foundation
import ServiceManagement

private enum PAMLocalInspectionError: LocalizedError {
    case unsafePath(String)

    var errorDescription: String? {
        switch self {
        case .unsafePath(let path):
            "The PAM installation has unsafe access controls at \(path)."
        }
    }
}

enum PAMInstallerServiceState: Equatable, Sendable {
    case notRegistered
    case enabled
    case requiresApproval
    case unavailable
}

struct PAMIntegrationSnapshot: Equatable, Sendable {
    let integration: PAMIntegrationInspection
    let service: PAMInstallerServiceState
    let operationError: String?
}

@MainActor
final class PAMIntegrationController {
    private let service: SMAppService
    private(set) var snapshot: PAMIntegrationSnapshot {
        didSet { didChange?(snapshot) }
    }
    var didChange: ((PAMIntegrationSnapshot) -> Void)?

    init() {
        service = SMAppService.daemon(plistName: PAMIntegrationConstants.launchDaemonPlistName)
        snapshot = PAMIntegrationSnapshot(
            integration: PAMIntegrationInspection(state: .notInstalled, detail: nil),
            service: .notRegistered,
            operationError: nil
        )
    }

    func refresh() {
        let serviceState = currentServiceState
        guard serviceState == .enabled else {
            snapshot = PAMIntegrationSnapshot(
                integration: localInspection(),
                service: serviceState,
                operationError: nil
            )
            return
        }

        callInstaller { [weak self] proxy, finish in
            proxy.status { code, detail in
                finish()
                Task { @MainActor [weak self] in
                    self?.acceptRemoteState(code: code, detail: detail)
                }
            }
        }
    }

    func install() {
        clearOperationError()
        do {
            switch service.status {
            case .notRegistered:
                try service.register()
            case .enabled:
                break
            case .requiresApproval:
                presentRequiredApproval()
                return
            case .notFound:
                updateOperationError("The PAM installer is missing from this application build.")
                return
            @unknown default:
                snapshot = PAMIntegrationSnapshot(
                    integration: localInspection(),
                    service: .unavailable,
                    operationError: "The PAM installer service has an unknown state."
                )
                return
            }
        } catch {
            if service.status == .requiresApproval {
                presentRequiredApproval()
                return
            }
            updateOperationError(error.localizedDescription)
            return
        }

        guard service.status == .enabled else {
            presentRequiredApproval()
            return
        }

        callInstaller { [weak self] proxy, finish in
            proxy.install { code, detail in
                finish()
                Task { @MainActor [weak self] in
                    self?.acceptRemoteState(code: code, detail: detail)
                }
            }
        }
    }

    func uninstall() {
        clearOperationError()

        guard service.status == .enabled else {
            let local = localInspection()
            if local.state == .notInstalled {
                unregisterServiceIfNeeded()
            } else {
                snapshot = PAMIntegrationSnapshot(
                    integration: local,
                    service: currentServiceState,
                    operationError: "Enable the Who Sudo'd installer in Login Items before removal."
                )
                SMAppService.openSystemSettingsLoginItems()
            }
            return
        }

        callInstaller { [weak self] proxy, finish in
            proxy.uninstall { code, detail in
                finish()
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    guard PAMIntegrationStateCode(rawValue: code) == .notInstalled else {
                        acceptRemoteState(code: code, detail: detail)
                        return
                    }
                    unregisterServiceIfNeeded()
                }
            }
        }
    }

    private var currentServiceState: PAMInstallerServiceState {
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

    private func localInspection() -> PAMIntegrationInspection {
        let configurationURL = URL(fileURLWithPath: PAMIntegrationConstants.sudoConfigurationPath)
        let modulePayloadURL = Bundle.main.bundleURL
            .appendingPathComponent(PAMIntegrationConstants.embeddedModuleRelativePath)
        let terminalReaderPayloadURL = Bundle.main.bundleURL
            .appendingPathComponent(PAMIntegrationConstants.embeddedTerminalReaderRelativePath)

        do {
            let configuration = try Data(contentsOf: configurationURL, options: .mappedIfSafe)
            let installedModule = try installedPayloadData(
                at: PAMIntegrationConstants.installedModulePath
            )
            let installedTerminalReader = try installedPayloadData(
                at: PAMIntegrationConstants.installedTerminalReaderPath
            )
            guard let modulePayload = try? Data(
                contentsOf: modulePayloadURL,
                options: .mappedIfSafe
            ),
            let terminalReaderPayload = try? Data(
                contentsOf: terminalReaderPayloadURL,
                options: .mappedIfSafe
            ) else {
                return PAMIntegrationInspection(
                    state: .unsupported,
                    detail: "A bundled PAM component is missing."
                )
            }
            return PAMConfigurationEditor.inspect(
                configuration: configuration,
                moduleExists: installedModule != nil,
                moduleMatchesPayload: installedModule == modulePayload,
                terminalReaderExists: installedTerminalReader != nil,
                terminalReaderMatchesPayload: installedTerminalReader == terminalReaderPayload
            )
        } catch {
            return PAMIntegrationInspection(state: .unsupported, detail: error.localizedDescription)
        }
    }

    private func installedPayloadData(at path: String) throws -> Data? {
        var pathMetadata = stat()
        guard lstat(path, &pathMetadata) == 0 else {
            if errno == ENOENT {
                return nil
            }
            throw CocoaError(.fileReadUnknown)
        }
        try requireSafeInstalledDirectories()
        guard pathMetadata.st_mode & S_IFMT == S_IFREG,
              pathMetadata.st_uid == 0,
              pathMetadata.st_gid == 0,
              pathMetadata.st_nlink == 1,
              pathMetadata.st_mode & mode_t(0o777) == mode_t(0o555) else {
            throw PAMLocalInspectionError.unsafePath(path)
        }

        let descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else {
            throw CocoaError(.fileReadUnknown)
        }
        defer { close(descriptor) }
        var descriptorMetadata = stat()
        guard fstat(descriptor, &descriptorMetadata) == 0,
              descriptorMetadata.st_dev == pathMetadata.st_dev,
              descriptorMetadata.st_ino == pathMetadata.st_ino else {
            throw CocoaError(.fileReadUnknown)
        }
        try requireNoExtendedACL(fd: descriptor, path: path)

        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 16_384)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count == 0 {
                break
            }
            if count < 0 {
                if errno == EINTR {
                    continue
                }
                throw CocoaError(.fileReadUnknown)
            }
            data.append(buffer, count: count)
        }
        return data
    }

    private func requireSafeInstalledDirectories() throws {
        for path in [
            "/Library",
            "/Library/Security",
            PAMIntegrationConstants.installationDirectoryPath,
        ] {
            var metadata = stat()
            guard lstat(path, &metadata) == 0,
                  metadata.st_mode & S_IFMT == S_IFDIR,
                  metadata.st_uid == 0,
                  metadata.st_gid == 0,
                  metadata.st_mode & mode_t(0o7777) == mode_t(0o755) else {
                throw PAMLocalInspectionError.unsafePath(path)
            }
            try requireNoExtendedACL(path: path)
        }
    }

    private func requireNoExtendedACL(path: String) throws {
        errno = 0
        guard let accessControlList = acl_get_file(path, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT {
                return
            }
            throw CocoaError(.fileReadUnknown)
        }
        defer { acl_free(UnsafeMutableRawPointer(accessControlList)) }
        try requireEmptyAccessControlList(accessControlList, path: path)
    }

    private func requireNoExtendedACL(fd: Int32, path: String) throws {
        errno = 0
        guard let accessControlList = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT {
                return
            }
            throw CocoaError(.fileReadUnknown)
        }
        defer { acl_free(UnsafeMutableRawPointer(accessControlList)) }
        try requireEmptyAccessControlList(accessControlList, path: path)
    }

    private func requireEmptyAccessControlList(_ accessControlList: acl_t, path: String) throws {
        var entry: acl_entry_t?
        let result = acl_get_entry(
            accessControlList,
            Int32(ACL_FIRST_ENTRY.rawValue),
            &entry
        )
        if result == 1 {
            throw PAMLocalInspectionError.unsafePath(path)
        }
        if result < 0 {
            throw CocoaError(.fileReadUnknown)
        }
    }

    private func callInstaller(
        _ body: (PAMInstallerXPCProtocol, @escaping () -> Void) -> Void
    ) {
        let connection = NSXPCConnection(
            machServiceName: PAMIntegrationConstants.machServiceName,
            options: .privileged
        )
        connection.remoteObjectInterface = NSXPCInterface(with: PAMInstallerXPCProtocol.self)
        connection.setCodeSigningRequirement(PAMIntegrationConstants.installerSigningRequirement)

        let finish = {
            connection.invalidate()
        }
        connection.interruptionHandler = { [weak self] in
            finish()
            Task { @MainActor [weak self] in
                self?.updateOperationError("The PAM installer service stopped before it replied.")
            }
        }
        connection.invalidationHandler = {}
        connection.activate()

        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ [weak self] error in
            finish()
            Task { @MainActor [weak self] in
                self?.updateOperationError(error.localizedDescription)
            }
        }) as? PAMInstallerXPCProtocol else {
            finish()
            updateOperationError("The PAM installer service did not provide the expected interface.")
            return
        }
        body(proxy, finish)
    }

    private func acceptRemoteState(code: Int, detail: String?) {
        guard let state = PAMIntegrationStateCode(rawValue: code) else {
            updateOperationError("The PAM installer returned an unknown state.")
            return
        }
        snapshot = PAMIntegrationSnapshot(
            integration: PAMIntegrationInspection(state: state, detail: detail),
            service: currentServiceState,
            operationError: state == .unsupported ? detail : nil
        )
    }

    private func unregisterServiceIfNeeded() {
        do {
            if service.status != .notRegistered {
                try service.unregister()
            }
            snapshot = PAMIntegrationSnapshot(
                integration: localInspection(),
                service: currentServiceState,
                operationError: nil
            )
        } catch {
            updateOperationError(error.localizedDescription)
        }
    }

    private func clearOperationError() {
        snapshot = PAMIntegrationSnapshot(
            integration: snapshot.integration,
            service: currentServiceState,
            operationError: nil
        )
    }

    private func updateOperationError(_ message: String) {
        snapshot = PAMIntegrationSnapshot(
            integration: localInspection(),
            service: currentServiceState,
            operationError: message
        )
    }

    private func presentRequiredApproval() {
        snapshot = PAMIntegrationSnapshot(
            integration: localInspection(),
            service: currentServiceState,
            operationError: "Approve the Who Sudo'd installer in Login Items, then try again."
        )
        SMAppService.openSystemSettingsLoginItems()
    }
}

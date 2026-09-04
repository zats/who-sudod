import Darwin
import Foundation

private enum PAMLocalInspectionError: LocalizedError {
    case unsafePath(String)

    var errorDescription: String? {
        switch self {
        case .unsafePath(let path):
            "The PAM installation has unsafe access controls at \(path)."
        }
    }
}

struct PAMIntegrationSnapshot: Equatable, Sendable {
    let integration: PAMIntegrationInspection
    let helper: PAMHelperServiceState
    let operationError: String?
    let uninstallRecoveryPhase: PAMUninstallRecoveryPhase

    var uninstallPending: Bool {
        uninstallRecoveryPhase == .uninstallPending
    }

    var helperCleanupRequired: Bool {
        uninstallRecoveryPhase == .helperCleanupRequired
    }

    init(
        integration: PAMIntegrationInspection,
        helper: PAMHelperServiceState,
        operationError: String?,
        uninstallRecoveryPhase: PAMUninstallRecoveryPhase = .none
    ) {
        self.integration = integration
        self.helper = helper
        self.operationError = operationError
        self.uninstallRecoveryPhase = uninstallRecoveryPhase
    }
}

enum PAMUninstallRecoveryPhase: String, Equatable, Sendable {
    case none
    case uninstallPending
    case helperCleanupRequired
}

@MainActor
final class PAMIntegrationController {
    private let bundleURL: URL
    private let service: PAMHelperServiceControlling
    private let helper: PAMHelperCalling
    private let systemAdministrationAccess: PAMSystemAdministrationAccessAuthorizing
    private let authorizer: PAMOperationAuthorizing
    private let recoveryStore: PAMUninstallRecoveryStoring
    private let localInspectionOverride: (() -> PAMIntegrationInspection)?
    private var recoveryPhase: PAMUninstallRecoveryPhase
    private var operationIsInFlight = false
    private var stateRevision: UInt64 = 0

    private(set) var snapshot: PAMIntegrationSnapshot {
        didSet { didChange?(snapshot) }
    }
    private(set) var hasCompletedRefresh = false
    var didChange: ((PAMIntegrationSnapshot) -> Void)?

    init(
        bundleURL: URL = Bundle.main.bundleURL,
        service: PAMHelperServiceControlling? = nil,
        helper: PAMHelperCalling? = nil,
        systemAdministrationAccess: PAMSystemAdministrationAccessAuthorizing? = nil,
        authorizer: PAMOperationAuthorizing? = nil,
        recoveryStore: PAMUninstallRecoveryStoring? = nil,
        localInspection: (() -> PAMIntegrationInspection)? = nil
    ) {
        self.bundleURL = bundleURL.standardizedFileURL
        let service = service ?? SystemPAMHelperServiceController()
        self.service = service
        self.helper = helper ?? SystemPAMHelperClient(applicationBundleURL: bundleURL)
        self.systemAdministrationAccess = systemAdministrationAccess
            ?? SystemPAMSystemAdministrationAccessAuthorizer()
        self.authorizer = authorizer ?? SystemPAMOperationAuthorizer()
        let recoveryStore = recoveryStore ?? FilePAMUninstallRecoveryStore()
        self.recoveryStore = recoveryStore
        localInspectionOverride = localInspection
        let helperState = service.state
        var initialOperationError: String?
        var recoveryPhase: PAMUninstallRecoveryPhase
        do {
            recoveryPhase = try recoveryStore.load()
        } catch {
            recoveryPhase = .none
            initialOperationError = error.localizedDescription
        }
        if helperState == .notRegistered,
           recoveryPhase == .helperCleanupRequired {
            do {
                try recoveryStore.save(.none)
                recoveryPhase = .none
            } catch {
                initialOperationError = error.localizedDescription
            }
        }
        self.recoveryPhase = recoveryPhase
        snapshot = PAMIntegrationSnapshot(
            integration: PAMIntegrationInspection(state: .notInstalled, detail: nil),
            helper: helperState,
            operationError: initialOperationError,
            uninstallRecoveryPhase: recoveryPhase
        )
    }

    func refresh() {
        guard !operationIsInFlight else {
            return
        }
        stateRevision &+= 1
        let revision = stateRevision
        let helperState = service.state
        guard helperState == .enabled else {
            let integration = localInspection()
            let recovery = reconcileRecoveryPhase(
                for: integration,
                helperState: helperState
            )
            hasCompletedRefresh = true
            snapshot = PAMIntegrationSnapshot(
                integration: integration,
                helper: helperState,
                operationError: recovery.operationError,
                uninstallRecoveryPhase: recovery.phase
            )
            return
        }

        helper.preflight { [weak self] result in
            guard let self,
                  stateRevision == revision,
                  !operationIsInFlight else {
                return
            }
            switch result {
            case .success(let identity):
                helper.status(expectedBuildIdentity: identity) { [weak self] code, detail in
                    guard let self,
                          stateRevision == revision,
                          !operationIsInFlight else {
                        return
                    }
                    hasCompletedRefresh = true
                    acceptRemoteState(code: code, detail: detail)
                }
            case .failure(let error):
                let integration = localInspection()
                let recovery = reconcileRecoveryPhase(
                    for: integration,
                    helperState: service.state
                )
                hasCompletedRefresh = true
                snapshot = PAMIntegrationSnapshot(
                    integration: integration,
                    helper: service.state,
                    operationError: recovery.operationError ?? error.localizedDescription,
                    uninstallRecoveryPhase: recovery.phase
                )
            }
        }
    }

    func install() {
        guard beginOperation() else {
            return
        }
        guard requestSystemAdministrationAccess() else {
            return
        }
        prepareHelperForMutation { [weak self] identity in
            guard let self else {
                return
            }
            guard let authorization = requestAuthorization() else {
                finishOperation()
                return
            }

            helper.install(
                authorization: authorization,
                expectedBuildIdentity: identity
            ) { [weak self] result in
                guard let self else {
                    return
                }
                finishOperation()
                acceptInstallResult(result)
            }
        }
    }

    func uninstall() {
        guard beginOperation() else {
            return
        }
        let local = localInspection()
        if local.state == .notInstalled {
            unregisterHelperIfNeeded(integration: local)
            return
        }
        guard requestSystemAdministrationAccess() else {
            return
        }
        prepareHelperForMutation { [weak self] identity in
            guard let self else {
                return
            }
            guard let authorization = requestAuthorization() else {
                finishOperation()
                return
            }

            do {
                try setRecoveryPhase(.uninstallPending, forcePersistence: true)
            } catch {
                stopOperation(with: error.localizedDescription)
                return
            }
            helper.uninstall(
                authorization: authorization,
                expectedBuildIdentity: identity
            ) { [weak self] result in
                guard let self else {
                    return
                }
                guard result.operationError == nil,
                      let integration = result.inspection,
                      integration.state == .notInstalled else {
                    finishOperation()
                    acceptUninstallFailure(result)
                    return
                }
                unregisterHelperIfNeeded(integration: integration)
            }
        }
    }

    func finishRemoval() {
        guard beginOperation() else {
            return
        }
        let local = localInspection()
        guard local.state == .notInstalled else {
            do {
                try setRecoveryPhase(
                    local.state == .installed ? .none : .uninstallPending
                )
            } catch {
                finishOperation()
                snapshot = PAMIntegrationSnapshot(
                    integration: local,
                    helper: service.state,
                    operationError: error.localizedDescription,
                    uninstallRecoveryPhase: storedRecoveryPhase()
                )
                return
            }
            finishOperation()
            snapshot = PAMIntegrationSnapshot(
                integration: local,
                helper: service.state,
                operationError: "PAM removal is not complete. Try removal again.",
                uninstallRecoveryPhase: storedRecoveryPhase()
            )
            return
        }
        unregisterHelperIfNeeded(integration: local)
    }

    private func beginOperation() -> Bool {
        guard !operationIsInFlight else {
            return false
        }
        operationIsInFlight = true
        stateRevision &+= 1
        clearOperationError()
        return true
    }

    private func finishOperation() {
        operationIsInFlight = false
    }

    private func prepareHelperForMutation(
        recoveryAttempted: Bool = false,
        completion: @escaping (PAMHelperBuildIdentity) -> Void
    ) {
        do {
            switch service.state {
            case .notRegistered:
                try service.register()
            case .enabled:
                preflightHelper(
                    recoveryAttempted: recoveryAttempted,
                    completion: completion
                )
                return
            case .requiresApproval:
                stopForRequiredApproval()
                return
            case .unavailable:
                stopOperation(
                    with: "The PAM helper is missing from this application build."
                )
                return
            }
        } catch {
            if service.state == .requiresApproval {
                stopForRequiredApproval()
            } else {
                stopOperation(with: error.localizedDescription)
            }
            return
        }

        switch service.state {
        case .enabled:
            preflightHelper(
                recoveryAttempted: recoveryAttempted,
                completion: completion
            )
        case .requiresApproval, .notRegistered:
            stopForRequiredApproval()
        case .unavailable:
            stopOperation(with: "The PAM helper is missing from this application build.")
        }
    }

    private func preflightHelper(
        recoveryAttempted: Bool,
        completion: @escaping (PAMHelperBuildIdentity) -> Void
    ) {
        helper.preflight { [weak self] result in
            guard let self, operationIsInFlight else {
                return
            }
            switch result {
            case .success(let identity):
                completion(identity)
            case .failure(let error):
                guard error.allowsServiceRecovery, !recoveryAttempted else {
                    stopOperation(with: error.localizedDescription)
                    return
                }
                replaceHelperAndRetryPreflight(completion: completion)
            }
        }
    }

    private func replaceHelperAndRetryPreflight(
        completion: @escaping (PAMHelperBuildIdentity) -> Void
    ) {
        service.unregister { [weak self] errorMessage in
            guard let self, operationIsInFlight else {
                return
            }
            if let errorMessage, service.state != .notRegistered {
                stopOperation(with: errorMessage)
                return
            }
            do {
                try service.register()
            } catch {
                if service.state == .requiresApproval {
                    stopForRequiredApproval()
                } else {
                    stopOperation(with: error.localizedDescription)
                }
                return
            }
            prepareHelperForMutation(
                recoveryAttempted: true,
                completion: completion
            )
        }
    }

    private func requestAuthorization() -> PAMOperationAuthorization? {
        do {
            return try authorizer.requestAuthorization()
        } catch PAMOperationAuthorizationError.cancelled {
            clearOperationError()
            return nil
        } catch {
            updateOperationError(error.localizedDescription)
            return nil
        }
    }

    private func requestSystemAdministrationAccess() -> Bool {
        do {
            try systemAdministrationAccess.requestAccess()
            return true
        } catch {
            stopOperation(with: error.localizedDescription)
            return false
        }
    }

    private func localInspection() -> PAMIntegrationInspection {
        if let localInspectionOverride {
            return localInspectionOverride()
        }
        let configurationURL = URL(fileURLWithPath: PAMIntegrationConstants.sudoConfigurationPath)
        let modulePayloadURL = bundleURL.appendingPathComponent(
            PAMIntegrationConstants.embeddedModuleRelativePath
        )
        let terminalReaderPayloadURL = bundleURL.appendingPathComponent(
            PAMIntegrationConstants.embeddedTerminalReaderRelativePath
        )

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
        switch PAMExtendedACLInspector.inspect(path: path) {
        case .absent:
            return
        case .present:
            throw PAMLocalInspectionError.unsafePath(path)
        case .queryFailed:
            throw CocoaError(.fileReadUnknown)
        }
    }

    private func requireNoExtendedACL(fd: Int32, path: String) throws {
        switch PAMExtendedACLInspector.inspect(fileDescriptor: fd) {
        case .absent:
            return
        case .present:
            throw PAMLocalInspectionError.unsafePath(path)
        case .queryFailed:
            throw CocoaError(.fileReadUnknown)
        }
    }

    private func acceptRemoteState(code: Int, detail: String?) {
        if code == PAMHelperReplyCode.transportFailure {
            let integration = localInspection()
            let recovery = reconcileRecoveryPhase(
                for: integration,
                helperState: service.state
            )
            snapshot = PAMIntegrationSnapshot(
                integration: integration,
                helper: service.state,
                operationError: recovery.operationError
                    ?? detail
                    ?? "The PAM helper did not complete the request.",
                uninstallRecoveryPhase: recovery.phase
            )
            return
        }
        guard let state = PAMIntegrationStateCode(rawValue: code) else {
            updateOperationError("The PAM helper returned an unknown state.")
            return
        }
        let helperState = service.state
        let integration = PAMIntegrationInspection(state: state, detail: detail)
        let recovery = reconcileRecoveryPhase(
            for: integration,
            helperState: helperState
        )
        snapshot = PAMIntegrationSnapshot(
            integration: integration,
            helper: helperState,
            operationError: recovery.operationError
                ?? (state == .unsupported ? detail : nil),
            uninstallRecoveryPhase: recovery.phase
        )
    }

    private func acceptInstallResult(_ result: PAMHelperMutationResult) {
        guard let inspection = result.inspection else {
            updateOperationError(
                result.operationError ?? "The PAM helper did not complete the request.",
                preserving: localInspection()
            )
            return
        }
        var operationError = result.operationError
        if operationError == nil, inspection.state == .installed {
            do {
                try setRecoveryPhase(.none)
            } catch {
                operationError = error.localizedDescription
            }
        }
        snapshot = PAMIntegrationSnapshot(
            integration: inspection,
            helper: service.state,
            operationError: operationError,
            uninstallRecoveryPhase: storedRecoveryPhase()
        )
    }

    private func acceptUninstallFailure(_ result: PAMHelperMutationResult) {
        let integration = result.inspection ?? localInspection()
        snapshot = PAMIntegrationSnapshot(
            integration: integration,
            helper: service.state,
            operationError: result.operationError
                ?? "PAM removal did not complete. Try again.",
            uninstallRecoveryPhase: .uninstallPending
        )
    }

    private func unregisterHelperIfNeeded(integration: PAMIntegrationInspection) {
        guard service.state != .notRegistered else {
            do {
                try setRecoveryPhase(.none)
            } catch {
                finishOperation()
                snapshot = PAMIntegrationSnapshot(
                    integration: integration,
                    helper: service.state,
                    operationError: error.localizedDescription,
                    uninstallRecoveryPhase: storedRecoveryPhase()
                )
                return
            }
            snapshot = PAMIntegrationSnapshot(
                integration: integration,
                helper: service.state,
                operationError: nil
            )
            finishOperation()
            return
        }

        do {
            try setRecoveryPhase(.helperCleanupRequired)
        } catch {
            finishOperation()
            snapshot = PAMIntegrationSnapshot(
                integration: integration,
                helper: service.state,
                operationError: error.localizedDescription,
                uninstallRecoveryPhase: storedRecoveryPhase()
            )
            return
        }
        snapshot = PAMIntegrationSnapshot(
            integration: integration,
            helper: service.state,
            operationError: nil,
            uninstallRecoveryPhase: .helperCleanupRequired
        )
        service.unregister { [weak self] errorMessage in
            guard let self, operationIsInFlight else {
                return
            }
            finishOperation()
            if let errorMessage, service.state != .notRegistered {
                snapshot = PAMIntegrationSnapshot(
                    integration: integration,
                    helper: service.state,
                    operationError: errorMessage,
                    uninstallRecoveryPhase: .helperCleanupRequired
                )
                return
            }
            do {
                try setRecoveryPhase(.none)
            } catch {
                snapshot = PAMIntegrationSnapshot(
                    integration: integration,
                    helper: service.state,
                    operationError: error.localizedDescription,
                    uninstallRecoveryPhase: storedRecoveryPhase()
                )
                return
            }
            snapshot = PAMIntegrationSnapshot(
                integration: integration,
                helper: service.state,
                operationError: nil
            )
        }
    }

    private func reconcileRecoveryPhase(
        for integration: PAMIntegrationInspection,
        helperState: PAMHelperServiceState
    ) -> (phase: PAMUninstallRecoveryPhase, operationError: String?) {
        let phase = storedRecoveryPhase()
        let resolvedPhase: PAMUninstallRecoveryPhase
        switch phase {
        case .none:
            resolvedPhase = .none
        case .uninstallPending:
            switch integration.state {
            case .installed:
                resolvedPhase = .none
            case .notInstalled:
                resolvedPhase = helperState == .notRegistered
                    ? .none
                    : .helperCleanupRequired
            case .needsRepair, .removalOnly, .unsupported:
                resolvedPhase = .uninstallPending
            }
        case .helperCleanupRequired:
            if helperState == .notRegistered || integration.state == .installed {
                resolvedPhase = .none
            } else if integration.state == .notInstalled {
                resolvedPhase = .helperCleanupRequired
            } else {
                resolvedPhase = .uninstallPending
            }
        }
        do {
            try setRecoveryPhase(resolvedPhase)
            return (resolvedPhase, nil)
        } catch {
            return (storedRecoveryPhase(), error.localizedDescription)
        }
    }

    private func storedRecoveryPhase() -> PAMUninstallRecoveryPhase {
        recoveryPhase
    }

    private func setRecoveryPhase(
        _ phase: PAMUninstallRecoveryPhase,
        forcePersistence: Bool = false
    ) throws {
        if !forcePersistence, recoveryPhase == phase {
            return
        }
        try recoveryStore.save(phase)
        recoveryPhase = phase
    }

    private func clearOperationError() {
        snapshot = PAMIntegrationSnapshot(
            integration: snapshot.integration,
            helper: service.state,
            operationError: nil,
            uninstallRecoveryPhase: snapshot.uninstallRecoveryPhase
        )
    }

    private func updateOperationError(
        _ message: String,
        preserving integration: PAMIntegrationInspection? = nil
    ) {
        snapshot = PAMIntegrationSnapshot(
            integration: integration ?? localInspection(),
            helper: service.state,
            operationError: message,
            uninstallRecoveryPhase: snapshot.uninstallRecoveryPhase
        )
    }

    private func stopOperation(with message: String) {
        finishOperation()
        updateOperationError(message)
    }

    private func stopForRequiredApproval() {
        finishOperation()
        snapshot = PAMIntegrationSnapshot(
            integration: localInspection(),
            helper: service.state,
            operationError: "Allow the Who Sudo'd helper in Login Items, then try again.",
            uninstallRecoveryPhase: snapshot.uninstallRecoveryPhase
        )
        service.openApprovalSettings()
    }
}

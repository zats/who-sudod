import Foundation

final class PAMInstallerService: NSObject, PAMInstallerXPCProtocol {
    private static let shuttingDownDetail = "The PAM helper is shutting down. Try again."

    private let files = PAMInstallerFileManager()
    private let mutationAuthorizationGate = PAMInstallerMutationAuthorizationGate()
    private let clientAuditSessionGate = PAMInstallerClientAuditSessionGate()
    private let lock = NSLock()
    private let lifecycle: PAMInstallerLifecycle

    init(lifecycle: PAMInstallerLifecycle) {
        self.lifecycle = lifecycle
    }

    func buildIdentity(reply: @escaping (Data?, String?) -> Void) {
        guard lifecycle.beginOperation() else {
            reply(nil, Self.shuttingDownDetail)
            return
        }
        defer { lifecycle.endOperation() }
        do {
            let identity = try PAMHelperBuildIdentity.currentHelper()
            reply(identity.token, nil)
        } catch {
            reply(
                nil,
                (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            )
        }
    }

    func status(reply: @escaping (Int, String?) -> Void) {
        performWithoutAuthorization({ files.inspect() }, reply: reply)
    }

    func install(
        authorization: Data,
        expectedBuildIdentity: Data,
        reply: @escaping (Int, String?, String?) -> Void
    ) {
        perform(
            authorization: authorization,
            expectedBuildIdentity: expectedBuildIdentity,
            operation: { files.install(expectedBuildIdentity: expectedBuildIdentity) },
            reply: reply
        )
    }

    func uninstall(
        authorization: Data,
        expectedBuildIdentity: Data,
        reply: @escaping (Int, String?, String?) -> Void
    ) {
        perform(
            authorization: authorization,
            expectedBuildIdentity: expectedBuildIdentity,
            operation: { files.uninstall(expectedBuildIdentity: expectedBuildIdentity) },
            reply: reply
        )
    }

    private func performWithoutAuthorization(
        _ operation: () -> PAMIntegrationInspection,
        reply: @escaping (Int, String?) -> Void
    ) {
        guard lifecycle.beginOperation() else {
            reply(PAMHelperReplyCode.transportFailure, Self.shuttingDownDetail)
            return
        }
        defer { lifecycle.endOperation() }
        let inspection = lock.withLock(operation)
        reply(inspection.state.rawValue, inspection.detail)
    }

    private func perform(
        authorization: Data,
        expectedBuildIdentity: Data,
        operation: () -> PAMInstallerMutationResult,
        reply: @escaping (Int, String?, String?) -> Void
    ) {
        guard lifecycle.beginOperation() else {
            reply(
                PAMHelperReplyCode.transportFailure,
                nil,
                Self.shuttingDownDetail
            )
            return
        }
        defer { lifecycle.endOperation() }
        guard let connection = NSXPCConnection.current() else {
            let result = PAMInstallerMutationResult(
                inspection: files.inspect(),
                operationError: PAMInstallerClientAuditSessionError.unavailable
                    .localizedDescription
            )
            reply(
                result.inspection.state.rawValue,
                result.inspection.detail,
                result.operationError
            )
            return
        }
        let clientAuditSession = PAMInstallerClientAuditSession(
            userIdentifier: connection.effectiveUserIdentifier,
            sessionIdentifier: connection.auditSessionIdentifier
        )
        let result = lock.withLock {
            do {
                return try mutationAuthorizationGate.perform(
                    authorization: authorization,
                    expectedBuildIdentity: expectedBuildIdentity,
                    operation: {
                        try clientAuditSessionGate.perform(
                            client: clientAuditSession,
                            operation: operation
                        )
                    }
                )
            } catch {
                return PAMInstallerMutationResult(
                    inspection: files.inspect(),
                    operationError: (error as? LocalizedError)?.errorDescription
                        ?? error.localizedDescription
                )
            }
        }
        reply(
            result.inspection.state.rawValue,
            result.inspection.detail,
            result.operationError
        )
    }
}

final class PAMInstallerListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let lifecycle = PAMInstallerLifecycle()
    private lazy var service = PAMInstallerService(lifecycle: lifecycle)

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        guard connection.processIdentifier > 0 else {
            return false
        }
        guard lifecycle.add(connection) else {
            return false
        }
        let finish = { [weak lifecycle, weak connection] in
            guard let connection else {
                return
            }
            lifecycle?.remove(connection)
        }
        connection.interruptionHandler = finish
        connection.invalidationHandler = finish
        connection.exportedInterface = NSXPCInterface(with: PAMInstallerXPCProtocol.self)
        connection.exportedObject = service
        connection.activate()
        return true
    }
}

let delegate = PAMInstallerListenerDelegate()
let listener = NSXPCListener(machServiceName: PAMIntegrationConstants.machServiceName)
let applicationSigningRequirement: String
do {
    applicationSigningRequirement = try PAMHelperBuildIdentity.currentHelper()
        .exactApplicationSigningRequirement()
} catch {
    exit(EXIT_FAILURE)
}
listener.setConnectionCodeSigningRequirement(applicationSigningRequirement)
listener.delegate = delegate
listener.activate()
dispatchMain()

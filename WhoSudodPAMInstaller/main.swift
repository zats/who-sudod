import Foundation

final class PAMInstallerLifecycle: @unchecked Sendable {
    private let lock = NSLock()
    private var connections: [ObjectIdentifier: NSXPCConnection] = [:]
    private var activeOperations = 0
    private var exitGeneration: UInt64 = 0

    init() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            self?.exitIfStillIdle(generation: 0)
        }
    }

    func add(_ connection: NSXPCConnection) {
        lock.withLock {
            exitGeneration &+= 1
            connections[ObjectIdentifier(connection)] = connection
        }
    }

    func remove(_ connection: NSXPCConnection) {
        lock.withLock {
            connections.removeValue(forKey: ObjectIdentifier(connection))
            scheduleExitIfIdle()
        }
    }

    func beginOperation() {
        lock.withLock {
            exitGeneration &+= 1
            activeOperations += 1
        }
    }

    func endOperation() {
        lock.withLock {
            activeOperations -= 1
            scheduleExitIfIdle()
        }
    }

    private func scheduleExitIfIdle() {
        guard connections.isEmpty, activeOperations == 0 else {
            return
        }
        exitGeneration &+= 1
        let generation = exitGeneration
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { [weak self] in
            self?.exitIfStillIdle(generation: generation)
        }
    }

    private func exitIfStillIdle(generation: UInt64) {
        let shouldExit = lock.withLock {
            exitGeneration == generation
                && connections.isEmpty
                && activeOperations == 0
        }
        if shouldExit {
            exit(EXIT_SUCCESS)
        }
    }
}

final class PAMInstallerService: NSObject, PAMInstallerXPCProtocol {
    private let files = PAMInstallerFileManager()
    private let mutationAuthorizationGate = PAMInstallerMutationAuthorizationGate()
    private let clientAuditSessionGate = PAMInstallerClientAuditSessionGate()
    private let lock = NSLock()
    private let lifecycle: PAMInstallerLifecycle

    init(lifecycle: PAMInstallerLifecycle) {
        self.lifecycle = lifecycle
    }

    func buildIdentity(reply: @escaping (Data?, String?) -> Void) {
        lifecycle.beginOperation()
        do {
            let identity = try PAMHelperBuildIdentity.currentHelper()
            reply(identity.token, nil)
        } catch {
            reply(
                nil,
                (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            )
        }
        lifecycle.endOperation()
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
        lifecycle.beginOperation()
        let inspection = lock.withLock(operation)
        reply(inspection.state.rawValue, inspection.detail)
        lifecycle.endOperation()
    }

    private func perform(
        authorization: Data,
        expectedBuildIdentity: Data,
        operation: () -> PAMInstallerMutationResult,
        reply: @escaping (Int, String?, String?) -> Void
    ) {
        lifecycle.beginOperation()
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
            lifecycle.endOperation()
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
        lifecycle.endOperation()
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
        lifecycle.add(connection)
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

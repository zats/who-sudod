import Foundation

enum PAMHelperPreflightError: LocalizedError, Equatable {
    case invalidEmbeddedBuild(String)
    case serviceUnavailable(String)
    case identityMismatch

    var allowsServiceRecovery: Bool {
        switch self {
        case .invalidEmbeddedBuild:
            false
        case .serviceUnavailable, .identityMismatch:
            true
        }
    }

    var errorDescription: String? {
        switch self {
        case .invalidEmbeddedBuild(let detail), .serviceUnavailable(let detail):
            detail
        case .identityMismatch:
            PAMHelperBuildIdentityError.mismatch.errorDescription
        }
    }
}

struct PAMHelperMutationResult: Equatable, Sendable {
    let inspection: PAMIntegrationInspection?
    let operationError: String?

    static func transportFailure(_ detail: String) -> Self {
        Self(inspection: nil, operationError: detail)
    }
}

@MainActor
protocol PAMHelperCalling: AnyObject {
    func preflight(
        reply: @escaping (Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) -> Void
    )
    func status(
        expectedBuildIdentity: PAMHelperBuildIdentity,
        reply: @escaping (Int, String?) -> Void
    )
    func install(
        authorization: PAMOperationAuthorization,
        expectedBuildIdentity: PAMHelperBuildIdentity,
        reply: @escaping (PAMHelperMutationResult) -> Void
    )
    func uninstall(
        authorization: PAMOperationAuthorization,
        expectedBuildIdentity: PAMHelperBuildIdentity,
        reply: @escaping (PAMHelperMutationResult) -> Void
    )
}

@MainActor
final class SystemPAMHelperClient: PAMHelperCalling {
    private let applicationBundleURL: URL

    init(applicationBundleURL: URL = Bundle.main.bundleURL) {
        self.applicationBundleURL = applicationBundleURL.standardizedFileURL
    }

    func preflight(
        reply: @escaping (Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) -> Void
    ) {
        let expectedIdentity: PAMHelperBuildIdentity
        do {
            expectedIdentity = try PAMHelperBuildIdentity.embedded(in: applicationBundleURL)
        } catch {
            reply(.failure(.invalidEmbeddedBuild(error.localizedDescription)))
            return
        }
        let exactHelperRequirement: String
        do {
            exactHelperRequirement = try expectedIdentity.exactHelperSigningRequirement()
        } catch {
            reply(.failure(.invalidEmbeddedBuild(error.localizedDescription)))
            return
        }

        callIdentity(signingRequirement: exactHelperRequirement, reply: reply) { proxy, finish in
            proxy.buildIdentity { token, detail in
                guard let token else {
                    finish(
                        .failure(
                            .serviceUnavailable(
                                detail ?? "The PAM helper could not report its build identity."
                            )
                        )
                    )
                    return
                }
                guard token == expectedIdentity.token else {
                    finish(.failure(.identityMismatch))
                    return
                }
                finish(.success(expectedIdentity))
            }
        }
    }

    func status(
        expectedBuildIdentity: PAMHelperBuildIdentity,
        reply: @escaping (Int, String?) -> Void
    ) {
        let signingRequirement: String
        do {
            signingRequirement = try expectedBuildIdentity.exactHelperSigningRequirement()
        } catch {
            reply(PAMHelperReplyCode.transportFailure, error.localizedDescription)
            return
        }
        call(signingRequirement: signingRequirement, reply: reply) { proxy, finish in
            proxy.status { code, detail in
                finish(code, detail)
            }
        }
    }

    func install(
        authorization: PAMOperationAuthorization,
        expectedBuildIdentity: PAMHelperBuildIdentity,
        reply: @escaping (PAMHelperMutationResult) -> Void
    ) {
        let signingRequirement: String
        do {
            signingRequirement = try expectedBuildIdentity.exactHelperSigningRequirement()
        } catch {
            reply(.transportFailure(error.localizedDescription))
            return
        }
        callMutation(
            signingRequirement: signingRequirement,
            reply: reply,
            retaining: authorization
        ) { proxy, finish in
            proxy.install(
                authorization: authorization.externalFormData,
                expectedBuildIdentity: expectedBuildIdentity.token
            ) { code, detail, operationError in
                finish(Self.mutationResult(
                    code: code,
                    detail: detail,
                    operationError: operationError
                ))
            }
        }
    }

    func uninstall(
        authorization: PAMOperationAuthorization,
        expectedBuildIdentity: PAMHelperBuildIdentity,
        reply: @escaping (PAMHelperMutationResult) -> Void
    ) {
        let signingRequirement: String
        do {
            signingRequirement = try expectedBuildIdentity.exactHelperSigningRequirement()
        } catch {
            reply(.transportFailure(error.localizedDescription))
            return
        }
        callMutation(
            signingRequirement: signingRequirement,
            reply: reply,
            retaining: authorization
        ) { proxy, finish in
            proxy.uninstall(
                authorization: authorization.externalFormData,
                expectedBuildIdentity: expectedBuildIdentity.token
            ) { code, detail, operationError in
                finish(Self.mutationResult(
                    code: code,
                    detail: detail,
                    operationError: operationError
                ))
            }
        }
    }

    private static func mutationResult(
        code: Int,
        detail: String?,
        operationError: String?
    ) -> PAMHelperMutationResult {
        guard let state = PAMIntegrationStateCode(rawValue: code) else {
            return .transportFailure("The PAM helper returned an unknown state.")
        }
        return PAMHelperMutationResult(
            inspection: PAMIntegrationInspection(state: state, detail: detail),
            operationError: operationError
        )
    }

    private func callIdentity(
        signingRequirement: String,
        reply: @escaping (Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) -> Void,
        body: (
            PAMInstallerXPCProtocol,
            @escaping (Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) -> Void
        ) -> Void
    ) {
        let connection = connection(signingRequirement: signingRequirement)
        let completion = PAMHelperIdentityReply(connection: connection, reply: reply)
        connection.interruptionHandler = {
            completion.finish(
                .failure(.serviceUnavailable("The PAM helper stopped before it replied."))
            )
        }
        connection.invalidationHandler = {
            completion.finish(
                .failure(
                    .serviceUnavailable(
                        "The PAM helper connection closed before it replied."
                    )
                )
            )
        }
        connection.activate()

        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            completion.finish(.failure(.serviceUnavailable(error.localizedDescription)))
        }) as? PAMInstallerXPCProtocol else {
            completion.finish(
                .failure(
                    .serviceUnavailable(
                        "The PAM helper did not provide the expected interface."
                    )
                )
            )
            return
        }
        body(proxy, completion.finish)
    }

    private func call(
        signingRequirement: String = PAMIntegrationConstants.helperSigningRequirement,
        reply: @escaping (Int, String?) -> Void,
        retaining retainedObject: AnyObject? = nil,
        body: (
            PAMInstallerXPCProtocol,
            @escaping (Int, String?) -> Void
        ) -> Void
    ) {
        let connection = connection(signingRequirement: signingRequirement)

        let completion = PAMHelperReply(
            connection: connection,
            retainedObject: retainedObject,
            reply: reply
        )
        connection.interruptionHandler = {
            completion.finish(
                PAMHelperReplyCode.transportFailure,
                "The PAM helper stopped before it replied."
            )
        }
        connection.invalidationHandler = {
            completion.finish(
                PAMHelperReplyCode.transportFailure,
                "The PAM helper connection closed before it replied."
            )
        }
        connection.activate()

        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            completion.finish(
                PAMHelperReplyCode.transportFailure,
                error.localizedDescription
            )
        }) as? PAMInstallerXPCProtocol else {
            completion.finish(
                PAMHelperReplyCode.transportFailure,
                "The PAM helper did not provide the expected interface."
            )
            return
        }
        body(proxy, completion.finish)
    }

    private func callMutation(
        signingRequirement: String,
        reply: @escaping (PAMHelperMutationResult) -> Void,
        retaining retainedObject: AnyObject? = nil,
        body: (
            PAMInstallerXPCProtocol,
            @escaping (PAMHelperMutationResult) -> Void
        ) -> Void
    ) {
        let connection = connection(signingRequirement: signingRequirement)
        let completion = PAMHelperMutationReply(
            connection: connection,
            retainedObject: retainedObject,
            reply: reply
        )
        connection.interruptionHandler = {
            completion.finish(
                .transportFailure("The PAM helper stopped before it replied.")
            )
        }
        connection.invalidationHandler = {
            completion.finish(
                .transportFailure(
                    "The PAM helper connection closed before it replied."
                )
            )
        }
        connection.activate()

        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            completion.finish(.transportFailure(error.localizedDescription))
        }) as? PAMInstallerXPCProtocol else {
            completion.finish(
                .transportFailure(
                    "The PAM helper did not provide the expected interface."
                )
            )
            return
        }
        body(proxy, completion.finish)
    }

    private func connection(signingRequirement: String) -> NSXPCConnection {
        let connection = NSXPCConnection(
            machServiceName: PAMIntegrationConstants.machServiceName,
            options: .privileged
        )
        connection.remoteObjectInterface = NSXPCInterface(with: PAMInstallerXPCProtocol.self)
        connection.setCodeSigningRequirement(signingRequirement)
        return connection
    }
}

private final class PAMHelperIdentityReply: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: NSXPCConnection?
    private var reply: ((Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) -> Void)?

    init(
        connection: NSXPCConnection,
        reply: @escaping (Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) -> Void
    ) {
        self.connection = connection
        self.reply = reply
    }

    func finish(_ result: Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) {
        let values = lock.withLock {
            () -> (
                NSXPCConnection,
                (Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) -> Void
            )? in
            guard let connection, let reply else {
                return nil
            }
            self.connection = nil
            self.reply = nil
            return (connection, reply)
        }
        guard let (connection, reply) = values else {
            return
        }
        connection.invalidate()
        Task { @MainActor in
            reply(result)
        }
    }
}

private final class PAMHelperReply: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: NSXPCConnection?
    private var retainedObject: AnyObject?
    private var reply: ((Int, String?) -> Void)?

    init(
        connection: NSXPCConnection,
        retainedObject: AnyObject?,
        reply: @escaping (Int, String?) -> Void
    ) {
        self.connection = connection
        self.retainedObject = retainedObject
        self.reply = reply
    }

    func finish(_ code: Int, _ detail: String?) {
        let values = lock.withLock { () -> (NSXPCConnection, (Int, String?) -> Void)? in
            guard let connection, let reply else {
                return nil
            }
            self.connection = nil
            self.retainedObject = nil
            self.reply = nil
            return (connection, reply)
        }
        guard let (connection, reply) = values else {
            return
        }
        connection.invalidate()
        Task { @MainActor in
            reply(code, detail)
        }
    }
}

private final class PAMHelperMutationReply: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: NSXPCConnection?
    private var retainedObject: AnyObject?
    private var reply: ((PAMHelperMutationResult) -> Void)?

    init(
        connection: NSXPCConnection,
        retainedObject: AnyObject?,
        reply: @escaping (PAMHelperMutationResult) -> Void
    ) {
        self.connection = connection
        self.retainedObject = retainedObject
        self.reply = reply
    }

    func finish(_ result: PAMHelperMutationResult) {
        let values = lock.withLock {
            () -> (NSXPCConnection, (PAMHelperMutationResult) -> Void)? in
            guard let connection, let reply else {
                return nil
            }
            self.connection = nil
            self.retainedObject = nil
            self.reply = nil
            return (connection, reply)
        }
        guard let (connection, reply) = values else {
            return
        }
        connection.invalidate()
        Task { @MainActor in
            reply(result)
        }
    }
}

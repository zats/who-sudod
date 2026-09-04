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
    private static let replyTimeout: TimeInterval = 3
    private static let replyTimeoutDetail = "The PAM helper did not reply within three seconds."

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

        callIdentity(signingRequirement: exactHelperRequirement, reply: reply) {
            proxy,
            completion in
            proxy.buildIdentity(
                reply: completion.buildIdentityReplyHandler(
                    expectedIdentity: expectedIdentity
                )
            )
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
        call(
            signingRequirement: signingRequirement,
            reply: reply
        ) { proxy, completion in
            proxy.status(reply: completion.statusReplyHandler())
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
        ) { proxy, completion in
            proxy.install(
                authorization: authorization.externalFormData,
                expectedBuildIdentity: expectedBuildIdentity.token,
                reply: completion.mutationReplyHandler()
            )
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
        ) { proxy, completion in
            proxy.uninstall(
                authorization: authorization.externalFormData,
                expectedBuildIdentity: expectedBuildIdentity.token,
                reply: completion.mutationReplyHandler()
            )
        }
    }

    private func callIdentity(
        signingRequirement: String,
        reply: @escaping (Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) -> Void,
        body: (
            PAMInstallerXPCProtocol,
            PAMHelperIdentityReply
        ) -> Void
    ) {
        let connection = connection(signingRequirement: signingRequirement)
        let completion = PAMHelperIdentityReply(connection: connection, reply: reply)
        completion.failIfPending(
            after: Self.replyTimeout,
            detail: Self.replyTimeoutDetail
        )
        connection.interruptionHandler = completion.failureHandler(
            detail: "The PAM helper stopped before it replied."
        )
        connection.invalidationHandler = completion.failureHandler(
            detail: "The PAM helper connection closed before it replied."
        )
        connection.activate()

        guard let proxy = connection.remoteObjectProxyWithErrorHandler(
            completion.errorHandler()
        ) as? PAMInstallerXPCProtocol else {
            completion.finish(
                .failure(
                    .serviceUnavailable(
                        "The PAM helper did not provide the expected interface."
                    )
                )
            )
            return
        }
        body(proxy, completion)
    }

    private func call(
        signingRequirement: String = PAMIntegrationConstants.helperSigningRequirement,
        reply: @escaping (Int, String?) -> Void,
        retaining retainedObject: AnyObject? = nil,
        body: (
            PAMInstallerXPCProtocol,
            PAMHelperReply
        ) -> Void
    ) {
        let connection = connection(signingRequirement: signingRequirement)

        let completion = PAMHelperReply(
            connection: connection,
            retainedObject: retainedObject,
            reply: reply
        )
        completion.failIfPending(
            after: Self.replyTimeout,
            detail: Self.replyTimeoutDetail
        )
        connection.interruptionHandler = completion.failureHandler(
            detail: "The PAM helper stopped before it replied."
        )
        connection.invalidationHandler = completion.failureHandler(
            detail: "The PAM helper connection closed before it replied."
        )
        connection.activate()

        guard let proxy = connection.remoteObjectProxyWithErrorHandler(
            completion.errorHandler()
        ) as? PAMInstallerXPCProtocol else {
            completion.finish(
                PAMHelperReplyCode.transportFailure,
                "The PAM helper did not provide the expected interface."
            )
            return
        }
        body(proxy, completion)
    }

    private func callMutation(
        signingRequirement: String,
        reply: @escaping (PAMHelperMutationResult) -> Void,
        retaining retainedObject: AnyObject? = nil,
        body: (
            PAMInstallerXPCProtocol,
            PAMHelperMutationReply
        ) -> Void
    ) {
        let connection = connection(signingRequirement: signingRequirement)
        let completion = PAMHelperMutationReply(
            connection: connection,
            retainedObject: retainedObject,
            reply: reply
        )
        connection.interruptionHandler = completion.failureHandler(
            detail: "The PAM helper stopped before it replied."
        )
        connection.invalidationHandler = completion.failureHandler(
            detail: "The PAM helper connection closed before it replied."
        )
        connection.activate()

        guard let proxy = connection.remoteObjectProxyWithErrorHandler(
            completion.errorHandler()
        ) as? PAMInstallerXPCProtocol else {
            completion.finish(
                .transportFailure(
                    "The PAM helper did not provide the expected interface."
                )
            )
            return
        }
        body(proxy, completion)
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

private final class PAMHelperConnectionReference: @unchecked Sendable {
    private let value: NSXPCConnection

    init(_ value: NSXPCConnection) {
        self.value = value
    }

    @MainActor
    func invalidate() {
        value.invalidate()
    }
}

final class PAMHelperIdentityReply: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: PAMHelperConnectionReference?
    private var reply: ((Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) -> Void)?

    init(
        connection: NSXPCConnection,
        reply: @escaping (Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) -> Void
    ) {
        self.connection = PAMHelperConnectionReference(connection)
        self.reply = reply
    }

    func failIfPending(after interval: TimeInterval, detail: String) {
        DispatchQueue.global(qos: .userInitiated).asyncAfter(
            deadline: .now() + interval
        ) { [self] in
            finish(.failure(.serviceUnavailable(detail)))
        }
    }

    func failureHandler(detail: String) -> @Sendable () -> Void {
        { [self] in
            finish(.failure(.serviceUnavailable(detail)))
        }
    }

    func errorHandler() -> @Sendable (Error) -> Void {
        { [self] error in
            finish(.failure(.serviceUnavailable(error.localizedDescription)))
        }
    }

    func buildIdentityReplyHandler(
        expectedIdentity: PAMHelperBuildIdentity
    ) -> @Sendable (Data?, String?) -> Void {
        { [self] token, detail in
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

    func finish(_ result: Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) {
        let values = lock.withLock {
            () -> (
                PAMHelperConnectionReference,
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
        Task { @MainActor in
            connection.invalidate()
            reply(result)
        }
    }
}

final class PAMHelperReply: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: PAMHelperConnectionReference?
    private var retainedObject: AnyObject?
    private var reply: ((Int, String?) -> Void)?

    init(
        connection: NSXPCConnection,
        retainedObject: AnyObject?,
        reply: @escaping (Int, String?) -> Void
    ) {
        self.connection = PAMHelperConnectionReference(connection)
        self.retainedObject = retainedObject
        self.reply = reply
    }

    func failIfPending(after interval: TimeInterval, detail: String) {
        DispatchQueue.global(qos: .userInitiated).asyncAfter(
            deadline: .now() + interval
        ) { [self] in
            finish(PAMHelperReplyCode.transportFailure, detail)
        }
    }

    func failureHandler(detail: String) -> @Sendable () -> Void {
        { [self] in
            finish(PAMHelperReplyCode.transportFailure, detail)
        }
    }

    func errorHandler() -> @Sendable (Error) -> Void {
        { [self] error in
            finish(PAMHelperReplyCode.transportFailure, error.localizedDescription)
        }
    }

    func statusReplyHandler() -> @Sendable (Int, String?) -> Void {
        { [self] code, detail in
            finish(code, detail)
        }
    }

    func finish(_ code: Int, _ detail: String?) {
        let values = lock.withLock {
            () -> (PAMHelperConnectionReference, (Int, String?) -> Void)? in
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
        Task { @MainActor in
            connection.invalidate()
            reply(code, detail)
        }
    }
}

final class PAMHelperMutationReply: @unchecked Sendable {
    private let lock = NSLock()
    private var connection: PAMHelperConnectionReference?
    private var retainedObject: AnyObject?
    private var reply: ((PAMHelperMutationResult) -> Void)?

    init(
        connection: NSXPCConnection,
        retainedObject: AnyObject?,
        reply: @escaping (PAMHelperMutationResult) -> Void
    ) {
        self.connection = PAMHelperConnectionReference(connection)
        self.retainedObject = retainedObject
        self.reply = reply
    }

    func failureHandler(detail: String) -> @Sendable () -> Void {
        { [self] in
            finish(.transportFailure(detail))
        }
    }

    func errorHandler() -> @Sendable (Error) -> Void {
        { [self] error in
            finish(.transportFailure(error.localizedDescription))
        }
    }

    func mutationReplyHandler() -> @Sendable (Int, String?, String?) -> Void {
        { [self] code, detail, operationError in
            if code == PAMHelperReplyCode.transportFailure {
                finish(
                    .transportFailure(
                        operationError
                            ?? detail
                            ?? "The PAM helper did not complete the request."
                    )
                )
                return
            }
            guard let state = PAMIntegrationStateCode(rawValue: code) else {
                finish(.transportFailure("The PAM helper returned an unknown state."))
                return
            }
            finish(
                PAMHelperMutationResult(
                    inspection: PAMIntegrationInspection(state: state, detail: detail),
                    operationError: operationError
                )
            )
        }
    }

    func finish(_ result: PAMHelperMutationResult) {
        let values = lock.withLock {
            () -> (PAMHelperConnectionReference, (PAMHelperMutationResult) -> Void)? in
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
        Task { @MainActor in
            connection.invalidate()
            reply(result)
        }
    }
}

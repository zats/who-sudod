import Darwin
import Foundation

enum AuthenticationEventSource: Equatable, Sendable {
    case localAuthentication
    case authorization
}

enum LocalAuthenticationOperation: String, Hashable, Sendable {
    case evaluatePolicy
    case evaluateAccessControl
}

struct LocalAuthenticationRequestKey: Hashable, Sendable {
    let processID: pid_t
    let executablePath: String
    let operation: LocalAuthenticationOperation
    let contextComponents: [UInt64]
    let clientID: UInt64
}

enum AuthenticationRequestIdentifier: Hashable, Sendable {
    case localAuthentication(LocalAuthenticationRequestKey)
    case authorization(authdProcessID: pid_t, engineID: UInt64)
}

struct AuthenticationClientEvent: Equatable, Sendable {
    let processID: pid_t
    let executablePath: String?
    let receivedAt: Date
    let source: AuthenticationEventSource
    let requestIdentifier: AuthenticationRequestIdentifier?

    init(
        processID: pid_t,
        executablePath: String?,
        receivedAt: Date,
        source: AuthenticationEventSource,
        requestIdentifier: AuthenticationRequestIdentifier? = nil
    ) {
        self.processID = processID
        self.executablePath = executablePath
        self.receivedAt = receivedAt
        self.source = source
        self.requestIdentifier = requestIdentifier
    }
}

enum AuthenticationLifecycleEvent: Equatable, Sendable {
    case began(AuthenticationClientEvent)
    case ended(AuthenticationRequestIdentifier, receivedAt: Date)
    case reset
}

enum AuthenticationLogRecord: Equatable, Sendable {
    case localAuthentication(AuthenticationClientEvent)
    case localAuthenticationCompletion(AuthenticationRequestIdentifier)
    case authorizationEvaluation(
        requestIdentifier: AuthenticationRequestIdentifier,
        event: AuthenticationClientEvent,
        rightsCount: UInt
    )
    case authorizationMechanism(AuthenticationRequestIdentifier)
    case authorizationCompletion(AuthenticationRequestIdentifier)
}

enum AuthenticationLogEventParser {
    private struct LogRecord: Decodable {
        let subsystem: String?
        let category: String?
        let eventMessage: String?
        let processID: Int?
        let processImagePath: String?
    }

    private static let localAuthenticationSubsystem = "com.apple.LocalAuthentication"
    private static let authorizationSubsystem = "com.apple.Authorization"
    private static let authorizationDaemonPaths: Set<String> = [
        "/usr/libexec/authd",
        "/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/authd.xpc/Contents/MacOS/authd"
    ]
    private static let interactiveAuthorizationMechanisms: Set<String> = [
        "builtin:authenticate",
        "builtin:confirm",
        "builtin:prompt",
        "builtin:unlock-keychain"
    ]
    private static let brokerNames: Set<String> = [
        "coreauthd",
        "coreautha",
        "SecurityAgent",
        "authorizationhost",
        "LocalAuthenticationRemoteService"
    ]

    static func parse(line: String, receivedAt: Date) -> AuthenticationClientEvent? {
        switch parseRecord(line: line, receivedAt: receivedAt) {
        case let .localAuthentication(event),
             let .authorizationEvaluation(_, event, _):
            return AuthenticationClientEvent(
                processID: event.processID,
                executablePath: event.executablePath,
                receivedAt: event.receivedAt,
                source: event.source
            )
        case .localAuthenticationCompletion,
             .authorizationMechanism,
             .authorizationCompletion,
             nil:
            return nil
        }
    }

    static func parseRecord(line: String, receivedAt: Date) -> AuthenticationLogRecord? {
        guard let data = line.data(using: .utf8),
              let record = try? JSONDecoder().decode(LogRecord.self, from: data) else {
            return nil
        }

        if record.subsystem == localAuthenticationSubsystem {
            return parseLocalAuthentication(record, receivedAt: receivedAt)
        }
        if record.subsystem == authorizationSubsystem {
            return parseAuthorizationEvaluation(record, receivedAt: receivedAt)
                ?? parseAuthorizationMechanism(record)
                ?? parseAuthorizationCompletion(record)
        }
        return nil
    }

    private static func parseAuthorizationEvaluation(
        _ record: LogRecord,
        receivedAt: Date
    ) -> AuthenticationLogRecord? {
        guard isTrustedAuthorizationDaemon(record),
              let message = record.eventMessage,
              message.hasPrefix("Process ") else {
            return nil
        }

        let processPrefix = "Process "
        let processIDMarker = " (PID "
        let evaluationPrefix = " evaluates "
        let rightsMarker = " rights with flags "
        let engineMarker = " (engine "
        guard let markerRange = message.range(
            of: processIDMarker,
            options: .backwards
        ),
        let closingParenthesis = message[markerRange.upperBound...].firstIndex(of: ")"),
        message[message.index(after: closingParenthesis)...].hasPrefix(evaluationPrefix) else {
            return nil
        }

        let pathStart = message.index(message.startIndex, offsetBy: processPrefix.count)
        let clientPath = String(message[pathStart..<markerRange.lowerBound])
        let rawProcessID = message[markerRange.upperBound..<closingParenthesis]
        let rightsCountStart = message.index(
            message.index(after: closingParenthesis),
            offsetBy: evaluationPrefix.count
        )
        guard let rightsRange = message.range(
            of: rightsMarker,
            range: rightsCountStart..<message.endIndex
        ) else {
            return nil
        }
        let rawRightsCount = message[rightsCountStart..<rightsRange.lowerBound]
        let flagsText = message[rightsRange.upperBound...].prefix { $0.isHexDigit }
        let afterFlags = message.index(rightsRange.upperBound, offsetBy: flagsText.count)
        guard message[afterFlags...].hasPrefix(engineMarker) else {
            return nil
        }
        let engineStart = message.index(afterFlags, offsetBy: engineMarker.count)
        guard let engineEnd = message[engineStart...].firstIndex(of: ",") else {
            return nil
        }
        let rawEngineID = message[engineStart..<engineEnd]
        guard let executablePath = absolutePath(clientPath),
              let processID = validProcessID(Int(rawProcessID)),
              let rightsCount = UInt(rawRightsCount),
              rightsCount > 0,
              let flags = UInt32(flagsText, radix: 16),
              flags & 1 == 1,
              let engineID = UInt64(rawEngineID),
              let authdProcessID = validProcessID(record.processID) else {
            return nil
        }

        let requestIdentifier = AuthenticationRequestIdentifier.authorization(
            authdProcessID: authdProcessID,
            engineID: engineID
        )

        return .authorizationEvaluation(
            requestIdentifier: requestIdentifier,
            event: AuthenticationClientEvent(
                processID: processID,
                executablePath: executablePath,
                receivedAt: receivedAt,
                source: .authorization,
                requestIdentifier: requestIdentifier
            ),
            rightsCount: rightsCount
        )
    }

    private static func parseAuthorizationMechanism(
        _ record: LogRecord
    ) -> AuthenticationLogRecord? {
        guard isTrustedAuthorizationDaemon(record),
              let message = record.eventMessage,
              message.hasPrefix("engine ") else {
            return nil
        }

        let enginePrefix = "engine "
        let mechanismMarker = ": running mechanism "
        let engineStart = message.index(message.startIndex, offsetBy: enginePrefix.count)
        guard let markerRange = message.range(
            of: mechanismMarker,
            range: engineStart..<message.endIndex
        ),
        let engineID = UInt64(message[engineStart..<markerRange.lowerBound]) else {
            return nil
        }
        let mechanism = String(
            message[markerRange.upperBound...].prefix { !$0.isWhitespace && $0 != "(" }
        )
        let baseMechanism = mechanism.split(separator: ",", maxSplits: 1).first.map(String.init)
        guard let baseMechanism,
              interactiveAuthorizationMechanisms.contains(baseMechanism),
              let authdProcessID = validProcessID(record.processID) else {
            return nil
        }
        return .authorizationMechanism(
            .authorization(
                authdProcessID: authdProcessID,
                engineID: engineID
            )
        )
    }

    private static func parseAuthorizationCompletion(
        _ record: LogRecord
    ) -> AuthenticationLogRecord? {
        guard isTrustedAuthorizationDaemon(record),
              let message = record.eventMessage,
              message.hasPrefix("engine "),
              let resultMarker = message.range(of: ": authorize result: "),
              resultMarker.lowerBound > message.startIndex,
              isUnsignedDecimalInteger(message[
                  message.index(message.startIndex, offsetBy: "engine ".count)..<resultMarker.lowerBound
              ]),
              let engineID = UInt64(message[
                  message.index(message.startIndex, offsetBy: "engine ".count)..<resultMarker.lowerBound
              ]),
              isSignedDecimalInteger(message[resultMarker.upperBound...]),
              Int32(message[resultMarker.upperBound...]) != nil,
              let authdProcessID = validProcessID(record.processID) else {
            return nil
        }
        return .authorizationCompletion(
            .authorization(
                authdProcessID: authdProcessID,
                engineID: engineID
            )
        )
    }

    private static func isTrustedAuthorizationDaemon(_ record: LogRecord) -> Bool {
        guard record.category == "authd",
              let daemonPath = record.processImagePath else {
            return false
        }
        return authorizationDaemonPaths.contains(daemonPath)
    }

    private static func parseLocalAuthentication(
        _ record: LogRecord,
        receivedAt: Date
    ) -> AuthenticationLogRecord? {
        guard categoryContainsClient(record.category),
              categoryContainsInteractive(record.category),
              let message = record.eventMessage,
              let processID = validProcessID(record.processID),
              let executablePath = absolutePath(record.processImagePath),
              !brokerNames.contains(URL(fileURLWithPath: executablePath).lastPathComponent) else {
            return nil
        }

        if let operation = localAuthenticationRequestOperation(message) {
            guard !message.contains(
                "uiDelegate:<LACUIAuthenticationViewModel"
            ) else {
                return nil
            }
            let requestIdentifier = localAuthenticationRequestIdentifier(
                processID: processID,
                executablePath: executablePath,
                operation: operation,
                message: message
            )
            return .localAuthentication(
                AuthenticationClientEvent(
                    processID: processID,
                    executablePath: executablePath,
                    receivedAt: receivedAt,
                    source: .localAuthentication,
                    requestIdentifier: requestIdentifier
                )
            )
        }

        guard let operation = localAuthenticationCompletionOperation(message),
              let requestIdentifier = localAuthenticationRequestIdentifier(
                  processID: processID,
                  executablePath: executablePath,
                  operation: operation,
                  message: message
              ) else {
            return nil
        }
        return .localAuthenticationCompletion(requestIdentifier)
    }

    private static func localAuthenticationRequestOperation(
        _ message: String
    ) -> LocalAuthenticationOperation? {
        if message.hasPrefix("evaluatePolicy:") {
            return .evaluatePolicy
        }
        if message.hasPrefix("evaluateAccessControl:") {
            return .evaluateAccessControl
        }
        return nil
    }

    private static func localAuthenticationCompletionOperation(
        _ message: String
    ) -> LocalAuthenticationOperation? {
        if message.hasPrefix("evaluatePolicy on "),
           message.contains(" returned ") {
            return .evaluatePolicy
        }
        if message.hasPrefix("evaluateAccessControl on "),
           message.contains(" returned ") {
            return .evaluateAccessControl
        }
        return nil
    }

    private static func localAuthenticationRequestIdentifier(
        processID: pid_t,
        executablePath: String,
        operation: LocalAuthenticationOperation,
        message: String
    ) -> AuthenticationRequestIdentifier? {
        let contextMarker = " on LAContext["
        let contextRange: Range<String.Index>
        let completionPrefix = operation.rawValue + contextMarker
        if message.hasPrefix(completionPrefix) {
            let lowerBound = message.index(
                message.startIndex,
                offsetBy: operation.rawValue.count
            )
            contextRange = lowerBound..<message.index(
                lowerBound,
                offsetBy: contextMarker.count
            )
        } else if let finalContextRange = message.range(
            of: contextMarker,
            options: .backwards
        ) {
            contextRange = finalContextRange
        } else {
            return nil
        }

        guard let componentEnd = message[contextRange.upperBound...].firstIndex(
            where: { $0 == "]" || $0.isWhitespace }
        ) else {
            return nil
        }
        let rawContext = message[contextRange.upperBound..<componentEnd]
        let rawComponents = rawContext.split(
            separator: ":",
            omittingEmptySubsequences: false
        )
        guard rawComponents.count == 3,
              rawComponents.allSatisfy({ component in
                  !component.isEmpty && component.allSatisfy(\.isNumber)
              }) else {
            return nil
        }
        let contextComponents = rawComponents.compactMap { UInt64($0) }
        guard contextComponents.count == rawComponents.count else {
            return nil
        }

        let closingBracket: String.Index
        if message[componentEnd] == "]" {
            closingBracket = componentEnd
        } else if let bracket = message[componentEnd...].firstIndex(of: "]") {
            closingBracket = bracket
        } else {
            return nil
        }
        let afterContext = message.index(after: closingBracket)
        guard let clientMarker = message.range(
            of: " cid:",
            range: afterContext..<message.endIndex
        ) else {
            return nil
        }
        let rawClientID = message[clientMarker.upperBound...].prefix { $0.isNumber }
        let clientIDEnd = message.index(
            clientMarker.upperBound,
            offsetBy: rawClientID.count
        )
        guard !rawClientID.isEmpty,
              clientIDEnd == message.endIndex || message[clientIDEnd].isWhitespace,
              let clientID = UInt64(rawClientID) else {
            return nil
        }
        return .localAuthentication(
            LocalAuthenticationRequestKey(
                processID: processID,
                executablePath: executablePath,
                operation: operation,
                contextComponents: contextComponents,
                clientID: clientID
            )
        )
    }

    private static func isSignedDecimalInteger(_ value: Substring) -> Bool {
        let digits = value.first == "-" ? value.dropFirst() : value[...]
        return isUnsignedDecimalInteger(digits)
    }

    private static func isUnsignedDecimalInteger(_ value: Substring) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
    }

    private static func categoryContainsClient(_ category: String?) -> Bool {
        categoryContains("Client", in: category)
    }

    private static func categoryContainsInteractive(_ category: String?) -> Bool {
        categoryContains("Interactive", in: category)
    }

    private static func categoryContains(_ value: String, in category: String?) -> Bool {
        category?.split(separator: ",").contains {
            $0.trimmingCharacters(in: .whitespaces) == value
        } == true
    }

    private static func validProcessID(_ rawValue: Int?) -> pid_t? {
        guard let rawValue,
              let processID = pid_t(exactly: rawValue),
              processID > 1 else {
            return nil
        }
        return processID
    }

    private static func absolutePath(_ value: String?) -> String? {
        guard let value, value.hasPrefix("/") else {
            return nil
        }
        return value
    }
}

final class AuthenticationLogEventCorrelator: @unchecked Sendable {
    private static let maximumAuthorizationDelay: TimeInterval = 10
    private static let maximumActiveRequestCount = 128

    private struct PendingAuthorizationRequest {
        let event: AuthenticationClientEvent
    }

    private enum ActiveRequest {
        case localAuthentication(sequence: UInt64)
        case authorization(sequence: UInt64)

        var sequence: UInt64 {
            switch self {
            case let .localAuthentication(sequence),
                 let .authorization(sequence):
                return sequence
            }
        }
    }

    private let lock = NSLock()
    private var pendingAuthorizationRequests: [
        AuthenticationRequestIdentifier: PendingAuthorizationRequest
    ] = [:]
    private var activeRequests: [AuthenticationRequestIdentifier: ActiveRequest] = [:]
    private var nextActiveRequestSequence: UInt64 = 0

    func reset() {
        lock.lock()
        pendingAuthorizationRequests.removeAll()
        activeRequests.removeAll()
        nextActiveRequestSequence = 0
        lock.unlock()
    }

    func ingest(line: String, receivedAt: Date) -> AuthenticationClientEvent? {
        guard case let .began(event) = ingestLifecycle(
            line: line,
            receivedAt: receivedAt
        ) else {
            return nil
        }
        return AuthenticationClientEvent(
            processID: event.processID,
            executablePath: event.executablePath,
            receivedAt: event.receivedAt,
            source: event.source
        )
    }

    func ingestLifecycle(
        line: String,
        receivedAt: Date
    ) -> AuthenticationLifecycleEvent? {
        ingestLifecycles(line: line, receivedAt: receivedAt).first
    }

    func ingestLifecycles(
        line: String,
        receivedAt: Date
    ) -> [AuthenticationLifecycleEvent] {
        guard let record = AuthenticationLogEventParser.parseRecord(
            line: line,
            receivedAt: receivedAt
        ) else {
            return []
        }

        switch record {
        case let .localAuthentication(event):
            if let requestIdentifier = event.requestIdentifier {
                lock.lock()
                prunePendingAuthorizationRequests(now: receivedAt)
                rememberActiveRequest(
                    .localAuthentication(sequence: nextSequence()),
                    identifiedBy: requestIdentifier
                )
                lock.unlock()
            }
            return [.began(event)]
        case let .localAuthenticationCompletion(requestIdentifier):
            lock.lock()
            defer { lock.unlock() }
            prunePendingAuthorizationRequests(now: receivedAt)
            guard case .localAuthentication? = activeRequests.removeValue(
                forKey: requestIdentifier
            ) else {
                return []
            }
            return [.ended(requestIdentifier, receivedAt: receivedAt)]
        case let .authorizationEvaluation(requestIdentifier, event, _):
            lock.lock()
            defer { lock.unlock() }
            prunePendingAuthorizationRequests(now: receivedAt)
            pendingAuthorizationRequests[requestIdentifier] = PendingAuthorizationRequest(
                event: event
            )
            return []
        case let .authorizationMechanism(requestIdentifier):
            lock.lock()
            defer { lock.unlock() }
            prunePendingAuthorizationRequests(now: receivedAt)
            guard let pendingRequest = pendingAuthorizationRequests.removeValue(
                forKey: requestIdentifier
            ) else {
                return []
            }
            let sequence = nextSequence()
            rememberActiveRequest(
                .authorization(sequence: sequence),
                identifiedBy: requestIdentifier
            )
            return [.began(
                AuthenticationClientEvent(
                    processID: pendingRequest.event.processID,
                    executablePath: pendingRequest.event.executablePath,
                    receivedAt: receivedAt,
                    source: pendingRequest.event.source,
                    requestIdentifier: requestIdentifier
                )
            )]
        case let .authorizationCompletion(requestIdentifier):
            lock.lock()
            defer { lock.unlock() }
            prunePendingAuthorizationRequests(now: receivedAt)
            pendingAuthorizationRequests.removeValue(forKey: requestIdentifier)
            guard case .authorization? = activeRequests.removeValue(
                forKey: requestIdentifier
            ) else {
                return []
            }
            return [.ended(requestIdentifier, receivedAt: receivedAt)]
        }
    }

    private func prunePendingAuthorizationRequests(now: Date) {
        let pendingCutoff = now.addingTimeInterval(-Self.maximumAuthorizationDelay)
        pendingAuthorizationRequests = pendingAuthorizationRequests.filter {
            $0.value.event.receivedAt >= pendingCutoff
        }
    }

    private func nextSequence() -> UInt64 {
        nextActiveRequestSequence &+= 1
        return nextActiveRequestSequence
    }

    private func rememberActiveRequest(
        _ request: ActiveRequest,
        identifiedBy requestIdentifier: AuthenticationRequestIdentifier
    ) {
        activeRequests[requestIdentifier] = request
        guard activeRequests.count > Self.maximumActiveRequestCount,
              let oldestRequest = activeRequests.min(by: {
                  $0.value.sequence < $1.value.sequence
              }) else {
            return
        }
        activeRequests.removeValue(forKey: oldestRequest.key)
    }
}

private final class AuthenticationLogLineBuffer: @unchecked Sendable {
    private static let maximumBufferedBytes = 1_048_576

    private let lock = NSLock()
    private var storage = Data()

    func append(_ data: Data) -> [String] {
        lock.lock()
        defer { lock.unlock() }

        storage.append(data)
        if storage.count > Self.maximumBufferedBytes,
           !storage.contains(0x0A) {
            storage.removeAll(keepingCapacity: false)
            return []
        }

        var lines: [String] = []
        while let newlineIndex = storage.firstIndex(of: 0x0A) {
            let lineByteCount = storage.distance(from: storage.startIndex, to: newlineIndex)
            let lineData = lineByteCount <= Self.maximumBufferedBytes
                ? Data(storage[..<newlineIndex])
                : nil
            storage.removeSubrange(...newlineIndex)
            guard let lineData, !lineData.isEmpty else {
                continue
            }
            lines.append(String(decoding: lineData, as: UTF8.self))
        }
        if storage.count > Self.maximumBufferedBytes {
            storage.removeAll(keepingCapacity: false)
        }
        return lines
    }
}

final class AuthenticationLifecycleEventQueue: @unchecked Sendable {
    let stream: AsyncStream<AuthenticationLifecycleEvent>

    private let continuation: AsyncStream<AuthenticationLifecycleEvent>.Continuation

    init() {
        let pair = AsyncStream.makeStream(of: AuthenticationLifecycleEvent.self)
        stream = pair.stream
        continuation = pair.continuation
    }

    func yield(_ event: AuthenticationLifecycleEvent) {
        continuation.yield(event)
    }

    func finish() {
        continuation.finish()
    }
}

@MainActor
final class AuthenticationEventMonitor {
    private static let predicate = """
    (subsystem == "com.apple.LocalAuthentication" AND category CONTAINS "Client" AND category CONTAINS "Interactive" AND (eventMessage BEGINSWITH "evaluatePolicy:" OR eventMessage BEGINSWITH "evaluateAccessControl:" OR (eventMessage BEGINSWITH "evaluatePolicy on " AND eventMessage CONTAINS " returned ") OR (eventMessage BEGINSWITH "evaluateAccessControl on " AND eventMessage CONTAINS " returned "))) OR (subsystem == "com.apple.Authorization" AND category == "authd" AND process == "authd" AND ((eventMessage BEGINSWITH "Process " AND eventMessage CONTAINS ") evaluates ") OR (eventMessage BEGINSWITH "engine " AND (eventMessage CONTAINS ": running mechanism " OR eventMessage CONTAINS ": authorize result: "))))
    """

    private let eventHandler: (AuthenticationLifecycleEvent) -> Void
    private let eventCorrelator = AuthenticationLogEventCorrelator()
    private var task: Process?
    private var outputHandle: FileHandle?
    private var eventQueue: AuthenticationLifecycleEventQueue?
    private var eventDeliveryTask: Task<Void, Never>?
    private var generation = 0

    init(eventHandler: @escaping (AuthenticationLifecycleEvent) -> Void) {
        self.eventHandler = eventHandler
    }

    func start() {
        guard task == nil else {
            return
        }

        generation += 1
        let currentGeneration = generation
        let process = Process()
        let output = Pipe()
        let handle = output.fileHandleForReading
        let lineBuffer = AuthenticationLogLineBuffer()
        let eventQueue = AuthenticationLifecycleEventQueue()

        process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        process.arguments = [
            "stream",
            "--style", "ndjson",
            "--level", "debug",
            "--predicate", Self.predicate
        ]
        process.environment = ["LC_ALL": "C"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice

        handle.readabilityHandler = { readableHandle in
            let data = readableHandle.availableData
            guard !data.isEmpty else {
                readableHandle.readabilityHandler = nil
                return
            }
            for line in lineBuffer.append(data) {
                let events = self.eventCorrelator.ingestLifecycles(
                    line: line,
                    receivedAt: Date()
                )
                for event in events {
                    eventQueue.yield(event)
                }
            }
        }
        process.terminationHandler = { _ in
            handle.readabilityHandler = nil
            eventQueue.yield(.reset)
            eventQueue.finish()
        }

        task = process
        outputHandle = handle
        self.eventQueue = eventQueue
        eventDeliveryTask = Task { @MainActor [weak self] in
            for await event in eventQueue.stream {
                guard !Task.isCancelled else {
                    return
                }
                self?.deliver(event, generation: currentGeneration)
            }
            self?.didTerminate(generation: currentGeneration)
        }
        do {
            try process.run()
        } catch {
            handle.readabilityHandler = nil
            process.terminationHandler = nil
            eventQueue.finish()
            eventDeliveryTask?.cancel()
            eventDeliveryTask = nil
            self.eventQueue = nil
            task = nil
            outputHandle = nil
        }
    }

    func stop() {
        let process = task
        generation += 1
        eventCorrelator.reset()
        outputHandle?.readabilityHandler = nil
        outputHandle = nil
        task?.terminationHandler = nil
        self.task = nil
        eventQueue?.finish()
        eventQueue = nil
        eventDeliveryTask?.cancel()
        eventDeliveryTask = nil

        guard let process else {
            return
        }
        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
    }

    private func deliver(_ event: AuthenticationLifecycleEvent, generation: Int) {
        guard generation == self.generation, task != nil else {
            return
        }
        eventHandler(event)
    }

    private func didTerminate(generation: Int) {
        guard generation == self.generation else {
            return
        }
        outputHandle?.readabilityHandler = nil
        outputHandle = nil
        task?.terminationHandler = nil
        task = nil
        eventQueue = nil
        eventDeliveryTask = nil
    }
}

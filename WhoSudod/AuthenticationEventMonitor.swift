import Darwin
import Foundation

enum AuthenticationEventSource: Equatable, Sendable {
    case localAuthentication
    case authorization
}

struct AuthenticationClientEvent: Equatable, Sendable {
    let processID: pid_t
    let executablePath: String?
    let receivedAt: Date
    let source: AuthenticationEventSource
}

enum AuthenticationLogRecord: Equatable, Sendable {
    case localAuthentication(AuthenticationClientEvent)
    case authorizationEvaluation(engineID: UInt64, event: AuthenticationClientEvent)
    case authorizationMechanism(engineID: UInt64)
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
    private static let localAuthenticationRequestPrefixes = [
        "evaluatePolicy:",
        "evaluateAccessControl:"
    ]
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
             let .authorizationEvaluation(_, event):
            return event
        case .authorizationMechanism, nil:
            return nil
        }
    }

    static func parseRecord(line: String, receivedAt: Date) -> AuthenticationLogRecord? {
        guard let data = line.data(using: .utf8),
              let record = try? JSONDecoder().decode(LogRecord.self, from: data) else {
            return nil
        }

        if record.subsystem == localAuthenticationSubsystem {
            return parseLocalAuthentication(record, receivedAt: receivedAt).map {
                .localAuthentication($0)
            }
        }
        if record.subsystem == authorizationSubsystem {
            return parseAuthorizationEvaluation(record, receivedAt: receivedAt)
                ?? parseAuthorizationMechanism(record)
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
              let engineID = UInt64(rawEngineID) else {
            return nil
        }

        return .authorizationEvaluation(
            engineID: engineID,
            event: AuthenticationClientEvent(
                processID: processID,
                executablePath: executablePath,
                receivedAt: receivedAt,
                source: .authorization
            )
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
              interactiveAuthorizationMechanisms.contains(baseMechanism) else {
            return nil
        }
        return .authorizationMechanism(engineID: engineID)
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
    ) -> AuthenticationClientEvent? {
        guard categoryContainsClient(record.category),
              categoryContainsInteractive(record.category),
              let message = record.eventMessage,
              localAuthenticationRequestPrefixes.contains(where: message.hasPrefix),
              !message.contains("uiDelegate:<LACUIAuthenticationViewModel"),
              let processID = validProcessID(record.processID),
              let executablePath = absolutePath(record.processImagePath),
              !brokerNames.contains(URL(fileURLWithPath: executablePath).lastPathComponent) else {
            return nil
        }

        return AuthenticationClientEvent(
            processID: processID,
            executablePath: executablePath,
            receivedAt: receivedAt,
            source: .localAuthentication
        )
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

    private let lock = NSLock()
    private var pendingAuthorizationEvents: [UInt64: AuthenticationClientEvent] = [:]

    func ingest(line: String, receivedAt: Date) -> AuthenticationClientEvent? {
        guard let record = AuthenticationLogEventParser.parseRecord(
            line: line,
            receivedAt: receivedAt
        ) else {
            return nil
        }

        switch record {
        case let .localAuthentication(event):
            return event
        case let .authorizationEvaluation(engineID, event):
            lock.lock()
            defer { lock.unlock() }
            pruneAuthorizationEvents(now: receivedAt)
            pendingAuthorizationEvents[engineID] = event
            return nil
        case let .authorizationMechanism(engineID):
            lock.lock()
            defer { lock.unlock() }
            pruneAuthorizationEvents(now: receivedAt)
            guard let event = pendingAuthorizationEvents.removeValue(forKey: engineID) else {
                return nil
            }
            return AuthenticationClientEvent(
                processID: event.processID,
                executablePath: event.executablePath,
                receivedAt: receivedAt,
                source: event.source
            )
        }
    }

    private func pruneAuthorizationEvents(now: Date) {
        let cutoff = now.addingTimeInterval(-Self.maximumAuthorizationDelay)
        pendingAuthorizationEvents = pendingAuthorizationEvents.filter {
            $0.value.receivedAt >= cutoff
        }
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

@MainActor
final class AuthenticationEventMonitor {
    private static let predicate = """
    (subsystem == "com.apple.LocalAuthentication" AND category CONTAINS "Client" AND category CONTAINS "Interactive" AND (eventMessage BEGINSWITH "evaluatePolicy:" OR eventMessage BEGINSWITH "evaluateAccessControl:")) OR (subsystem == "com.apple.Authorization" AND category == "authd" AND process == "authd" AND ((eventMessage BEGINSWITH "Process " AND eventMessage CONTAINS ") evaluates ") OR (eventMessage BEGINSWITH "engine " AND eventMessage CONTAINS ": running mechanism ")))
    """

    private let eventHandler: (AuthenticationClientEvent) -> Void
    private var task: Process?
    private var outputHandle: FileHandle?
    private var generation = 0

    init(eventHandler: @escaping (AuthenticationClientEvent) -> Void) {
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
        let eventCorrelator = AuthenticationLogEventCorrelator()

        process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        process.arguments = [
            "stream",
            "--style", "ndjson",
            "--level", "info",
            "--predicate", Self.predicate
        ]
        process.environment = ["LC_ALL": "C"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice

        handle.readabilityHandler = { [weak self] readableHandle in
            let data = readableHandle.availableData
            guard !data.isEmpty else {
                readableHandle.readabilityHandler = nil
                return
            }
            for line in lineBuffer.append(data) {
                guard let event = eventCorrelator.ingest(
                    line: line,
                    receivedAt: Date()
                ) else {
                    continue
                }
                Task { @MainActor [weak self] in
                    self?.deliver(event, generation: currentGeneration)
                }
            }
        }
        process.terminationHandler = { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.didTerminate(generation: currentGeneration)
            }
        }

        task = process
        outputHandle = handle
        do {
            try process.run()
        } catch {
            handle.readabilityHandler = nil
            process.terminationHandler = nil
            task = nil
            outputHandle = nil
        }
    }

    func stop() {
        guard let task else {
            return
        }

        generation += 1
        outputHandle?.readabilityHandler = nil
        outputHandle = nil
        task.terminationHandler = nil
        self.task = nil

        if task.isRunning {
            task.terminate()
            task.waitUntilExit()
        }
    }

    private func deliver(_ event: AuthenticationClientEvent, generation: Int) {
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
        task = nil
    }
}

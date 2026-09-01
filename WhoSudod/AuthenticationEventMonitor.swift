import Darwin
import Foundation

enum AuthenticationEventSource: Equatable, Sendable {
    case localAuthentication
    case authorizationShell
}

struct AuthenticationClientEvent: Equatable, Sendable {
    let processID: pid_t
    let executablePath: String?
    let receivedAt: Date
    let source: AuthenticationEventSource
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
    private static let brokerNames: Set<String> = [
        "coreauthd",
        "coreautha",
        "SecurityAgent",
        "authorizationhost",
        "LocalAuthenticationRemoteService"
    ]

    static func parse(line: String, receivedAt: Date) -> AuthenticationClientEvent? {
        guard let data = line.data(using: .utf8),
              let record = try? JSONDecoder().decode(LogRecord.self, from: data) else {
            return nil
        }

        if record.subsystem == localAuthenticationSubsystem {
            return parseLocalAuthentication(record, receivedAt: receivedAt)
        }
        if record.subsystem == authorizationSubsystem {
            return parseAuthorizationShell(record, receivedAt: receivedAt)
        }
        return nil
    }

    private static func parseLocalAuthentication(
        _ record: LogRecord,
        receivedAt: Date
    ) -> AuthenticationClientEvent? {
        guard categoryContainsClient(record.category),
              record.eventMessage?.hasPrefix("evaluatePolicy:") == true,
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

    private static func parseAuthorizationShell(
        _ record: LogRecord,
        receivedAt: Date
    ) -> AuthenticationClientEvent? {
        guard let loggerPath = absolutePath(record.processImagePath),
              URL(fileURLWithPath: loggerPath).lastPathComponent == "authd",
              let message = record.eventMessage else {
            return nil
        }

        let prefix = "process: PID "
        let suffix = " is shell"
        guard message.hasPrefix(prefix), message.hasSuffix(suffix) else {
            return nil
        }
        let start = message.index(message.startIndex, offsetBy: prefix.count)
        let end = message.index(message.endIndex, offsetBy: -suffix.count)
        guard start < end,
              let rawProcessID = Int(message[start..<end]),
              let processID = validProcessID(rawProcessID) else {
            return nil
        }

        return AuthenticationClientEvent(
            processID: processID,
            executablePath: nil,
            receivedAt: receivedAt,
            source: .authorizationShell
        )
    }

    private static func categoryContainsClient(_ category: String?) -> Bool {
        category?
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .contains("Client") == true
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
    (subsystem == "com.apple.LocalAuthentication" AND category CONTAINS "Client" AND eventMessage BEGINSWITH "evaluatePolicy:") OR (subsystem == "com.apple.Authorization" AND process == "authd" AND eventMessage BEGINSWITH "process: PID " AND eventMessage ENDSWITH " is shell")
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

        process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        process.arguments = [
            "stream",
            "--style", "ndjson",
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
                guard let event = AuthenticationLogEventParser.parse(
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

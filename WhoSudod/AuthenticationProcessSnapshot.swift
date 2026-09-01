import Darwin
import Foundation

enum SudoInvocationParser {
    private static let longOptionsWithArguments: Set<String> = [
        "--chdir",
        "--chroot",
        "--close-from",
        "--command-timeout",
        "--group",
        "--host",
        "--other-user",
        "--prompt",
        "--user"
    ]
    private static let nonExecutingLongOptions: Set<String> = [
        "--edit",
        "--help",
        "--list",
        "--remove-timestamp",
        "--validate",
        "--version"
    ]
    private static let shellModeLongOptions: Set<String> = [
        "--login",
        "--shell"
    ]
    private static let shortOptionsWithArguments: Set<Character> = [
        "C", "D", "g", "h", "p", "R", "T", "U", "u"
    ]
    private static let nonExecutingShortOptions: Set<Character> = [
        "e", "K", "l", "V", "v"
    ]
    private static let shellModeShortOptions: Set<Character> = ["i", "s"]

    static func command(from processArguments: [String]) -> RequestedCommand? {
        guard let invocation = processArguments.first,
              URL(fileURLWithPath: invocation).lastPathComponent != "sudoedit" else {
            return nil
        }

        var index = 1
        while index < processArguments.count {
            let token = processArguments[index]
            if token == "--" {
                index += 1
                break
            }
            if isEnvironmentAssignment(token) {
                index += 1
                continue
            }
            guard token.hasPrefix("-"), token != "-" else {
                break
            }

            if token.hasPrefix("--") {
                let option = String(token.prefix { $0 != "=" })
                if nonExecutingLongOptions.contains(option) {
                    return nil
                }
                if shellModeLongOptions.contains(option) {
                    return nil
                }
                if longOptionsWithArguments.contains(option), !token.contains("=") {
                    guard processArguments.indices.contains(index + 1) else {
                        return nil
                    }
                    index += 2
                } else {
                    index += 1
                }
                continue
            }

            let flags = Array(token.dropFirst())
            var consumesNextArgument = false
            for (flagIndex, flag) in flags.enumerated() {
                if nonExecutingShortOptions.contains(flag) {
                    return nil
                }
                if shellModeShortOptions.contains(flag) {
                    return nil
                }
                guard shortOptionsWithArguments.contains(flag) else {
                    continue
                }

                let hasAttachedArgument = flagIndex < flags.index(before: flags.endIndex)
                consumesNextArgument = !hasAttachedArgument
                break
            }
            if consumesNextArgument {
                guard processArguments.indices.contains(index + 1) else {
                    return nil
                }
                index += 2
            } else {
                index += 1
            }
        }

        while index < processArguments.count,
              isEnvironmentAssignment(processArguments[index]) {
            index += 1
        }
        guard index < processArguments.count,
              !processArguments[index].isEmpty else {
            return nil
        }
        return RequestedCommand(
            executable: processArguments[index],
            arguments: Array(processArguments.dropFirst(index + 1))
        )
    }

    private static func isEnvironmentAssignment(_ token: String) -> Bool {
        guard let equals = token.firstIndex(of: "="), equals != token.startIndex else {
            return false
        }
        let name = token[..<equals]
        guard let first = name.first,
              first == "_" || first.isLetter else {
            return false
        }
        return name.dropFirst().allSatisfy { $0 == "_" || $0.isLetter || $0.isNumber }
    }
}

struct RequestedCommand: Hashable, Sendable {
    let executable: String
    let arguments: [String]

    var displayText: String {
        ([executable] + arguments)
            .map(Self.displayArgument)
            .joined(separator: " ")
    }

    private static func displayArgument(_ argument: String) -> String {
        let unquotedCharacters = CharacterSet.alphanumerics.union(
            CharacterSet(charactersIn: "_@%+=:,./-")
        )
        if !argument.isEmpty,
           argument.unicodeScalars.allSatisfy(unquotedCharacters.contains) {
            return argument
        }
        return "'\(argument.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
}

struct ProcessStartTime: Hashable, Comparable, Sendable {
    let seconds: UInt64
    let microseconds: UInt64

    static func < (lhs: ProcessStartTime, rhs: ProcessStartTime) -> Bool {
        if lhs.seconds != rhs.seconds {
            return lhs.seconds < rhs.seconds
        }
        return lhs.microseconds < rhs.microseconds
    }

    var date: Date {
        Date(
            timeIntervalSince1970: TimeInterval(seconds)
                + TimeInterval(microseconds) / 1_000_000
        )
    }
}

struct ProcessIdentity: Hashable, Sendable {
    let pid: pid_t
    let startTime: ProcessStartTime
}

struct ProcessRecord: Hashable, Sendable {
    let pid: pid_t
    let parentPID: pid_t
    let realUserID: uid_t
    let name: String
    let executablePath: String?
    let startTime: ProcessStartTime
    let processArguments: [String]?

    init(
        pid: pid_t,
        parentPID: pid_t,
        realUserID: uid_t,
        name: String,
        executablePath: String?,
        startTime: ProcessStartTime,
        processArguments: [String]? = nil
    ) {
        self.pid = pid
        self.parentPID = parentPID
        self.realUserID = realUserID
        self.name = name
        self.executablePath = executablePath
        self.startTime = startTime
        self.processArguments = processArguments
    }

    var requestedCommand: RequestedCommand? {
        guard executablePath == "/usr/bin/sudo",
              let processArguments else {
            return nil
        }
        return SudoInvocationParser.command(from: processArguments)
    }

    var identity: ProcessIdentity {
        ProcessIdentity(pid: pid, startTime: startTime)
    }
}

enum AuthenticationRequestKind: Equatable, Sendable {
    case sudo
    case localAuthentication
    case authorization
}

enum AuthenticationAttribution: Equatable, Sendable {
    case localAuthenticationLog
    case authorizationLog
    case heuristicSudo

    var isLogAttributed: Bool {
        self != .heuristicSudo
    }
}

struct AuthenticationRequestAnchor: Equatable, Sendable {
    let identity: ProcessIdentity
    let requestKind: AuthenticationRequestKind
    let attribution: AuthenticationAttribution
}

struct ProcessDescendant: Equatable, Sendable {
    let process: ProcessRecord
    let depthFromRequester: Int
}

struct ProcessChain: Equatable, Sendable {
    let processes: [ProcessRecord]
    let descendants: [ProcessDescendant]
    let isComplete: Bool
    let requestKind: AuthenticationRequestKind
    let attribution: AuthenticationAttribution

    var requesterProcess: ProcessRecord {
        processes[processes.count - 1]
    }

    var anchor: AuthenticationRequestAnchor {
        AuthenticationRequestAnchor(
            identity: requesterProcess.identity,
            requestKind: requestKind,
            attribution: attribution
        )
    }

    var processCount: Int {
        processes.count + descendants.count
    }
}

enum ProcessInspectionState: Equatable, Sendable {
    case complete
    case partial
    case unavailable
    case pending
    case requesterExited
}

struct AuthenticationProcessSnapshot: Equatable, Sendable {
    let candidates: [ProcessChain]
    let inspectionState: ProcessInspectionState

    init(
        candidates: [ProcessChain],
        inspectionState: ProcessInspectionState = .complete
    ) {
        self.candidates = candidates
        self.inspectionState = inspectionState
    }

    static let empty = AuthenticationProcessSnapshot(candidates: [])
    static let pending = AuthenticationProcessSnapshot(candidates: [], inspectionState: .pending)
    static let unavailable = AuthenticationProcessSnapshot(candidates: [], inspectionState: .unavailable)

    var processCount: Int {
        candidates.reduce(0) { $0 + $1.processCount }
    }
}

enum ProcessSnapshotSelection {
    static func refreshingLive(
        current: AuthenticationProcessSnapshot,
        observed: AuthenticationProcessSnapshot
    ) -> AuthenticationProcessSnapshot {
        if observed.inspectionState == .unavailable, !current.candidates.isEmpty {
            return AuthenticationProcessSnapshot(
                candidates: current.candidates,
                inspectionState: .unavailable
            )
        }
        guard !observed.candidates.isEmpty else {
            if let pinned = current.candidates.first, pinned.attribution.isLogAttributed {
                return AuthenticationProcessSnapshot(
                    candidates: [pinned],
                    inspectionState: .requesterExited
                )
            }
            return AuthenticationProcessSnapshot(
                candidates: [],
                inspectionState: observed.inspectionState
            )
        }

        let observedByIdentity = Dictionary(
            uniqueKeysWithValues: observed.candidates.map { chain in
                (chain.requesterProcess.identity, chain)
            }
        )
        let pinnedChain = current.candidates.first.flatMap { chain in
            observedByIdentity[chain.requesterProcess.identity]
        }
        let observedChain = pinnedChain ?? observed.candidates[0]
        return AuthenticationProcessSnapshot(
            candidates: [observedChain],
            inspectionState: observed.inspectionState
        )
    }
}

enum ProcessTreeBuilder {
    static func build(
        records: [ProcessRecord],
        requesterIdentities: [ProcessIdentity],
        requestKind: AuthenticationRequestKind,
        attribution: AuthenticationAttribution,
        maximumDepth: Int = 64
    ) -> AuthenticationProcessSnapshot {
        let recordsByPID = Dictionary(records.map { ($0.pid, $0) }, uniquingKeysWith: newerRecord)
        let requesterRecords = requesterIdentities.compactMap { identity -> ProcessRecord? in
            guard let record = recordsByPID[identity.pid], record.identity == identity else {
                return nil
            }
            return record
        }
        .sorted { lhs, rhs in
            if lhs.startTime != rhs.startTime {
                return lhs.startTime > rhs.startTime
            }
            return lhs.pid > rhs.pid
        }

        let candidates = requesterRecords.map { requester in
            makeChain(
                from: requester,
                recordsByPID: recordsByPID,
                requestKind: requestKind,
                attribution: attribution,
                maximumDepth: maximumDepth
            )
        }
        return AuthenticationProcessSnapshot(candidates: candidates)
    }

    private static func newerRecord(_ lhs: ProcessRecord, _ rhs: ProcessRecord) -> ProcessRecord {
        lhs.startTime >= rhs.startTime ? lhs : rhs
    }

    private static func makeChain(
        from requester: ProcessRecord,
        recordsByPID: [pid_t: ProcessRecord],
        requestKind: AuthenticationRequestKind,
        attribution: AuthenticationAttribution,
        maximumDepth: Int
    ) -> ProcessChain {
        var chain = [requester]
        var visited = Set([requester.pid])
        var current = requester
        var isComplete = current.parentPID == 0

        while !isComplete && chain.count < maximumDepth {
            guard let parent = recordsByPID[current.parentPID] else {
                break
            }
            guard !visited.contains(parent.pid), parent.startTime <= current.startTime else {
                break
            }

            chain.append(parent)
            visited.insert(parent.pid)
            current = parent
            isComplete = current.pid == 1 || current.parentPID == 0
        }

        return ProcessChain(
            processes: chain.reversed(),
            descendants: makeDescendants(
                from: requester,
                recordsByPID: recordsByPID,
                maximumDepth: maximumDepth
            ),
            isComplete: isComplete,
            requestKind: requestKind,
            attribution: attribution
        )
    }

    private static func makeDescendants(
        from requester: ProcessRecord,
        recordsByPID: [pid_t: ProcessRecord],
        maximumDepth: Int
    ) -> [ProcessDescendant] {
        let childrenByParent = Dictionary(
            grouping: recordsByPID.values.filter { $0.pid != requester.pid },
            by: \.parentPID
        )
        var descendants: [ProcessDescendant] = []
        var visited = Set([requester.pid])

        func appendChildren(of parent: ProcessRecord, depth: Int) {
            guard depth <= maximumDepth else {
                return
            }
            let children = (childrenByParent[parent.pid] ?? []).sorted { lhs, rhs in
                if lhs.startTime != rhs.startTime {
                    return lhs.startTime < rhs.startTime
                }
                return lhs.pid < rhs.pid
            }
            for child in children {
                guard child.startTime >= parent.startTime,
                      visited.insert(child.pid).inserted else {
                    continue
                }
                descendants.append(
                    ProcessDescendant(process: child, depthFromRequester: depth)
                )
                appendChildren(of: child, depth: depth + 1)
            }
        }

        appendChildren(of: requester, depth: 1)
        return descendants
    }
}

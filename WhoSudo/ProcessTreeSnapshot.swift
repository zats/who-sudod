import Darwin
import Foundation

struct ProcessStartTime: Hashable, Comparable, Sendable {
    let seconds: UInt64
    let microseconds: UInt64

    static func < (lhs: ProcessStartTime, rhs: ProcessStartTime) -> Bool {
        if lhs.seconds != rhs.seconds {
            return lhs.seconds < rhs.seconds
        }
        return lhs.microseconds < rhs.microseconds
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
    let commandLine: String?

    init(
        pid: pid_t,
        parentPID: pid_t,
        realUserID: uid_t,
        name: String,
        executablePath: String?,
        startTime: ProcessStartTime,
        commandLine: String? = nil
    ) {
        self.pid = pid
        self.parentPID = parentPID
        self.realUserID = realUserID
        self.name = name
        self.executablePath = executablePath
        self.startTime = startTime
        self.commandLine = commandLine
    }

    var requestedCommand: String? {
        guard executablePath == "/usr/bin/sudo",
              var text = commandLine?.trimmingCharacters(in: .whitespacesAndNewlines),
              !text.isEmpty else {
            return nil
        }
        for prefix in ["/usr/bin/sudo ", "sudo "] where text.hasPrefix(prefix) {
            text.removeFirst(prefix.count)
            break
        }
        return text.isEmpty ? nil : text
    }

    var identity: ProcessIdentity {
        ProcessIdentity(pid: pid, startTime: startTime)
    }
}

struct ProcessDescendant: Equatable, Sendable {
    let process: ProcessRecord
    let depthFromSudo: Int
}

struct ProcessChain: Equatable, Sendable {
    let processes: [ProcessRecord]
    let descendants: [ProcessDescendant]
    let isComplete: Bool

    var sudoProcess: ProcessRecord {
        processes[processes.count - 1]
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
}

struct SudoProcessSnapshot: Equatable, Sendable {
    let candidates: [ProcessChain]
    let inspectionState: ProcessInspectionState

    init(
        candidates: [ProcessChain],
        inspectionState: ProcessInspectionState = .complete
    ) {
        self.candidates = candidates
        self.inspectionState = inspectionState
    }

    static let empty = SudoProcessSnapshot(candidates: [])
    static let pending = SudoProcessSnapshot(candidates: [], inspectionState: .pending)
    static let unavailable = SudoProcessSnapshot(candidates: [], inspectionState: .unavailable)

    var processCount: Int {
        candidates.reduce(0) { $0 + $1.processCount }
    }
}

enum ProcessSnapshotSelection {
    static func refreshingLive(
        current: SudoProcessSnapshot,
        observed: SudoProcessSnapshot
    ) -> SudoProcessSnapshot {
        if observed.inspectionState == .unavailable, !current.candidates.isEmpty {
            return SudoProcessSnapshot(
                candidates: current.candidates,
                inspectionState: .unavailable
            )
        }
        guard !observed.candidates.isEmpty else {
            return SudoProcessSnapshot(
                candidates: [],
                inspectionState: observed.inspectionState
            )
        }

        let observedByIdentity = Dictionary(
            uniqueKeysWithValues: observed.candidates.map { chain in
                return (chain.sudoProcess.identity, chain)
            }
        )
        let pinnedChain = current.candidates.first.flatMap { chain -> ProcessChain? in
            observedByIdentity[chain.sudoProcess.identity]
        }
        let observedChain = pinnedChain ?? observed.candidates[0]
        return SudoProcessSnapshot(
            candidates: [observedChain],
            inspectionState: observed.inspectionState
        )
    }
}

enum ProcessTreeBuilder {
    static func build(
        records: [ProcessRecord],
        realUserID: uid_t,
        sudoPath: String = "/usr/bin/sudo",
        maximumDepth: Int = 64
    ) -> SudoProcessSnapshot {
        let recordsByPID = Dictionary(records.map { ($0.pid, $0) }, uniquingKeysWith: newerRecord)
        let sudoRecords = records
            .filter {
                $0.realUserID == realUserID
                    && $0.executablePath == sudoPath
            }
            .sorted { lhs, rhs in
                if lhs.startTime != rhs.startTime {
                    return lhs.startTime > rhs.startTime
                }
                return lhs.pid > rhs.pid
            }

        let candidates = sudoRecords.map { sudoRecord in
            makeChain(from: sudoRecord, recordsByPID: recordsByPID, maximumDepth: maximumDepth)
        }
        return SudoProcessSnapshot(candidates: candidates)
    }

    private static func newerRecord(_ lhs: ProcessRecord, _ rhs: ProcessRecord) -> ProcessRecord {
        lhs.startTime >= rhs.startTime ? lhs : rhs
    }

    private static func makeChain(
        from sudoRecord: ProcessRecord,
        recordsByPID: [pid_t: ProcessRecord],
        maximumDepth: Int
    ) -> ProcessChain {
        var chain = [sudoRecord]
        var visited = Set([sudoRecord.pid])
        var current = sudoRecord
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
                from: sudoRecord,
                recordsByPID: recordsByPID,
                maximumDepth: maximumDepth
            ),
            isComplete: isComplete
        )
    }

    private static func makeDescendants(
        from sudoRecord: ProcessRecord,
        recordsByPID: [pid_t: ProcessRecord],
        maximumDepth: Int
    ) -> [ProcessDescendant] {
        let childrenByParent = Dictionary(
            grouping: recordsByPID.values.filter { $0.pid != sudoRecord.pid },
            by: \.parentPID
        )
        var descendants: [ProcessDescendant] = []
        var visited = Set([sudoRecord.pid])

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
                    ProcessDescendant(process: child, depthFromSudo: depth)
                )
                appendChildren(of: child, depth: depth + 1)
            }
        }

        appendChildren(of: sudoRecord, depth: 1)
        return descendants
    }
}

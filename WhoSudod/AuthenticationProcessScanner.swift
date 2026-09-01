import Darwin
import Foundation

enum DisplayTextSanitizer {
    static func sanitize(_ value: String) -> String {
        var result = ""
        for scalar in value.unicodeScalars {
            let isBidirectionalControl: Bool
            switch scalar.value {
            case 0x061C, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069:
                isBidirectionalControl = true
            default:
                isBidirectionalControl = false
            }
            if CharacterSet.controlCharacters.contains(scalar) || isBidirectionalControl {
                result.append("�")
            } else {
                result.unicodeScalars.append(scalar)
            }
        }
        return result
    }
}

actor AuthenticationProcessScanner {
    private final class OutputAccumulator: @unchecked Sendable {
        private let lock = NSLock()
        private let maximumBytes: Int
        private var storage = Data()
        private(set) var exceededLimit = false

        init(maximumBytes: Int) {
            self.maximumBytes = maximumBytes
        }

        func append(_ data: Data) {
            lock.lock()
            defer { lock.unlock() }
            guard !exceededLimit else {
                return
            }
            guard storage.count + data.count <= maximumBytes else {
                exceededLimit = true
                storage.removeAll(keepingCapacity: false)
                return
            }
            storage.append(data)
        }

        func snapshot() -> (data: Data, exceededLimit: Bool) {
            lock.lock()
            defer { lock.unlock() }
            return (storage, exceededLimit)
        }
    }

    private struct KernelProcess {
        let pid: pid_t
        let parentPID: pid_t
        let realUserID: uid_t
        let name: String
        let startTime: ProcessStartTime
    }

    private struct Requester {
        let process: KernelProcess
        let requestKind: AuthenticationRequestKind
        let attribution: AuthenticationAttribution
    }

    private var commandLines: [ProcessIdentity: String] = [:]
    private var commandLineAttempts: [ProcessIdentity: Int] = [:]

    func snapshot(
        realUserID: uid_t = getuid(),
        preferredAnchor: AuthenticationRequestAnchor? = nil,
        evidence: [AuthenticationClientEvent] = [],
        allowSudoFallback: Bool
    ) async -> AuthenticationProcessSnapshot {
        let catalog: [pid_t: KernelProcess]
        do {
            catalog = try captureKernelProcesses()
        } catch {
            return .unavailable
        }

        pruneCommandLineCache(using: catalog)

        if let preferredAnchor,
           let process = verifiedProcess(
               identity: preferredAnchor.identity,
               realUserID: realUserID,
               in: catalog
           ) {
            return await snapshot(
                for: [
                    Requester(
                        process: process,
                        requestKind: preferredAnchor.requestKind,
                        attribution: preferredAnchor.attribution
                    )
                ],
                in: catalog
            )
        }
        if let preferredAnchor, preferredAnchor.attribution.isLogAttributed {
            return .empty
        }

        for event in evidence {
            guard let process = verifiedProcess(
                for: event,
                realUserID: realUserID,
                in: catalog
            ) else {
                continue
            }
            let requestKind: AuthenticationRequestKind = event.source == .localAuthentication
                ? .localAuthentication
                : .authorization
            let attribution: AuthenticationAttribution = event.source == .localAuthentication
                ? .localAuthenticationLog
                : .authorizationLog
            return await snapshot(
                for: [
                    Requester(
                        process: process,
                        requestKind: process.name == "sudo" ? .sudo : requestKind,
                        attribution: attribution
                    )
                ],
                in: catalog
            )
        }

        guard allowSudoFallback else {
            return .empty
        }

        let sudoProcesses = catalog.values
            .filter { process in
                process.realUserID == realUserID && process.name == "sudo"
            }
            .sorted(by: newestFirst)
            .filter { process in
                guard isSameProcessImage(process), executablePath(for: process.pid) == "/usr/bin/sudo" else {
                    return false
                }
                return true
            }
        return await snapshot(
            for: sudoProcesses.map { process in
                Requester(
                    process: process,
                    requestKind: .sudo,
                    attribution: .heuristicSudo
                )
            },
            in: catalog
        )
    }

    private func snapshot(
        for requesters: [Requester],
        in catalog: [pid_t: KernelProcess]
    ) async -> AuthenticationProcessSnapshot {
        guard !requesters.isEmpty else {
            return .empty
        }

        var relevantProcesses: [pid_t: ProcessRecord] = [:]
        var verifiedRequesters: [Requester] = []
        var inspectionWasIncomplete = false
        for (index, requester) in requesters.enumerated() {
            let process = requester.process
            guard isSameProcessImage(process) else {
                continue
            }
            guard let path = executablePath(for: process.pid) else {
                inspectionWasIncomplete = true
                continue
            }
            let commandLine = path == "/usr/bin/sudo" && index == 0
                ? await commandLine(for: process)
                : nil
            let requesterRecord = record(
                for: process,
                executablePath: path,
                commandLine: commandLine
            )
            relevantProcesses[requesterRecord.pid] = requesterRecord
            verifiedRequesters.append(requester)

            for ancestor in ancestry(from: process, in: catalog).dropFirst() {
                relevantProcesses[ancestor.pid] = resolvedRecord(for: ancestor)
                    ?? unresolvedRecord(for: ancestor)
            }
            for descendant in descendants(from: process, in: catalog) {
                relevantProcesses[descendant.pid] = resolvedRecord(for: descendant)
                    ?? unresolvedRecord(for: descendant)
            }
        }

        guard let first = verifiedRequesters.first else {
            return AuthenticationProcessSnapshot(
                candidates: [],
                inspectionState: inspectionWasIncomplete ? .partial : .complete
            )
        }
        let snapshot = ProcessTreeBuilder.build(
            records: Array(relevantProcesses.values),
            requesterIdentities: verifiedRequesters.map { identity(for: $0.process) },
            requestKind: first.requestKind,
            attribution: first.attribution
        )
        return AuthenticationProcessSnapshot(
            candidates: snapshot.candidates,
            inspectionState: inspectionWasIncomplete ? .partial : .complete
        )
    }

    private func verifiedProcess(
        identity: ProcessIdentity,
        realUserID: uid_t,
        in catalog: [pid_t: KernelProcess]
    ) -> KernelProcess? {
        guard let process = catalog[identity.pid],
              process.realUserID == realUserID,
              self.identity(for: process) == identity,
              isSameProcessImage(process) else {
            return nil
        }
        return process
    }

    private func verifiedProcess(
        for evidence: AuthenticationClientEvent,
        realUserID: uid_t,
        in catalog: [pid_t: KernelProcess]
    ) -> KernelProcess? {
        guard let process = catalog[evidence.processID],
              process.realUserID == realUserID,
              process.startTime.date <= evidence.receivedAt.addingTimeInterval(1),
              isSameProcessImage(process),
              let livePath = executablePath(for: process.pid) else {
            return nil
        }
        if let expectedPath = evidence.executablePath,
           normalizedPath(expectedPath) != normalizedPath(livePath) {
            return nil
        }
        return process
    }

    private func pruneCommandLineCache(using catalog: [pid_t: KernelProcess]) {
        let liveSudoIdentities = Set(
            catalog.values
                .filter { $0.name == "sudo" }
                .map(identity(for:))
        )
        commandLines = commandLines.filter { liveSudoIdentities.contains($0.key) }
        commandLineAttempts = commandLineAttempts.filter { liveSudoIdentities.contains($0.key) }
    }

    private func captureKernelProcesses() throws -> [pid_t: KernelProcess] {
        var managementInformationBase: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]

        for _ in 0..<4 {
            var requiredBytes = 0
            guard sysctl(&managementInformationBase, 4, nil, &requiredBytes, nil, 0) == 0 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }

            let stride = MemoryLayout<kinfo_proc>.stride
            var entries = [kinfo_proc](
                repeating: kinfo_proc(),
                count: requiredBytes / stride + 64
            )
            var actualBytes = entries.count * stride
            let result = entries.withUnsafeMutableBytes { bytes in
                sysctl(&managementInformationBase, 4, bytes.baseAddress, &actualBytes, nil, 0)
            }

            if result == 0 {
                return Dictionary(
                    uniqueKeysWithValues: entries.prefix(actualBytes / stride).map { entry in
                        let process = kernelProcess(from: entry)
                        return (process.pid, process)
                    }
                )
            }
            guard errno == ENOMEM else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        throw POSIXError(.ENOMEM)
    }

    private func kernelProcess(from entry: kinfo_proc) -> KernelProcess {
        let start = entry.kp_proc.p_un.__p_starttime
        return KernelProcess(
            pid: entry.kp_proc.p_pid,
            parentPID: entry.kp_eproc.e_ppid,
            realUserID: entry.kp_eproc.e_pcred.p_ruid,
            name: cString(from: entry.kp_proc.p_comm),
            startTime: ProcessStartTime(
                seconds: UInt64(max(0, start.tv_sec)),
                microseconds: UInt64(max(0, start.tv_usec))
            )
        )
    }

    private func ancestry(
        from leaf: KernelProcess,
        in catalog: [pid_t: KernelProcess]
    ) -> [KernelProcess] {
        var processes = [leaf]
        var seen = Set([leaf.pid])
        var child = leaf

        while child.parentPID > 0, let parent = catalog[child.parentPID] {
            guard parent.startTime <= child.startTime, seen.insert(parent.pid).inserted else {
                break
            }
            processes.append(parent)
            child = parent
        }
        return processes
    }

    private func descendants(
        from root: KernelProcess,
        in catalog: [pid_t: KernelProcess]
    ) -> [KernelProcess] {
        let childrenByParent = Dictionary(
            grouping: catalog.values.filter { $0.pid != root.pid },
            by: \.parentPID
        )
        var result: [KernelProcess] = []
        var visited = Set([root.pid])

        func appendChildren(of parent: KernelProcess, depth: Int) {
            guard depth <= 64 else {
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
                result.append(child)
                appendChildren(of: child, depth: depth + 1)
            }
        }

        appendChildren(of: root, depth: 1)
        return result
    }

    private func resolvedRecord(for process: KernelProcess) -> ProcessRecord? {
        let path = executablePath(for: process.pid)
        guard isSameProcessImage(process) else {
            return nil
        }
        return record(for: process, executablePath: path)
    }

    private func record(
        for process: KernelProcess,
        executablePath: String?,
        commandLine: String? = nil
    ) -> ProcessRecord {
        ProcessRecord(
            pid: process.pid,
            parentPID: process.parentPID,
            realUserID: process.realUserID,
            name: executablePath.map { URL(fileURLWithPath: $0).lastPathComponent } ?? process.name,
            executablePath: executablePath,
            startTime: process.startTime,
            commandLine: commandLine
        )
    }

    private func unresolvedRecord(for process: KernelProcess) -> ProcessRecord {
        ProcessRecord(
            pid: process.pid,
            parentPID: process.parentPID,
            realUserID: process.realUserID,
            name: process.name,
            executablePath: nil,
            startTime: process.startTime
        )
    }

    private func isSameProcessImage(_ process: KernelProcess) -> Bool {
        guard let current = currentKernelProcess(for: process.pid) else {
            return false
        }
        return current.startTime == process.startTime && current.name == process.name
    }

    private func currentKernelProcess(for processID: pid_t) -> KernelProcess? {
        var managementInformationBase: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, processID]
        var entry = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        guard sysctl(&managementInformationBase, 4, &entry, &size, nil, 0) == 0,
              size == MemoryLayout<kinfo_proc>.stride,
              entry.kp_proc.p_pid == processID else {
            return nil
        }
        return kernelProcess(from: entry)
    }

    private func executablePath(for processID: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let length = buffer.withUnsafeMutableBytes { bytes in
            proc_pidpath(processID, bytes.baseAddress, UInt32(bytes.count))
        }
        guard length > 0 else {
            return nil
        }
        return String(decoding: buffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)), as: UTF8.self)
    }

    private func normalizedPath(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL.path
    }

    private func identity(for process: KernelProcess) -> ProcessIdentity {
        ProcessIdentity(pid: process.pid, startTime: process.startTime)
    }

    private func newestFirst(_ lhs: KernelProcess, _ rhs: KernelProcess) -> Bool {
        if lhs.startTime != rhs.startTime {
            return lhs.startTime > rhs.startTime
        }
        return lhs.pid > rhs.pid
    }

    private func commandLine(for process: KernelProcess) async -> String? {
        let identity = identity(for: process)
        if let cached = commandLines[identity] {
            return cached
        }
        guard commandLineAttempts[identity, default: 0] < 2 else {
            return nil
        }
        commandLineAttempts[identity, default: 0] += 1

        let task = Process()
        let output = Pipe()
        let outputHandle = output.fileHandleForReading
        let accumulator = OutputAccumulator(maximumBytes: 1_048_576)
        outputHandle.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
            } else {
                accumulator.append(data)
            }
        }
        task.executableURL = URL(fileURLWithPath: "/bin/ps")
        task.arguments = ["-ww", "-p", String(process.pid), "-o", "command="]
        task.environment = ["LC_ALL": "C"]
        task.standardOutput = output
        task.standardError = FileHandle.nullDevice

        do {
            try task.run()
        } catch {
            return nil
        }

        let deadline = ProcessInfo.processInfo.systemUptime + 0.35
        while task.isRunning,
              !Task.isCancelled,
              !accumulator.snapshot().exceededLimit,
              ProcessInfo.processInfo.systemUptime < deadline {
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
        if task.isRunning {
            task.terminate()
            let terminationDeadline = ProcessInfo.processInfo.systemUptime + 0.10
            while task.isRunning, ProcessInfo.processInfo.systemUptime < terminationDeadline {
                try? await Task.sleep(nanoseconds: 5_000_000)
            }
        }
        if task.isRunning {
            kill(task.processIdentifier, SIGKILL)
        }
        task.waitUntilExit()
        outputHandle.readabilityHandler = nil
        accumulator.append(outputHandle.readDataToEndOfFile())
        let capturedOutput = accumulator.snapshot()
        guard task.terminationReason == .exit,
              task.terminationStatus == 0,
              !Task.isCancelled,
              !capturedOutput.exceededLimit,
              isSameProcessImage(process),
              executablePath(for: process.pid) == "/usr/bin/sudo" else {
            return nil
        }

        let commandLine = String(decoding: capturedOutput.data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !commandLine.isEmpty else {
            return nil
        }
        let sanitized = DisplayTextSanitizer.sanitize(commandLine)
        commandLines[identity] = sanitized
        return sanitized
    }

    private func cString<T>(from tuple: T) -> String {
        withUnsafeBytes(of: tuple) { bytes in
            String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
        }
    }
}

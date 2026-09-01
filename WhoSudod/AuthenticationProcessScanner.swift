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

enum AuthenticationRequesterUserPolicy {
    static func allows(
        realUserID: uid_t,
        signedInUserID: uid_t,
        attribution: AuthenticationAttribution
    ) -> Bool {
        realUserID == signedInUserID
            || (realUserID == 0 && attribution == .authorizationLog)
    }
}

enum AuthenticationEvidencePathMatcher {
    static func matches(reportedPath: String, liveExecutablePath: String) -> Bool {
        let reported = normalized(reportedPath)
        let live = normalized(liveExecutablePath)
        if reported == live {
            return true
        }
        let bundleURL = URL(fileURLWithPath: reported)
        guard bundleURL.pathExtension == "app",
              let executableURL = Bundle(url: bundleURL)?.executableURL else {
            return false
        }
        return normalized(executableURL.path) == live
    }

    private static func normalized(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL.path
    }
}

enum ProcessCommandLineParser {
    static func arguments(fromPSOutput data: Data) -> [String]? {
        guard data.count <= 1_048_576,
              let output = String(data: data, encoding: .utf8) else {
            return nil
        }
        let arguments = output.split(whereSeparator: \.isWhitespace).map(String.init)
        return arguments.isEmpty ? nil : arguments
    }
}

enum AuthenticationAnchorPriority {
    static func isAuthoritative(_ anchor: AuthenticationRequestAnchor) -> Bool {
        anchor.attribution.isLogAttributed
    }
}

actor AuthenticationProcessScanner {
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

    private var processArgumentsByIdentity: [ProcessIdentity: [String]] = [:]
    private var processArgumentReadAttempts: [ProcessIdentity: Int] = [:]

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

        pruneProcessArgumentCache(using: catalog)

        if let preferredAnchor,
           AuthenticationAnchorPriority.isAuthoritative(preferredAnchor) {
            guard let process = verifiedProcess(
                identity: preferredAnchor.identity,
                realUserID: realUserID,
                attribution: preferredAnchor.attribution,
                in: catalog
            ) else {
                return .empty
            }
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

        for event in evidence {
            let attribution: AuthenticationAttribution = event.source == .localAuthentication
                ? .localAuthenticationLog
                : .authorizationLog
            guard let process = verifiedProcess(
                for: event,
                realUserID: realUserID,
                attribution: attribution,
                in: catalog
            ) else {
                continue
            }
            let requestKind: AuthenticationRequestKind = event.source == .localAuthentication
                ? .localAuthentication
                : .authorization
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

        if let preferredAnchor,
           let process = verifiedProcess(
               identity: preferredAnchor.identity,
               realUserID: realUserID,
               attribution: preferredAnchor.attribution,
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

        guard allowSudoFallback else {
            return .empty
        }

        let sudoProcesses = catalog.values
            .filter { process in
                AuthenticationRequesterUserPolicy.allows(
                    realUserID: process.realUserID,
                    signedInUserID: realUserID,
                    attribution: .heuristicSudo
                ) && process.name == "sudo"
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
        for requester in requesters {
            let process = requester.process
            guard isSameProcessImage(process) else {
                continue
            }
            guard let path = executablePath(for: process.pid) else {
                inspectionWasIncomplete = true
                continue
            }
            let processArguments = path == "/usr/bin/sudo"
                ? processArguments(for: process)
                : nil
            let requesterRecord = record(
                for: process,
                executablePath: path,
                processArguments: processArguments
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
        attribution: AuthenticationAttribution,
        in catalog: [pid_t: KernelProcess]
    ) -> KernelProcess? {
        guard let process = catalog[identity.pid],
              AuthenticationRequesterUserPolicy.allows(
                  realUserID: process.realUserID,
                  signedInUserID: realUserID,
                  attribution: attribution
              ),
              self.identity(for: process) == identity,
              isSameProcessImage(process) else {
            return nil
        }
        return process
    }

    private func verifiedProcess(
        for evidence: AuthenticationClientEvent,
        realUserID: uid_t,
        attribution: AuthenticationAttribution,
        in catalog: [pid_t: KernelProcess]
    ) -> KernelProcess? {
        guard let process = catalog[evidence.processID],
              AuthenticationRequesterUserPolicy.allows(
                  realUserID: process.realUserID,
                  signedInUserID: realUserID,
                  attribution: attribution
              ),
              process.startTime.date <= evidence.receivedAt.addingTimeInterval(1),
              isSameProcessImage(process),
              let livePath = executablePath(for: process.pid) else {
            return nil
        }
        if let expectedPath = evidence.executablePath,
           !AuthenticationEvidencePathMatcher.matches(
               reportedPath: expectedPath,
               liveExecutablePath: livePath
           ) {
            return nil
        }
        return process
    }

    private func pruneProcessArgumentCache(using catalog: [pid_t: KernelProcess]) {
        let liveSudoIdentities = Set(
            catalog.values
                .filter { $0.name == "sudo" }
                .map(identity(for:))
        )
        processArgumentsByIdentity = processArgumentsByIdentity.filter {
            liveSudoIdentities.contains($0.key)
        }
        processArgumentReadAttempts = processArgumentReadAttempts.filter {
            liveSudoIdentities.contains($0.key)
        }
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
        processArguments: [String]? = nil
    ) -> ProcessRecord {
        ProcessRecord(
            pid: process.pid,
            parentPID: process.parentPID,
            realUserID: process.realUserID,
            name: executablePath.map { URL(fileURLWithPath: $0).lastPathComponent } ?? process.name,
            executablePath: executablePath,
            startTime: process.startTime,
            processArguments: processArguments
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

    private func identity(for process: KernelProcess) -> ProcessIdentity {
        ProcessIdentity(pid: process.pid, startTime: process.startTime)
    }

    private func newestFirst(_ lhs: KernelProcess, _ rhs: KernelProcess) -> Bool {
        if lhs.startTime != rhs.startTime {
            return lhs.startTime > rhs.startTime
        }
        return lhs.pid > rhs.pid
    }

    private func processArguments(for process: KernelProcess) -> [String]? {
        let identity = identity(for: process)
        if let cached = processArgumentsByIdentity[identity] {
            return cached
        }
        guard processArgumentReadAttempts[identity, default: 0] < 2 else {
            return nil
        }
        processArgumentReadAttempts[identity, default: 0] += 1

        guard let arguments = capturedProcessArguments(processID: process.pid),
              !arguments.isEmpty,
              isSameProcessImage(process),
              executablePath(for: process.pid) == "/usr/bin/sudo" else {
            return nil
        }
        processArgumentsByIdentity[identity] = arguments
        return arguments
    }

    private func capturedProcessArguments(processID: pid_t) -> [String]? {
        let output = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-ww", "-p", String(processID), "-o", "args="]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return nil
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationReason == .exit,
              process.terminationStatus == 0 else {
            return nil
        }
        return ProcessCommandLineParser.arguments(fromPSOutput: data)
    }

    private func cString<T>(from tuple: T) -> String {
        withUnsafeBytes(of: tuple) { bytes in
            String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
        }
    }
}

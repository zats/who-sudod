#!/usr/bin/env xcrun swift

import Darwin
import Foundation

struct ExpectedPresentationRow: Codable {
    let candidateIndex: Int
    let depth: Int
    let process: String
    let pid: String
    let executableOrCommand: String
}

struct ExpectedTree: Codable {
    let surfaceKind: String
    let inspectionState: String
    let requestKind: String
    let attribution: String
    let candidateCount: Int
    let rows: [ExpectedPresentationRow]
}

struct LiveProcess {
    let pid: pid_t
    let parentPID: pid_t
    let startSeconds: Int64
    let startMicroseconds: Int32
    let name: String
    let executablePath: String
}

struct PendingCommand {
    let process: String
    let executableOrCommand: String
}

struct Arguments {
    let requesterPID: pid_t
    let surfaceKind: String
    let requestKind: String
    let attribution: String
    let outputURL: URL
    let pendingCommand: PendingCommand?
}

enum ExpectedTreeFailure: LocalizedError {
    case invalidArguments
    case processUnavailable(pid_t)
    case invalidAncestry(childPID: pid_t, parentPID: pid_t)
    case ancestryCycle(pid_t)
    case requesterChanged(pid_t)

    var errorDescription: String? {
        switch self {
        case .invalidArguments:
            "Invalid arguments."
        case let .processUnavailable(processID):
            "Could not inspect process \(processID)."
        case let .invalidAncestry(childPID, parentPID):
            "Process \(parentPID) cannot be the parent of process \(childPID)."
        case let .ancestryCycle(processID):
            "The ancestry contains process \(processID) more than once."
        case let .requesterChanged(processID):
            "Requester process \(processID) changed while its ancestry was inspected."
        }
    }
}

func fail(_ message: String, status: Int32) -> Never {
    FileHandle.standardError.write(Data("\(message)\n".utf8))
    exit(status)
}

func parseArguments(_ values: [String]) throws -> Arguments {
    guard values.count == 5 || values.count == 8,
          let requesterPID = pid_t(values[0]),
          requesterPID > 1,
          !values[1].isEmpty,
          !values[2].isEmpty,
          !values[3].isEmpty,
          values[4].hasPrefix("/") else {
        throw ExpectedTreeFailure.invalidArguments
    }

    let pendingCommand: PendingCommand?
    if values.count == 8 {
        guard values[5] == "--pending",
              !values[6].isEmpty,
              !values[7].isEmpty else {
            throw ExpectedTreeFailure.invalidArguments
        }
        pendingCommand = PendingCommand(
            process: values[6],
            executableOrCommand: values[7]
        )
    } else {
        pendingCommand = nil
    }

    return Arguments(
        requesterPID: requesterPID,
        surfaceKind: values[1],
        requestKind: values[2],
        attribution: values[3],
        outputURL: URL(fileURLWithPath: values[4]),
        pendingCommand: pendingCommand
    )
}

func executablePathFromPS(_ processID: pid_t) -> String? {
    let task = Process()
    let output = Pipe()
    task.executableURL = URL(fileURLWithPath: "/bin/ps")
    task.arguments = ["-ww", "-p", String(processID), "-o", "comm="]
    task.standardOutput = output
    task.standardError = FileHandle.nullDevice
    do {
        try task.run()
        task.waitUntilExit()
    } catch {
        return nil
    }
    guard task.terminationStatus == 0 else {
        return nil
    }
    let path = String(
        decoding: output.fileHandleForReading.readDataToEndOfFile(),
        as: UTF8.self
    ).trimmingCharacters(in: .whitespacesAndNewlines)
    guard path.hasPrefix("/") else {
        return nil
    }
    return path
}

func liveProcess(_ processID: pid_t) -> LiveProcess? {
    var managementInformationBase: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, processID]
    var entry = kinfo_proc()
    var entrySize = MemoryLayout<kinfo_proc>.stride
    guard sysctl(
        &managementInformationBase,
        4,
        &entry,
        &entrySize,
        nil,
        0
    ) == 0,
    entrySize == MemoryLayout<kinfo_proc>.stride,
    entry.kp_proc.p_pid == processID else {
        return nil
    }

    var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
    let pathLength = pathBuffer.withUnsafeMutableBytes { bytes in
        proc_pidpath(processID, bytes.baseAddress, UInt32(bytes.count))
    }
    let executablePath: String
    if pathLength > 0 {
        executablePath = String(
            decoding: pathBuffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)),
            as: UTF8.self
        )
    } else if let path = executablePathFromPS(processID) {
        executablePath = path
    } else {
        return nil
    }
    let start = entry.kp_proc.p_un.__p_starttime
    return LiveProcess(
        pid: processID,
        parentPID: entry.kp_eproc.e_ppid,
        startSeconds: Int64(start.tv_sec),
        startMicroseconds: Int32(start.tv_usec),
        name: URL(fileURLWithPath: executablePath).lastPathComponent,
        executablePath: executablePath
    )
}

func startedBeforeOrWith(_ parent: LiveProcess, child: LiveProcess) -> Bool {
    if parent.startSeconds != child.startSeconds {
        return parent.startSeconds < child.startSeconds
    }
    return parent.startMicroseconds <= child.startMicroseconds
}

func sameIdentity(_ lhs: LiveProcess, _ rhs: LiveProcess) -> Bool {
    lhs.pid == rhs.pid
        && lhs.startSeconds == rhs.startSeconds
        && lhs.startMicroseconds == rhs.startMicroseconds
        && lhs.executablePath == rhs.executablePath
}

func ancestry(from requesterPID: pid_t) throws -> [LiveProcess] {
    var result: [LiveProcess] = []
    var currentPID = requesterPID
    var visited: Set<pid_t> = []

    while currentPID > 0 {
        guard visited.insert(currentPID).inserted else {
            throw ExpectedTreeFailure.ancestryCycle(currentPID)
        }
        guard let process = liveProcess(currentPID) else {
            throw ExpectedTreeFailure.processUnavailable(currentPID)
        }
        if let child = result.last,
           !startedBeforeOrWith(process, child: child) {
            throw ExpectedTreeFailure.invalidAncestry(
                childPID: child.pid,
                parentPID: process.pid
            )
        }
        result.append(process)
        currentPID = process.parentPID
    }

    guard let firstRequester = result.first,
          let currentRequester = liveProcess(requesterPID),
          sameIdentity(firstRequester, currentRequester) else {
        throw ExpectedTreeFailure.requesterChanged(requesterPID)
    }
    return result.reversed()
}

func stableAncestry(from requesterPID: pid_t) throws -> [LiveProcess] {
    var lastError: Error = ExpectedTreeFailure.processUnavailable(requesterPID)
    for attempt in 0..<40 {
        do {
            return try ancestry(from: requesterPID)
        } catch {
            lastError = error
        }
        if attempt < 39 {
            usleep(50_000)
        }
    }
    throw lastError
}

func enclosingApplicationPath(for executablePath: String) -> String? {
    var url = URL(fileURLWithPath: executablePath)
    while url.path != "/" {
        if url.pathExtension == "app",
           Bundle(url: url)?.executableURL?.resolvingSymlinksInPath().path
            == URL(fileURLWithPath: executablePath).resolvingSymlinksInPath().path {
            return url.path
        }
        url.deleteLastPathComponent()
    }
    return nil
}

func displayName(for process: LiveProcess) -> String {
    guard let appPath = enclosingApplicationPath(for: process.executablePath),
          let bundle = Bundle(url: URL(fileURLWithPath: appPath)) else {
        return process.name
    }
    return (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
        ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
        ?? process.name
}

func expectedTree(for arguments: Arguments) throws -> ExpectedTree {
    let processes = try stableAncestry(from: arguments.requesterPID)
    var rows = processes.enumerated().map { depth, process in
        let name = displayName(for: process)
        return ExpectedPresentationRow(
            candidateIndex: 0,
            depth: depth,
            process: name,
            pid: String(process.pid),
            executableOrCommand: process.executablePath
        )
    }
    if let pendingCommand = arguments.pendingCommand {
        rows.append(
            ExpectedPresentationRow(
                candidateIndex: 0,
                depth: processes.count,
                process: pendingCommand.process,
                pid: "—",
                executableOrCommand: pendingCommand.executableOrCommand
            )
        )
    }
    return ExpectedTree(
        surfaceKind: arguments.surfaceKind,
        inspectionState: "complete",
        requestKind: arguments.requestKind,
        attribution: arguments.attribution,
        candidateCount: 1,
        rows: rows
    )
}

let usage = """
Usage:
  write-expected-process-tree.swift REQUESTER_PID SURFACE_KIND REQUEST_KIND ATTRIBUTION OUTPUT_JSON
  write-expected-process-tree.swift REQUESTER_PID SURFACE_KIND REQUEST_KIND ATTRIBUTION OUTPUT_JSON --pending PROCESS EXECUTABLE_OR_COMMAND
"""

do {
    let arguments = try parseArguments(Array(CommandLine.arguments.dropFirst()))
    let tree = try expectedTree(for: arguments)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(tree).write(to: arguments.outputURL, options: .atomic)
} catch ExpectedTreeFailure.invalidArguments {
    fail(usage, status: 64)
} catch {
    fail("Could not write the expected process tree: \(error.localizedDescription)", status: 74)
}

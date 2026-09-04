#!/usr/bin/env xcrun swift

import Darwin
import Foundation

struct PresentationRow: Codable, Equatable {
    let candidateIndex: Int
    let depth: Int
    let process: String
    let pid: String
    let executableOrCommand: String
}

struct DiagnosticState: Decodable {
    let schemaVersion: Int
    let runID: String
    let writeSequence: Int
    let writtenAtUptime: TimeInterval
    let promptSequence: Int
    let accessibilityTrusted: Bool
    let visibility: String
    let promptPresent: Bool
    let renderingComplete: Bool
    let surfaceKind: String?
    let presentation: String?
    let passwordInputVisible: Bool
    let inspectionState: String
    let requestKind: String?
    let attribution: String?
    let candidateCount: Int
    let rows: [PresentationRow]
}

struct ExpectedTree: Decodable {
    let surfaceKind: String
    let inspectionState: String
    let requestKind: String
    let attribution: String
    let passwordInputVisible: Bool
    let candidateCount: Int
    let rows: [PresentationRow]

    var presentation: String {
        surfaceKind == "terminalPassword" ? "notch" : "dialog"
    }
}

enum Mode {
    case ready(stateURL: URL, runID: String, appPID: pid_t, timeout: TimeInterval)
    case tree(
        stateURL: URL,
        runID: String,
        afterPromptSequence: Int,
        expected: ExpectedTree,
        appPID: pid_t,
        requesterPID: pid_t,
        timeout: TimeInterval
    )
    case hidden(
        stateURL: URL,
        runID: String,
        promptSequence: Int,
        appPID: pid_t,
        timeout: TimeInterval
    )
}

func writeError(_ message: String) {
    FileHandle.standardError.write(Data("\(message)\n".utf8))
}

func absoluteURL(_ value: String) -> URL? {
    guard value.hasPrefix("/") else {
        return nil
    }
    return URL(fileURLWithPath: value)
}

func timeout(_ value: String) -> TimeInterval? {
    guard let result = TimeInterval(value), result > 0 else {
        return nil
    }
    return result
}

func processID(_ value: String) -> pid_t? {
    guard let result = pid_t(value), result > 0 else {
        return nil
    }
    return result
}

func parseMode(_ values: [String]) -> Mode? {
    let decoder = JSONDecoder()
    switch values.first {
    case "ready":
        guard values.count == 5,
              let stateURL = absoluteURL(values[1]),
              !values[2].isEmpty,
              let appPID = processID(values[3]),
              let wait = timeout(values[4]) else {
            return nil
        }
        return .ready(
            stateURL: stateURL,
            runID: values[2],
            appPID: appPID,
            timeout: wait
        )
    case "tree":
        guard values.count == 9,
              let stateURL = absoluteURL(values[1]),
              !values[2].isEmpty,
              let sequence = Int(values[3]),
              let expectedURL = absoluteURL(values[4]),
              let expected = try? decoder.decode(
                ExpectedTree.self,
                from: Data(contentsOf: expectedURL)
              ),
              let appPID = processID(values[5]),
              let requesterPID = processID(values[6]),
              let wait = timeout(values[7]),
              values[8] == "--exact" else {
            return nil
        }
        return .tree(
            stateURL: stateURL,
            runID: values[2],
            afterPromptSequence: sequence,
            expected: expected,
            appPID: appPID,
            requesterPID: requesterPID,
            timeout: wait
        )
    case "hidden":
        guard values.count == 6,
              let stateURL = absoluteURL(values[1]),
              !values[2].isEmpty,
              let sequence = Int(values[3]),
              let appPID = processID(values[4]),
              let wait = timeout(values[5]) else {
            return nil
        }
        return .hidden(
            stateURL: stateURL,
            runID: values[2],
            promptSequence: sequence,
            appPID: appPID,
            timeout: wait
        )
    default:
        return nil
    }
}

func differences(expected: ExpectedTree, actual: DiagnosticState?) -> String {
    guard let actual else {
        return "No matching diagnostic state was read."
    }
    var lines: [String] = []
    let comparisons: [(String, String, String)] = [
        ("visibility", "visible", actual.visibility),
        ("surfaceKind", expected.surfaceKind, actual.surfaceKind ?? "<none>"),
        ("presentation", expected.presentation, actual.presentation ?? "<none>"),
        ("inspectionState", expected.inspectionState, actual.inspectionState),
        ("requestKind", expected.requestKind, actual.requestKind ?? "<none>"),
        ("attribution", expected.attribution, actual.attribution ?? "<none>")
    ]
    for (name, expectedValue, actualValue) in comparisons where expectedValue != actualValue {
        lines.append("\(name): expected \(expectedValue), got \(actualValue)")
    }
    if !actual.accessibilityTrusted {
        lines.append("accessibilityTrusted: expected true, got false")
    }
    if !actual.promptPresent {
        lines.append("promptPresent: expected true, got false")
    }
    if !actual.renderingComplete {
        lines.append("renderingComplete: expected true, got false")
    }
    if actual.passwordInputVisible != expected.passwordInputVisible {
        lines.append(
            "passwordInputVisible: expected \(expected.passwordInputVisible), got \(actual.passwordInputVisible)"
        )
    }
    if actual.candidateCount != expected.candidateCount {
        lines.append(
            "candidateCount: expected \(expected.candidateCount), got \(actual.candidateCount)"
        )
    }
    let count = max(expected.rows.count, actual.rows.count)
    for index in 0..<count {
        let expectedRow = expected.rows.indices.contains(index) ? expected.rows[index] : nil
        let actualRow = actual.rows.indices.contains(index) ? actual.rows[index] : nil
        switch (expectedRow, actualRow) {
        case let (expectedRow?, actualRow?):
            if expectedRow.candidateIndex != actualRow.candidateIndex {
                lines.append(
                    "row \(index) candidateIndex: expected \(expectedRow.candidateIndex), got \(actualRow.candidateIndex)"
                )
            }
            if expectedRow.depth != actualRow.depth {
                lines.append(
                    "row \(index) depth: expected \(expectedRow.depth), got \(actualRow.depth)"
                )
            }
            if expectedRow.process != actualRow.process {
                lines.append(
                    "row \(index) process: expected \(expectedRow.process), got \(actualRow.process)"
                )
            }
            if expectedRow.pid != actualRow.pid {
                lines.append(
                    "row \(index) pid: expected \(expectedRow.pid), got \(actualRow.pid)"
                )
            }
            if expectedRow.executableOrCommand != actualRow.executableOrCommand {
                lines.append("row \(index) executableOrCommand: values differ and are hidden")
            }
        case let (expectedRow?, nil):
            lines.append(
                "row \(index): expected \(expectedRow.process) [\(expectedRow.pid)], got <missing>"
            )
        case let (nil, actualRow?):
            lines.append(
                "row \(index): expected <missing>, got \(actualRow.process) [\(actualRow.pid)]"
            )
        case (nil, nil):
            break
        }
    }
    return lines.isEmpty ? "State did not stay stable long enough." : lines.joined(separator: "\n")
}

let values = Array(CommandLine.arguments.dropFirst())
guard let mode = parseMode(values) else {
    writeError(
        """
        Usage:
          wait-for-live-tree.swift ready STATE_PATH RUN_ID APP_PID TIMEOUT_SECONDS
          wait-for-live-tree.swift tree STATE_PATH RUN_ID AFTER_PROMPT_SEQUENCE EXPECTED_JSON APP_PID REQUESTER_PID TIMEOUT_SECONDS --exact
          wait-for-live-tree.swift hidden STATE_PATH RUN_ID PROMPT_SEQUENCE APP_PID TIMEOUT_SECONDS
        """
    )
    exit(64)
}

let stateURL: URL
let runID: String
let wait: TimeInterval
switch mode {
case let .ready(url, identifier, _, timeout):
    (stateURL, runID, wait) = (url, identifier, timeout)
case let .tree(url, identifier, _, _, _, _, timeout):
    (stateURL, runID, wait) = (url, identifier, timeout)
case let .hidden(url, identifier, _, _, timeout):
    (stateURL, runID, wait) = (url, identifier, timeout)
}

let requiredLiveProcessIDs: [pid_t]
switch mode {
case let .ready(_, _, appPID, _):
    requiredLiveProcessIDs = [appPID]
case let .tree(_, _, _, _, appPID, requesterPID, _):
    requiredLiveProcessIDs = [appPID, requesterPID]
case let .hidden(_, _, _, appPID, _):
    requiredLiveProcessIDs = [appPID]
}

let decoder = JSONDecoder()
let deadline = Date().addingTimeInterval(wait)
let requiredStability: TimeInterval
switch mode {
case .tree:
    requiredStability = 1
case .ready, .hidden:
    requiredStability = 0.1
}
var stableSince: Date?
var lastObservedState: DiagnosticState?

while Date() < deadline {
    for processID in requiredLiveProcessIDs {
        errno = 0
        if kill(processID, 0) != 0, errno != EPERM {
            writeError("Required process \(processID) exited during the live check.")
            exit(71)
        }
    }
    if let data = try? Data(contentsOf: stateURL),
       let state = try? decoder.decode(DiagnosticState.self, from: data),
       state.schemaVersion == 4,
       state.runID == runID {
        lastObservedState = state
        let stateAge = ProcessInfo.processInfo.systemUptime - state.writtenAtUptime
        let stateIsFresh = stateAge >= -1 && stateAge <= 0.5
        let matches: Bool
        switch mode {
        case .ready:
            matches = stateIsFresh
                && state.accessibilityTrusted
                && state.visibility == "hidden"
                && !state.promptPresent
                && state.renderingComplete
                && state.surfaceKind == nil
                && state.presentation == nil
                && !state.passwordInputVisible
                && state.requestKind == nil
                && state.attribution == nil
                && state.candidateCount == 0
                && state.rows.isEmpty
        case let .tree(_, _, afterPromptSequence, expected, _, _, _):
            matches = stateIsFresh
                && state.promptSequence != afterPromptSequence
                && state.accessibilityTrusted
                && state.visibility == "visible"
                && state.promptPresent
                && state.renderingComplete
                && state.surfaceKind == expected.surfaceKind
                && state.presentation == expected.presentation
                && state.passwordInputVisible == expected.passwordInputVisible
                && state.inspectionState == expected.inspectionState
                && state.requestKind == expected.requestKind
                && state.attribution == expected.attribution
                && state.candidateCount == expected.candidateCount
                && state.rows == expected.rows
        case let .hidden(_, _, promptSequence, _, _):
            matches = stateIsFresh
                && state.promptSequence == promptSequence
                && state.accessibilityTrusted
                && state.visibility == "hidden"
                && !state.promptPresent
                && state.presentation == nil
                && !state.passwordInputVisible
                && state.rows.isEmpty
        }

        if matches {
            if stableSince == nil {
                stableSince = Date()
            } else if let stableSince,
                      Date().timeIntervalSince(stableSince) >= requiredStability {
                switch mode {
                case .ready:
                    print("PASS ready runID=\(state.runID)")
                case .tree:
                    print(
                        "PASS tree runID=\(state.runID) promptSequence=\(state.promptSequence) presentation=\(state.presentation ?? "<none>") passwordInputVisible=\(state.passwordInputVisible) rows=\(state.rows.count)"
                    )
                    for row in state.rows {
                        print("  \(row.process) [\(row.pid)]")
                    }
                case .hidden:
                    print(
                        "PASS hidden runID=\(state.runID) promptSequence=\(state.promptSequence)"
                    )
                }
                exit(0)
            }
        } else {
            stableSince = nil
        }
    }
    Thread.sleep(forTimeInterval: 0.025)
}

writeError("Live state did not match within \(wait) seconds.")
switch mode {
case .ready:
    if let lastObservedState {
        writeError("The app was not in a clean, trusted, hidden state.")
        writeError(
            "trusted=\(lastObservedState.accessibilityTrusted) visibility=\(lastObservedState.visibility) candidates=\(lastObservedState.candidateCount) rows=\(lastObservedState.rows.count)"
        )
    } else {
        writeError("No matching diagnostic state was read.")
    }
case let .tree(_, _, _, expected, _, _, _):
    writeError(differences(expected: expected, actual: lastObservedState))
case .hidden:
    if let state = lastObservedState {
        writeError(
            "visibility: expected a closed prompt and hidden empty table, got promptPresent=\(state.promptPresent) visibility=\(state.visibility) rows=\(state.rows.count)"
        )
    } else {
        writeError("No matching diagnostic state was read.")
    }
}
exit(1)

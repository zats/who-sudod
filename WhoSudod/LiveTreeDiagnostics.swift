#if DEBUG
import Foundation

struct LiveTreeDiagnosticState: Codable, Equatable, Sendable {
    enum Visibility: String, Codable, Sendable {
        case visible
        case hidden
    }

    let schemaVersion: Int
    let runID: String
    let writeSequence: Int
    let writtenAtUptime: TimeInterval
    let promptSequence: Int
    let accessibilityTrusted: Bool
    let visibility: Visibility
    let promptPresent: Bool
    let renderingComplete: Bool
    let surfaceKind: String?
    let inspectionState: String
    let requestKind: String?
    let attribution: String?
    let candidateCount: Int
    let rows: [ProcessTablePresentationRow]
}

struct LiveTreeDiagnostics {
    static let runIDEnvironmentKey = "WHO_SUDOD_TEST_RUN_ID"
    static let statePathEnvironmentKey = "WHO_SUDOD_TEST_STATE_PATH"

    private struct Payload: Equatable {
        let promptSequence: Int
        let accessibilityTrusted: Bool
        let visibility: LiveTreeDiagnosticState.Visibility
        let promptPresent: Bool
        let renderingComplete: Bool
        let surfaceKind: String?
        let inspectionState: String
        let requestKind: String?
        let attribution: String?
        let candidateCount: Int
        let rows: [ProcessTablePresentationRow]
    }

    private let runID: String
    private let stateURL: URL
    private var writeSequence = 0
    private var lastWriteUptime: TimeInterval?
    private var lastPayload: Payload?

    init?(environment: [String: String] = ProcessInfo.processInfo.environment) {
        guard let runID = environment[Self.runIDEnvironmentKey],
              !runID.isEmpty,
              let statePath = environment[Self.statePathEnvironmentKey],
              statePath.hasPrefix("/") else {
            return nil
        }
        self.init(runID: runID, stateURL: URL(fileURLWithPath: statePath))
    }

    init?(runID: String, stateURL: URL) {
        guard !runID.isEmpty, stateURL.isFileURL, stateURL.path.hasPrefix("/") else {
            return nil
        }
        self.runID = runID
        self.stateURL = stateURL
    }

    mutating func recordReadiness(
        accessibilityTrusted: Bool,
        promptSequence: Int
    ) throws {
        try record(
            Payload(
                promptSequence: promptSequence,
                accessibilityTrusted: accessibilityTrusted,
                visibility: .hidden,
                promptPresent: false,
                renderingComplete: true,
                surfaceKind: nil,
                inspectionState: "pending",
                requestKind: nil,
                attribution: nil,
                candidateCount: 0,
                rows: []
            )
        )
    }

    mutating func recordHidden(
        accessibilityTrusted: Bool,
        promptSequence: Int,
        promptPresent: Bool
    ) throws {
        try record(
            Payload(
                promptSequence: promptSequence,
                accessibilityTrusted: accessibilityTrusted,
                visibility: .hidden,
                promptPresent: promptPresent,
                renderingComplete: true,
                surfaceKind: nil,
                inspectionState: "pending",
                requestKind: nil,
                attribution: nil,
                candidateCount: 0,
                rows: []
            )
        )
    }

    mutating func recordVisible(
        promptSequence: Int,
        surfaceKind: AuthenticationSurfaceKind,
        snapshot: AuthenticationProcessSnapshot,
        renderedTable: RenderedProcessTable
    ) throws {
        let firstCandidate = snapshot.candidates.first
        try record(
            Payload(
                promptSequence: promptSequence,
                accessibilityTrusted: true,
                visibility: .visible,
                promptPresent: true,
                renderingComplete: renderedTable.isComplete,
                surfaceKind: surfaceKindName(surfaceKind),
                inspectionState: inspectionStateName(snapshot.inspectionState),
                requestKind: firstCandidate.map { requestKindName($0.requestKind) },
                attribution: firstCandidate.map { attributionName($0.attribution) },
                candidateCount: snapshot.candidates.count,
                rows: renderedTable.rows
            )
        )
    }

    private mutating func record(_ payload: Payload) throws {
        let now = ProcessInfo.processInfo.systemUptime
        if payload == lastPayload,
           let lastWriteUptime,
           now - lastWriteUptime < 0.2 {
            return
        }

        writeSequence += 1
        let state = LiveTreeDiagnosticState(
            schemaVersion: 3,
            runID: runID,
            writeSequence: writeSequence,
            writtenAtUptime: now,
            promptSequence: payload.promptSequence,
            accessibilityTrusted: payload.accessibilityTrusted,
            visibility: payload.visibility,
            promptPresent: payload.promptPresent,
            renderingComplete: payload.renderingComplete,
            surfaceKind: payload.surfaceKind,
            inspectionState: payload.inspectionState,
            requestKind: payload.requestKind,
            attribution: payload.attribution,
            candidateCount: payload.candidateCount,
            rows: payload.rows
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(state)
        try data.write(to: stateURL, options: .atomic)
        lastPayload = payload
        lastWriteUptime = now
    }

    private func surfaceKindName(_ kind: AuthenticationSurfaceKind) -> String {
        switch kind {
        case .securityAgent:
            "securityAgent"
        case .localAuthentication:
            "localAuthentication"
        case .terminalPassword:
            "terminalPassword"
        }
    }

    private func inspectionStateName(_ state: ProcessInspectionState) -> String {
        switch state {
        case .complete:
            "complete"
        case .partial:
            "partial"
        case .unavailable:
            "unavailable"
        case .pending:
            "pending"
        case .requesterExited:
            "requesterExited"
        }
    }

    private func requestKindName(_ kind: AuthenticationRequestKind) -> String {
        switch kind {
        case .sudo:
            "sudo"
        case .localAuthentication:
            "localAuthentication"
        case .authorization:
            "authorization"
        }
    }

    private func attributionName(_ attribution: AuthenticationAttribution) -> String {
        switch attribution {
        case .localAuthenticationLog:
            "localAuthenticationLog"
        case .authorizationLog:
            "authorizationLog"
        case .heuristicSudo:
            "heuristicSudo"
        }
    }
}
#endif

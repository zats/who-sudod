import AppKit
import Foundation
import os

struct AuthorizationMonitorStatus: Equatable {
    let message: String
    let accessibilityTrusted: Bool
    let isShowingPanel: Bool
}

struct WindowObservationStability: Equatable {
    let requiredMisses: Int
    private(set) var consecutiveMisses = 0

    init(requiredMisses: Int = 3) {
        precondition(requiredMisses > 0)
        self.requiredMisses = requiredMisses
    }

    mutating func recordConfirmation() {
        consecutiveMisses = 0
    }

    mutating func recordMiss() -> Bool {
        consecutiveMisses = min(consecutiveMisses + 1, requiredMisses)
        return consecutiveMisses == requiredMisses
    }

    mutating func reset() {
        consecutiveMisses = 0
    }
}

enum AuthenticationEvidenceSelection {
    static func rankedEvents(
        from events: [AuthenticationClientEvent],
        surfaceKind: AuthenticationSurfaceKind,
        firstSeenAt: Date,
        now: Date,
        maximumLeadTime: TimeInterval = 3,
        maximumLagTime: TimeInterval = 3
    ) -> [AuthenticationClientEvent] {
        let earliest = firstSeenAt.addingTimeInterval(-maximumLeadTime)
        let latest = min(now, firstSeenAt.addingTimeInterval(maximumLagTime))
        let eligible = events.filter { event in
            event.receivedAt >= earliest
                && event.receivedAt <= latest
                && (surfaceKind == .securityAgent || event.source == .localAuthentication)
        }
        let preferredSource: AuthenticationEventSource = surfaceKind == .securityAgent
            ? .authorizationShell
            : .localAuthentication
        return eligible.sorted { lhs, rhs in
            let lhsIsPreferred = lhs.source == preferredSource
            let rhsIsPreferred = rhs.source == preferredSource
            if lhsIsPreferred != rhsIsPreferred {
                return lhsIsPreferred
            }
            let lhsDistance = abs(lhs.receivedAt.timeIntervalSince(firstSeenAt))
            let rhsDistance = abs(rhs.receivedAt.timeIntervalSince(firstSeenAt))
            if lhsDistance != rhsDistance {
                return lhsDistance < rhsDistance
            }
            return lhs.receivedAt > rhs.receivedAt
        }
    }
}

@MainActor
final class AuthorizationPromptMonitor: NSObject {
    private static let securityAgentShownNotification = Notification.Name(
        "com.apple.SecurityAgent.consoleLogin.UIShown"
    )

    private let logger = Logger(subsystem: "com.zats.WhoSudo", category: "AuthorizationMonitor")
    private let scanner = AuthenticationProcessScanner()
    private let panel = ProcessTreePanelController()
    private let statusHandler: (AuthorizationMonitorStatus) -> Void
    private lazy var eventMonitor = AuthenticationEventMonitor { [weak self] event in
        self?.recordAuthenticationEvent(event)
    }
    private var timer: Timer?
    private var target: AuthenticationWindowSnapshot?
    private var targetFirstSeenAt: Date?
    private var recentEvents: [AuthenticationClientEvent] = []
    private var lastProcessSnapshot = AuthenticationProcessSnapshot.pending
    private var nextDiscoveryTime: TimeInterval = 0
    private var nextProcessScanTime: TimeInterval = 0
    private var processScanTask: Task<Void, Never>?
    private var processScanSequence = 0
    private var observationStability = WindowObservationStability()

    init(statusHandler: @escaping (AuthorizationMonitorStatus) -> Void) {
        self.statusHandler = statusHandler
        super.init()
    }

    func start() {
        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(securityAgentDidShow(_:)),
            name: Self.securityAgentShownNotification,
            object: nil,
            suspensionBehavior: .deliverImmediately
        )
        NSWorkspace.shared.notificationCenter.addObserver(
            self,
            selector: #selector(frontmostApplicationDidChange),
            name: NSWorkspace.didActivateApplicationNotification,
            object: nil
        )

        let timer = Timer(timeInterval: 1.0 / 30.0, target: self, selector: #selector(tick), userInfo: nil, repeats: true)
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
        refresh(forceDiscovery: true)
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        cancelProcessScan()
        eventMonitor.stop()
        DistributedNotificationCenter.default().removeObserver(self)
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        panel.hide()
    }

    @objc
    private func tick() {
        refresh(forceDiscovery: false)
    }

    @objc
    private func securityAgentDidShow(_ notification: Notification) {
        logger.notice("SecurityAgent UI notification received")
        if target?.surfaceKind == .securityAgent {
            resetAttribution(firstSeenAt: Date())
        }
        refresh(forceDiscovery: true)
    }

    @objc
    private func frontmostApplicationDidChange() {
        refresh(forceDiscovery: false)
    }

    private func refresh(forceDiscovery: Bool) {
        guard AccessibilityFocusReader.isTrusted else {
            eventMonitor.stop()
            cancelProcessScan()
            target = nil
            targetFirstSeenAt = nil
            lastProcessSnapshot = .pending
            observationStability.reset()
            panel.hide()
            report(message: "Accessibility access is required", isShowingPanel: false)
            return
        }
        eventMonitor.start()

        let now = ProcessInfo.processInfo.systemUptime

        if let currentTarget = target {
            guard let current = AuthenticationWindowLocator.snapshot(identity: currentTarget.identity) else {
                guard observationStability.recordMiss() else {
                    return
                }
                logger.notice("Authentication window closed")
                cancelProcessScan()
                target = nil
                targetFirstSeenAt = nil
                lastProcessSnapshot = .pending
                observationStability.reset()
                panel.hide()
                nextDiscoveryTime = 0
                report(message: waitingMessage, isShowingPanel: false)
                return
            }
            target = current
            updatePanel(for: current, now: now)
            return
        }

        guard forceDiscovery || now >= nextDiscoveryTime else {
            return
        }
        nextDiscoveryTime = now + 0.20

        guard let candidate = AuthenticationWindowLocator.frontmostCandidate() else {
            report(message: waitingMessage, isShowingPanel: false)
            return
        }

        target = candidate
        observationStability.reset()
        resetAttribution(firstSeenAt: Date())
        logger.notice("Authentication window detected for PID \(candidate.processID, privacy: .public)")
        updatePanel(for: candidate, now: now)
    }

    private func updatePanel(for window: AuthenticationWindowSnapshot, now: TimeInterval) {
        guard isAuthenticationWindowFocused(window) == true else {
            guard observationStability.recordMiss() else {
                return
            }
            let wasPresented = panel.isPresented
            panel.hide()
            if wasPresented {
                report(message: "Authentication dialog is not focused", isShowingPanel: false)
            }
            switchToFocusedCandidate(excluding: window.identity, now: now)
            return
        }
        observationStability.recordConfirmation()

        if now >= nextProcessScanTime, processScanTask == nil {
            nextProcessScanTime = now + 0.15
            startProcessScan(for: window)
        }

        panel.show(
            snapshot: lastProcessSnapshot,
            authenticationFrame: window.frame,
            visibleFrame: window.visibleFrame
        )
        if let chain = lastProcessSnapshot.candidates.first {
            let verification = chain.attribution.isLogAttributed ? "observed" : "likely"
            let freshness = lastProcessSnapshot.inspectionState == .requesterExited
                ? "last known"
                : "live"
            report(message: "Showing \(verification) \(freshness) requester", isShowingPanel: true)
        } else {
            report(message: "Authentication dialog detected; finding requester", isShowingPanel: true)
        }
    }

    private func startProcessScan(for window: AuthenticationWindowSnapshot) {
        processScanSequence += 1
        let sequence = processScanSequence
        let firstSeenAt = targetFirstSeenAt ?? Date()
        let evidence = AuthenticationEvidenceSelection.rankedEvents(
            from: recentEvents,
            surfaceKind: window.surfaceKind,
            firstSeenAt: firstSeenAt,
            now: Date()
        )
        let currentAnchor = lastProcessSnapshot.candidates.first?.anchor
        let preferredAnchor = evidence.isEmpty || currentAnchor?.attribution.isLogAttributed == true
            ? currentAnchor
            : nil
        processScanTask = Task { [weak self, scanner] in
            let newSnapshot = await scanner.snapshot(
                preferredAnchor: preferredAnchor,
                evidence: evidence,
                allowSudoFallback: window.surfaceKind == .securityAgent
            )
            guard !Task.isCancelled, let self,
                  self.processScanSequence == sequence else {
                return
            }
            self.processScanTask = nil
            guard self.target?.identity == window.identity else {
                return
            }

            let refreshedSnapshot = ProcessSnapshotSelection.refreshingLive(
                current: self.lastProcessSnapshot,
                observed: newSnapshot
            )
            if refreshedSnapshot != self.lastProcessSnapshot {
                self.logger.notice(
                    "Process snapshot has \(newSnapshot.candidates.count, privacy: .public) requester candidate(s)"
                )
                self.lastProcessSnapshot = refreshedSnapshot
            }
        }
    }

    private func switchToFocusedCandidate(
        excluding identity: AuthenticationWindowIdentity,
        now: TimeInterval
    ) {
        guard let candidate = AuthenticationWindowLocator.frontmostCandidate(),
              candidate.identity != identity else {
            return
        }
        target = candidate
        observationStability.reset()
        resetAttribution(firstSeenAt: Date())
        logger.notice(
            "Authentication window switched to PID \(candidate.processID, privacy: .public)"
        )
        updatePanel(for: candidate, now: now)
    }

    private func isAuthenticationWindowFocused(
        _ window: AuthenticationWindowSnapshot
    ) -> Bool? {
        switch window.identity {
        case .coreGraphics:
            return AccessibilityFocusReader.isFocusedWindow(
                processID: window.processID,
                matchingCoreGraphicsFrame: window.coreGraphicsFrame
            )
        case .accessibility:
            return AccessibilityFocusReader.isFocusedWindow(
                processID: window.processID,
                matchingCoreGraphicsFrame: window.coreGraphicsFrame
            )
        }
    }

    private func recordAuthenticationEvent(_ event: AuthenticationClientEvent) {
        recentEvents.removeAll { existing in
            existing.processID == event.processID && existing.source == event.source
        }
        recentEvents.append(event)
        let cutoff = event.receivedAt.addingTimeInterval(-10)
        recentEvents.removeAll { $0.receivedAt < cutoff }
        if recentEvents.count > 64 {
            recentEvents.removeFirst(recentEvents.count - 64)
        }
        nextProcessScanTime = 0
    }

    private func resetAttribution(firstSeenAt: Date) {
        cancelProcessScan()
        targetFirstSeenAt = firstSeenAt
        lastProcessSnapshot = .pending
        nextProcessScanTime = 0
    }

    private func cancelProcessScan() {
        guard let processScanTask else {
            return
        }
        processScanSequence += 1
        processScanTask.cancel()
        self.processScanTask = nil
    }

    private var waitingMessage: String {
        AccessibilityFocusReader.isTrusted
            ? "Waiting for an authentication dialog…"
            : "Waiting… Accessibility access is required"
    }

    private func report(message: String, isShowingPanel: Bool) {
        statusHandler(
            AuthorizationMonitorStatus(
                message: message,
                accessibilityTrusted: AccessibilityFocusReader.isTrusted,
                isShowingPanel: isShowingPanel
            )
        )
    }
}

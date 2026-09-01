import AppKit
import Foundation
import os

struct AuthorizationMonitorStatus: Equatable {
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

enum AuthenticationWindowRecovery {
    static func continuousReplacement(
        for missingWindow: AuthenticationWindowSnapshot,
        candidate: AuthenticationWindowSnapshot?
    ) -> AuthenticationWindowSnapshot? {
        guard let candidate else {
            return nil
        }
        if candidate.identity == missingWindow.identity {
            return candidate.processID == missingWindow.processID
                && candidate.surfaceKind == missingWindow.surfaceKind
                ? candidate
                : nil
        }
        guard AuthenticationWindowContinuity.representsSamePrompt(
            missingWindow,
            candidate
        ) else {
            return nil
        }
        return candidate
    }
}

enum AuthenticationWindowFocusTransition: Equatable {
    case samePrompt(AuthenticationWindowSnapshot)
    case differentPrompt(AuthenticationWindowSnapshot)
    case noCandidate

    static func resolve(
        from current: AuthenticationWindowSnapshot,
        to candidate: AuthenticationWindowSnapshot?
    ) -> AuthenticationWindowFocusTransition {
        guard let candidate else {
            return .noCandidate
        }
        if candidate.identity == current.identity {
            return candidate.processID == current.processID
                && candidate.surfaceKind == current.surfaceKind
                ? .samePrompt(candidate)
                : .differentPrompt(candidate)
        }
        if AuthenticationWindowContinuity.representsSamePrompt(current, candidate) {
            return .samePrompt(candidate)
        }
        return .differentPrompt(candidate)
    }

    var hidesCurrentPanel: Bool {
        switch self {
        case .samePrompt, .differentPrompt:
            false
        case .noCandidate:
            true
        }
    }
}

enum AuthenticationEvidenceSelection {
    static func rankedEvents(
        from events: [AuthenticationClientEvent],
        surfaceKind: AuthenticationSurfaceKind,
        firstSeenAt: Date,
        now: Date,
        maximumLeadTime: TimeInterval? = nil,
        maximumLagTime: TimeInterval = 3
    ) -> [AuthenticationClientEvent] {
        let allowedLeadTime = maximumLeadTime
            ?? (surfaceKind == .localAuthentication ? 5 : 3)
        let earliest = firstSeenAt.addingTimeInterval(-allowedLeadTime)
        let latest = min(now, firstSeenAt.addingTimeInterval(maximumLagTime))
        let requiredSource: AuthenticationEventSource = surfaceKind == .securityAgent
            ? .authorization
            : .localAuthentication
        let eligible = events.filter { event in
            event.receivedAt >= earliest
                && event.receivedAt <= latest
                && event.source == requiredSource
        }
        return eligible.sorted { lhs, rhs in
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
    private let panel: ProcessTreePanelController
    private let statusHandler: (AuthorizationMonitorStatus) -> Void
    private lazy var eventMonitor = AuthenticationEventMonitor { [weak self] event in
        self?.recordAuthenticationEvent(event)
    }
    private var timer: Timer?
    private var target: AuthenticationWindowSnapshot?
    private var promptSessions = AuthenticationPromptSessionStore()
    private var targetFirstSeenAt: Date?
    private var recentEvents: [AuthenticationClientEvent] = []
    private var lastProcessSnapshot = AuthenticationProcessSnapshot.pending
    private var nextDiscoveryTime: TimeInterval = 0
    private var nextProcessScanTime: TimeInterval = 0
    private var processScanTask: Task<Void, Never>?
    private var processScanSequence = 0
    private var promptSequence = 0
    private var observationStability = WindowObservationStability()

    init(
        displayMode: ProcessDisplayMode = .simple,
        displayModeRequestHandler: @escaping (ProcessDisplayMode) -> Void = { _ in },
        statusHandler: @escaping (AuthorizationMonitorStatus) -> Void
    ) {
        panel = ProcessTreePanelController(
            displayMode: displayMode,
            displayModeRequestHandler: displayModeRequestHandler
        )
        self.statusHandler = statusHandler
        super.init()
    }

    func setDisplayMode(_ mode: ProcessDisplayMode) {
        panel.setDisplayMode(mode)
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
        panel.recordReadiness(accessibilityTrusted: AccessibilityFocusReader.isTrusted)
        refresh(forceDiscovery: true)
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        cancelProcessScan()
        promptSessions.removeAll()
        eventMonitor.stop()
        DistributedNotificationCenter.default().removeObserver(self)
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        panel.hide(
            promptPresent: false,
            accessibilityTrusted: AccessibilityFocusReader.isTrusted
        )
    }

    @objc
    private func tick() {
        refresh(forceDiscovery: false)
    }

    @objc
    private func securityAgentDidShow(_ notification: Notification) {
        logger.notice("SecurityAgent UI notification received")
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
            promptSessions.removeAll()
            targetFirstSeenAt = nil
            lastProcessSnapshot = .pending
            observationStability.reset()
            panel.hide(promptPresent: false, accessibilityTrusted: false)
            panel.recordReadiness(accessibilityTrusted: false)
            report(isShowingPanel: false)
            return
        }
        eventMonitor.start()

        let now = ProcessInfo.processInfo.systemUptime
        let observationDate = Date()
        let visibleCoreGraphicsWindows = AuthenticationWindowLocator
            .onScreenCoreGraphicsCandidates()
        promptSessions.observeVisibleCoreGraphicsWindows(
            visibleCoreGraphicsWindows,
            at: observationDate
        )
        let frontmostCandidate = AuthenticationWindowLocator.frontmostCandidate(
            from: visibleCoreGraphicsWindows
        )

        if let currentTarget = target {
            if let frontmostCandidate {
                switch AuthenticationWindowFocusTransition.resolve(
                    from: currentTarget,
                    to: frontmostCandidate
                ) {
                case let .differentPrompt(candidate):
                    activatePrompt(candidate, at: Date())
                    logger.notice(
                        "Authentication window switched to PID \(candidate.processID, privacy: .public)"
                    )
                    updatePanel(for: candidate, now: now)
                    return
                case let .samePrompt(candidate) where candidate.identity != currentTarget.identity:
                    transferPromptSession(from: currentTarget, to: candidate, at: Date())
                    logger.notice(
                        "Authentication window representation switched for PID \(candidate.processID, privacy: .public)"
                    )
                    updatePanel(for: candidate, now: now)
                    return
                case .samePrompt, .noCandidate:
                    break
                }
            }

            guard let current = AuthenticationWindowLocator.snapshot(identity: currentTarget.identity) else {
                guard observationStability.recordMiss() else {
                    return
                }
                let candidate = frontmostCandidate
                if let replacement = AuthenticationWindowRecovery.continuousReplacement(
                    for: currentTarget,
                    candidate: candidate
                ) {
                    transferPromptSession(from: currentTarget, to: replacement, at: Date())
                    logger.notice(
                        "Authentication window representation recovered for PID \(replacement.processID, privacy: .public)"
                    )
                    updatePanel(for: replacement, now: now)
                    return
                }
                logger.notice("Authentication window closed")
                cancelProcessScan()
                promptSessions.remove(window: currentTarget)
                target = nil
                targetFirstSeenAt = nil
                lastProcessSnapshot = .pending
                observationStability.reset()
                if let candidate {
                    activatePrompt(candidate, at: Date())
                    updatePanel(for: candidate, now: now)
                    return
                }
                panel.hide(promptPresent: false, accessibilityTrusted: true)
                nextDiscoveryTime = 0
                report(isShowingPanel: false)
                return
            }
            target = current
            promptSessions.touch(window: current, at: Date())
            updatePanel(for: current, now: now)
            return
        }

        guard forceDiscovery || now >= nextDiscoveryTime else {
            return
        }
        nextDiscoveryTime = now + 0.20

        guard let candidate = frontmostCandidate else {
            panel.recordReadiness(accessibilityTrusted: true)
            report(isShowingPanel: false)
            return
        }

        activatePrompt(candidate, at: Date())
        logger.notice("Authentication window detected for PID \(candidate.processID, privacy: .public)")
        updatePanel(for: candidate, now: now)
    }

    private func updatePanel(
        for window: AuthenticationWindowSnapshot,
        now: TimeInterval,
        allowsFocusRecovery: Bool = true
    ) {
        switch isAuthenticationWindowFocused(window) {
        case true:
            observationStability.recordConfirmation()
        case false:
            observationStability.reset()
            hideForLostFocus(
                window: window,
                now: now,
                allowsFocusRecovery: allowsFocusRecovery
            )
            return
        case nil:
            guard observationStability.recordMiss() else {
                return
            }
            hideForLostFocus(
                window: window,
                now: now,
                allowsFocusRecovery: allowsFocusRecovery
            )
            return
        }

        if now >= nextProcessScanTime, processScanTask == nil {
            nextProcessScanTime = now + 0.15
            startProcessScan(for: window)
        }

        panel.show(
            snapshot: lastProcessSnapshot,
            promptSequence: promptSequence,
            surfaceKind: window.surfaceKind,
            authenticationFrame: window.frame,
            visibleFrame: window.visibleFrame
        )
        report(isShowingPanel: true)
    }

    private func hideForLostFocus(
        window: AuthenticationWindowSnapshot,
        now: TimeInterval,
        allowsFocusRecovery: Bool
    ) {
        let transition = AuthenticationWindowFocusTransition.resolve(
            from: window,
            to: AuthenticationWindowLocator.frontmostCandidate()
        )
        if allowsFocusRecovery,
           case let .samePrompt(candidate) = transition {
            transferPromptSession(from: window, to: candidate, at: Date())
            logger.notice(
                "Authentication window representation switched for PID \(candidate.processID, privacy: .public)"
            )
            updatePanel(
                for: candidate,
                now: now,
                allowsFocusRecovery: false
            )
            return
        }

        if case let .differentPrompt(candidate) = transition {
            activatePrompt(candidate, at: Date())
            logger.notice(
                "Authentication window switched to PID \(candidate.processID, privacy: .public)"
            )
            updatePanel(for: candidate, now: now)
            return
        }

        let wasPresented = panel.isPresented
        panel.hide(promptPresent: true, accessibilityTrusted: true)
        if wasPresented {
            report(isShowingPanel: false)
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
        let preferredAnchor = lastProcessSnapshot.candidates.first?.anchor
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
                self.promptSessions.update(
                    window: window,
                    processSnapshot: refreshedSnapshot,
                    at: Date()
                )
            }
        }
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
        recentEvents.append(event)
        let cutoff = event.receivedAt.addingTimeInterval(-10)
        recentEvents.removeAll { $0.receivedAt < cutoff }
        if recentEvents.count > 64 {
            recentEvents.removeFirst(recentEvents.count - 64)
        }
        nextProcessScanTime = 0
    }

    private func activatePrompt(
        _ window: AuthenticationWindowSnapshot,
        at date: Date
    ) {
        cancelProcessScan()
        let session = promptSessions.activate(window: window, at: date)
        target = window
        targetFirstSeenAt = session.firstSeenAt
        promptSequence = session.promptSequence
        lastProcessSnapshot = session.processSnapshot
        nextProcessScanTime = 0
        observationStability.reset()
    }

    private func transferPromptSession(
        from oldWindow: AuthenticationWindowSnapshot,
        to newWindow: AuthenticationWindowSnapshot,
        at date: Date
    ) {
        cancelProcessScan()
        let session = promptSessions.transfer(
            from: oldWindow,
            to: newWindow,
            at: date
        )
        target = newWindow
        targetFirstSeenAt = session.firstSeenAt
        promptSequence = session.promptSequence
        lastProcessSnapshot = session.processSnapshot
        nextProcessScanTime = 0
        observationStability.reset()
    }

    private func cancelProcessScan() {
        guard let processScanTask else {
            return
        }
        processScanSequence += 1
        processScanTask.cancel()
        self.processScanTask = nil
    }

    private func report(isShowingPanel: Bool) {
        statusHandler(
            AuthorizationMonitorStatus(
                accessibilityTrusted: AccessibilityFocusReader.isTrusted,
                isShowingPanel: isShowingPanel
            )
        )
    }
}

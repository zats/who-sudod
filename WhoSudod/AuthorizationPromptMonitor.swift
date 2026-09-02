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

enum AuthenticationWindowDiscoveryPolicy {
    static let fallbackInterval: TimeInterval = 0.20

    static func shouldInspectCoreGraphics(
        forceDiscovery: Bool,
        hasActiveSystemPrompt: Bool,
        isInFastDiscoveryBurst: Bool,
        now: TimeInterval,
        nextFallbackTime: TimeInterval
    ) -> Bool {
        forceDiscovery
            || hasActiveSystemPrompt
            || isInFastDiscoveryBurst
            || now >= nextFallbackTime
    }
}

enum TerminalPromptObservationResolution: Equatable {
    case keepCurrent
    case waitForCurrent
    case select(ProcessIdentity)
    case endCurrent
    case noSelection

    static func resolve(
        current: ProcessIdentity?,
        observed: [ProcessIdentity],
        active: [ProcessIdentity],
        currentMissConfirmed: Bool
    ) -> TerminalPromptObservationResolution {
        guard let current else {
            return active.first.map(Self.select) ?? .noSelection
        }
        if observed.contains(current) {
            if active.contains(current) {
                return .keepCurrent
            }
            if let replacement = active.first {
                return .select(replacement)
            }
            return .keepCurrent
        }
        guard currentMissConfirmed else {
            return .waitForCurrent
        }
        return active.first.map(Self.select) ?? .endCurrent
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
    private let ignoredApplications: IgnoredApplicationsStore
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
    private var terminalPromptScanTask: Task<Void, Never>?
    private var terminalPromptScanSequence = 0
    private var terminalPromptIdentity: ProcessIdentity?
    private var terminalPromptWindow: TerminalPromptWindowSnapshot?
    private var nextTerminalPromptScanTime: TimeInterval = 0
    private var nextTerminalPromptSequence = -1
    private var promptSequence = 0
    private var observationStability = WindowObservationStability()
    private var terminalPromptStability = WindowObservationStability()
    private var lastReportedStatus: AuthorizationMonitorStatus?
    private var fastCoreGraphicsDiscoveryUntil: TimeInterval = 0
    private var frontmostApplicationProcessID: pid_t?
    private var isCurrentSystemPromptIgnored = false

    init(
        displayMode: ProcessDisplayMode = .simple,
        ignoredApplications: IgnoredApplicationsStore,
        displayModeRequestHandler: @escaping (ProcessDisplayMode) -> Void = { _ in },
        statusHandler: @escaping (AuthorizationMonitorStatus) -> Void
    ) {
        panel = ProcessTreePanelController(
            displayMode: displayMode,
            displayModeRequestHandler: displayModeRequestHandler
        )
        self.ignoredApplications = ignoredApplications
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
        NSWorkspace.shared.notificationCenter.addObserver(
            self,
            selector: #selector(runningApplicationsDidChange),
            name: NSWorkspace.didLaunchApplicationNotification,
            object: nil
        )
        NSWorkspace.shared.notificationCenter.addObserver(
            self,
            selector: #selector(runningApplicationsDidChange),
            name: NSWorkspace.didTerminateApplicationNotification,
            object: nil
        )
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(screenParametersDidChange),
            name: NSApplication.didChangeScreenParametersNotification,
            object: nil
        )

        AuthenticationWindowLocator.invalidateDisplayCache()
        frontmostApplicationProcessID = NSWorkspace.shared.frontmostApplication?
            .processIdentifier
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
        cancelTerminalPromptScan()
        resetTerminalPrompt(hidePanel: false, promptPresent: false)
        promptSessions.removeAll()
        eventMonitor.stop()
        DistributedNotificationCenter.default().removeObserver(self)
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        NotificationCenter.default.removeObserver(self)
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
        beginFastDiscoveryBurst()
        refresh(forceDiscovery: true)
    }

    @objc
    private func frontmostApplicationDidChange(_ notification: Notification) {
        frontmostApplicationProcessID = (
            notification.userInfo?[NSWorkspace.applicationUserInfoKey]
                as? NSRunningApplication
        )?.processIdentifier
            ?? NSWorkspace.shared.frontmostApplication?.processIdentifier
        refresh(forceDiscovery: true)
    }

    @objc
    private func runningApplicationsDidChange() {
        refresh(forceDiscovery: true)
    }

    @objc
    private func screenParametersDidChange() {
        AuthenticationWindowLocator.invalidateDisplayCache()
        refresh(forceDiscovery: true)
    }

    private func refresh(forceDiscovery: Bool) {
        guard AccessibilityFocusReader.isTrusted else {
            eventMonitor.stop()
            cancelProcessScan()
            cancelTerminalPromptScan()
            target = nil
            terminalPromptIdentity = nil
            terminalPromptWindow = nil
            promptSessions.removeAll()
            targetFirstSeenAt = nil
            lastProcessSnapshot = .pending
            isCurrentSystemPromptIgnored = false
            observationStability.reset()
            terminalPromptStability.reset()
            panel.hide(promptPresent: false, accessibilityTrusted: false)
            panel.recordReadiness(accessibilityTrusted: false)
            report(isShowingPanel: false)
            return
        }
        eventMonitor.start()

        let now = ProcessInfo.processInfo.systemUptime
        let inspectsCoreGraphics = AuthenticationWindowDiscoveryPolicy
            .shouldInspectCoreGraphics(
                forceDiscovery: forceDiscovery,
                hasActiveSystemPrompt: target != nil,
                isInFastDiscoveryBurst: now < fastCoreGraphicsDiscoveryUntil,
                now: now,
                nextFallbackTime: nextDiscoveryTime
            )
        let frontmostCandidate: AuthenticationWindowSnapshot?
        if inspectsCoreGraphics {
            if target == nil {
                nextDiscoveryTime = now + AuthenticationWindowDiscoveryPolicy.fallbackInterval
            }
            let observationDate = Date()
            let visibleCoreGraphicsWindows = AuthenticationWindowLocator
                .onScreenCoreGraphicsCandidates()
            promptSessions.observeVisibleCoreGraphicsWindows(
                visibleCoreGraphicsWindows,
                at: observationDate
            )
            let visibleAccessibilityWindows = promptSessions.accessibilityWindowIdentities
                .compactMap { AuthenticationWindowLocator.snapshot(identity: $0) }
            promptSessions.observeVisibleAccessibilityWindows(
                visibleAccessibilityWindows,
                at: observationDate
            )
            frontmostCandidate = AuthenticationWindowLocator.frontmostCandidate(
                from: visibleCoreGraphicsWindows,
                frontmostProcessID: frontmostApplicationProcessID
            )
        } else {
            frontmostCandidate = AuthenticationWindowLocator
                .frontmostAccessibilityCandidate(
                    processID: frontmostApplicationProcessID
                )
        }

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
                isCurrentSystemPromptIgnored = false
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

        if terminalPromptIdentity != nil {
            if let candidate = frontmostCandidate {
                resetTerminalPrompt(hidePanel: false, promptPresent: true)
                activatePrompt(candidate, at: Date())
                logger.notice(
                    "Authentication window replaced terminal password prompt for PID \(candidate.processID, privacy: .public)"
                )
                updatePanel(for: candidate, now: now)
                return
            }
            updateTerminalPrompt(now: now)
            return
        }

        if let candidate = frontmostCandidate {
            activatePrompt(candidate, at: Date())
            logger.notice("Authentication window detected for PID \(candidate.processID, privacy: .public)")
            updatePanel(for: candidate, now: now)
            return
        }

        startTerminalPromptScanIfNeeded(now: now)
        guard inspectsCoreGraphics else {
            return
        }
        panel.recordReadiness(accessibilityTrusted: true)
        report(isShowingPanel: false)
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

        guard !isCurrentSystemPromptIgnored else {
            let wasPresented = panel.isPresented
            panel.hide(promptPresent: true, accessibilityTrusted: true)
            if wasPresented {
                report(isShowingPanel: false)
            }
            return
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
            to: AuthenticationWindowLocator.frontmostCandidate(
                frontmostProcessID: frontmostApplicationProcessID
            )
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

        cancelProcessScan()
        target = nil
        targetFirstSeenAt = nil
        lastProcessSnapshot = .pending
        isCurrentSystemPromptIgnored = false
        observationStability.reset()
        nextDiscoveryTime = 0
        let wasPresented = panel.isPresented
        panel.hide(promptPresent: true, accessibilityTrusted: true)
        if wasPresented {
            report(isShowingPanel: false)
        }
        startTerminalPromptScanIfNeeded(now: now)
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

            let visibleCurrent = IgnoredApplicationsPolicy.filtering(
                self.lastProcessSnapshot,
                by: self.ignoredApplications.rules
            )
            let visibleNewSnapshot = IgnoredApplicationsPolicy.filtering(
                newSnapshot,
                by: self.ignoredApplications.rules
            )
            let refreshedSnapshot = ProcessSnapshotSelection.refreshingLive(
                current: visibleCurrent,
                observed: visibleNewSnapshot
            )
            self.isCurrentSystemPromptIgnored = !newSnapshot.candidates.isEmpty
                && visibleNewSnapshot.candidates.isEmpty
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
            self.updatePanel(
                for: window,
                now: ProcessInfo.processInfo.systemUptime
            )
        }
    }

    private func updateTerminalPrompt(now: TimeInterval) {
        startTerminalPromptScanIfNeeded(now: now)
        guard let identity = terminalPromptIdentity,
              let chain = lastProcessSnapshot.candidates.first(where: {
                  $0.requesterProcess.identity == identity
              }) else {
            hideTerminalPromptPanel()
            return
        }
        let focusedWindow = TerminalPromptWindowLocator.focusedWindow(
            for: chain,
            preserving: terminalPromptWindow
        )
        guard let focusedWindow else {
            hideTerminalPromptPanel()
            return
        }

        self.terminalPromptWindow = focusedWindow
        panel.showStandalone(
            snapshot: AuthenticationProcessSnapshot(
                candidates: [chain],
                inspectionState: lastProcessSnapshot.inspectionState
            ),
            promptSequence: promptSequence,
            anchorFrame: focusedWindow.frame,
            visibleFrame: focusedWindow.visibleFrame
        )
        report(isShowingPanel: true)
    }

    private func hideTerminalPromptPanel() {
        let wasPresented = panel.isPresented
        panel.hide(promptPresent: true, accessibilityTrusted: true)
        if wasPresented {
            report(isShowingPanel: false)
        }
    }

    private func startTerminalPromptScanIfNeeded(now: TimeInterval) {
        guard target == nil,
              terminalPromptScanTask == nil,
              now >= nextTerminalPromptScanTime else {
            return
        }
        nextTerminalPromptScanTime = now + 0.10
        terminalPromptScanSequence += 1
        let sequence = terminalPromptScanSequence
        let preferredAnchor = terminalPromptIdentity.flatMap { identity in
            lastProcessSnapshot.candidates.first(where: {
                $0.requesterProcess.identity == identity
            })?.anchor
        }
        terminalPromptScanTask = Task { [weak self, scanner] in
            let unfilteredObserved = await scanner.terminalPasswordSudoSnapshot(
                preferredAnchor: preferredAnchor
            )
            guard !Task.isCancelled,
                  let self,
                  self.terminalPromptScanSequence == sequence else {
                return
            }
            self.terminalPromptScanTask = nil
            guard self.target == nil else {
                return
            }
            let observed = IgnoredApplicationsPolicy.filtering(
                unfilteredObserved,
                by: self.ignoredApplications.rules
            )

            let observedIdentities = observed.candidates.map {
                $0.requesterProcess.identity
            }
            let currentWasObserved = self.terminalPromptIdentity.map {
                observedIdentities.contains($0)
            } ?? false
            let currentMissConfirmed: Bool
            if self.terminalPromptIdentity == nil || currentWasObserved {
                self.terminalPromptStability.recordConfirmation()
                currentMissConfirmed = false
            } else {
                currentMissConfirmed = self.terminalPromptStability.recordMiss()
            }

            var activeWindows: [ProcessIdentity: TerminalPromptWindowSnapshot] = [:]
            for chain in observed.candidates {
                let identity = chain.requesterProcess.identity
                let window: TerminalPromptWindowSnapshot?
                if identity == self.terminalPromptIdentity {
                    window = TerminalPromptWindowLocator.focusedWindow(
                        for: chain,
                        preserving: self.terminalPromptWindow
                    )
                } else {
                    window = TerminalPromptWindowLocator.focusedWindow(for: chain)
                }
                if let window {
                    activeWindows[identity] = window
                }
            }
            let activeIdentities = observedIdentities.filter {
                activeWindows[$0] != nil
            }
            let resolution = TerminalPromptObservationResolution.resolve(
                current: self.terminalPromptIdentity,
                observed: observedIdentities,
                active: activeIdentities,
                currentMissConfirmed: currentMissConfirmed
            )

            switch resolution {
            case .keepCurrent:
                guard let currentIdentity = self.terminalPromptIdentity,
                      let chain = observed.candidates.first(where: {
                          $0.requesterProcess.identity == currentIdentity
                      }) else {
                    return
                }
                self.lastProcessSnapshot = AuthenticationProcessSnapshot(
                    candidates: [chain],
                    inspectionState: observed.inspectionState
                )
                if let activeWindow = activeWindows[currentIdentity] {
                    self.terminalPromptWindow = activeWindow
                }
                self.updateTerminalPrompt(now: ProcessInfo.processInfo.systemUptime)
            case .waitForCurrent:
                self.updateTerminalPrompt(now: ProcessInfo.processInfo.systemUptime)
            case let .select(identity):
                guard let chain = observed.candidates.first(where: {
                    $0.requesterProcess.identity == identity
                }), let window = activeWindows[identity] else {
                    return
                }
                self.terminalPromptStability.recordConfirmation()
                self.terminalPromptIdentity = identity
                self.terminalPromptWindow = window
                self.promptSequence = self.nextTerminalPromptSequence
                self.nextTerminalPromptSequence -= 1
                self.lastProcessSnapshot = AuthenticationProcessSnapshot(
                    candidates: [chain],
                    inspectionState: observed.inspectionState
                )
                self.logger.notice(
                    "Terminal password sudo detected for PID \(chain.requesterProcess.pid, privacy: .public)"
                )
                self.updateTerminalPrompt(now: ProcessInfo.processInfo.systemUptime)
            case .endCurrent:
                self.logger.notice("Terminal password sudo ended")
                self.resetTerminalPrompt(hidePanel: true, promptPresent: false)
            case .noSelection:
                break
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
        beginFastDiscoveryBurst()
        refresh(forceDiscovery: true)
    }

    private func beginFastDiscoveryBurst() {
        let now = ProcessInfo.processInfo.systemUptime
        fastCoreGraphicsDiscoveryUntil = max(
            fastCoreGraphicsDiscoveryUntil,
            now + 0.75
        )
    }

    private func activatePrompt(
        _ window: AuthenticationWindowSnapshot,
        at date: Date
    ) {
        cancelProcessScan()
        cancelTerminalPromptScan()
        terminalPromptIdentity = nil
        terminalPromptWindow = nil
        terminalPromptStability.reset()
        let session = promptSessions.activate(window: window, at: date)
        target = window
        targetFirstSeenAt = session.firstSeenAt
        promptSequence = session.promptSequence
        lastProcessSnapshot = IgnoredApplicationsPolicy.filtering(
            session.processSnapshot,
            by: ignoredApplications.rules
        )
        isCurrentSystemPromptIgnored = !session.processSnapshot.candidates.isEmpty
            && lastProcessSnapshot.candidates.isEmpty
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
        lastProcessSnapshot = IgnoredApplicationsPolicy.filtering(
            session.processSnapshot,
            by: ignoredApplications.rules
        )
        isCurrentSystemPromptIgnored = !session.processSnapshot.candidates.isEmpty
            && lastProcessSnapshot.candidates.isEmpty
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

    private func cancelTerminalPromptScan() {
        guard let terminalPromptScanTask else {
            return
        }
        terminalPromptScanSequence += 1
        terminalPromptScanTask.cancel()
        self.terminalPromptScanTask = nil
    }

    private func resetTerminalPrompt(
        hidePanel: Bool,
        promptPresent: Bool
    ) {
        cancelTerminalPromptScan()
        terminalPromptIdentity = nil
        terminalPromptWindow = nil
        terminalPromptStability.reset()
        nextTerminalPromptScanTime = 0
        lastProcessSnapshot = .pending
        if hidePanel {
            panel.hide(
                promptPresent: promptPresent,
                accessibilityTrusted: AccessibilityFocusReader.isTrusted
            )
            report(isShowingPanel: false)
        }
    }

    private func report(isShowingPanel: Bool) {
        let status = AuthorizationMonitorStatus(
            accessibilityTrusted: AccessibilityFocusReader.isTrusted,
            isShowingPanel: isShowingPanel
        )
        guard status != lastReportedStatus else {
            return
        }
        lastReportedStatus = status
        statusHandler(status)
    }
}

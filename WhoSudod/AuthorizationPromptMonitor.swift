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
            return (active.first ?? observed.first).map(Self.select)
                ?? .noSelection
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
        return (active.first ?? observed.first).map(Self.select)
            ?? .endCurrent
    }
}

struct TerminalPromptSuppressionState {
    private(set) var userDismissed: Set<ProcessIdentity> = []
    private(set) var completedPAMRequests: Set<ProcessIdentity> = []

    func allowsVerifiedPAMRequest(_ identity: ProcessIdentity) -> Bool {
        !userDismissed.contains(identity)
    }

    func suppressesHeuristicPrompt(_ identity: ProcessIdentity) -> Bool {
        userDismissed.contains(identity) || completedPAMRequests.contains(identity)
    }

    func suppressesActivePAMRequest(_ identity: ProcessIdentity) -> Bool {
        userDismissed.contains(identity)
    }

    mutating func beginVerifiedPAMRequest(_ identity: ProcessIdentity) -> Bool {
        guard allowsVerifiedPAMRequest(identity) else {
            return false
        }
        completedPAMRequests.remove(identity)
        return true
    }

    mutating func recordPAMCompletion(_ identity: ProcessIdentity) {
        completedPAMRequests.insert(identity)
    }

    mutating func recordUserDismissal(_ identity: ProcessIdentity) {
        userDismissed.insert(identity)
    }

    mutating func refresh(
        observed: Set<ProcessIdentity>,
        isRunning: (ProcessIdentity) -> Bool
    ) {
        let shouldRetain: (ProcessIdentity) -> Bool = {
            observed.contains($0) || isRunning($0)
        }
        userDismissed = Set(userDismissed.filter(shouldRetain))
        completedPAMRequests = Set(completedPAMRequests.filter(shouldRetain))
    }

    mutating func removeAll() {
        userDismissed.removeAll()
        completedPAMRequests.removeAll()
    }
}

enum PAMRequestReplacementPolicy {
    static func canSupersede(
        activeRequest: PAMPasswordRequest,
        activeIdentity: ProcessIdentity,
        incomingRequest: PAMPasswordRequest,
        currentIdentity: ProcessIdentity?
    ) -> Bool {
        activeRequest.identifier != incomingRequest.identifier
            && activeRequest.processID == incomingRequest.processID
            && activeRequest.realUserID == incomingRequest.realUserID
            && activeIdentity.pid == incomingRequest.processID
            && currentIdentity == activeIdentity
    }
}

enum AuthenticationCompletionHistory {
    static func recordBegin(
        _ requestIdentifier: AuthenticationRequestIdentifier?,
        in completedRequests: inout [AuthenticationRequestIdentifier: Date]
    ) {
        guard let requestIdentifier else {
            return
        }
        completedRequests.removeValue(forKey: requestIdentifier)
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

enum AuthenticationWindowAbsenceResolution: Equatable {
    case retain
    case countMiss
    case endImmediately

    static func resolve(
        presenterIsRunning: Bool,
        presenterIsActive: Bool,
        requesterIsFrontmost: Bool
    ) -> AuthenticationWindowAbsenceResolution {
        guard presenterIsRunning else {
            return .endImmediately
        }
        return presenterIsActive || requesterIsFrontmost
            ? .countMiss
            : .retain
    }
}

enum SystemPromptTeardownPolicy {
    static func shouldEnd(
        requestHasCompleted: Bool,
        requesterIsRunning: Bool,
        promptIsObserved: Bool
    ) -> Bool {
        requestHasCompleted || (!requesterIsRunning && !promptIsObserved)
    }

    static func shouldEnd(
        requestHasCompleted: Bool,
        requesterIsRunning: Bool,
        promptKey: AuthenticationPromptSessionKey,
        observedPromptKeys: Set<AuthenticationPromptSessionKey>
    ) -> Bool {
        shouldEnd(
            requestHasCompleted: requestHasCompleted,
            requesterIsRunning: requesterIsRunning,
            promptIsObserved: observedPromptKeys.contains(promptKey)
        )
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
        if AuthenticationWindowContinuity.representsSamePrompt(
            current,
            candidate
        ) {
            return .samePrompt(candidate)
        }
        return .differentPrompt(candidate)
    }
}

enum CoveredSystemPromptSelection {
    static func replacement(
        frontmost: AuthenticationWindowSnapshot?,
        observed: [AuthenticationWindowSnapshot],
        coveredKeys: [AuthenticationPromptSessionKey],
        excluding endedKey: AuthenticationPromptSessionKey
    ) -> AuthenticationWindowSnapshot? {
        if let frontmost,
           AuthenticationPromptSessionKey(window: frontmost) != endedKey {
            return frontmost
        }
        for key in coveredKeys.reversed() where key != endedKey {
            if let match = observed.first(where: {
                AuthenticationPromptSessionKey(window: $0) == key
            }) {
                return match
            }
        }
        return nil
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

enum AuthenticationRequestAssociation {
    static func unassignedActiveIdentifier(
        requesterProcessID: pid_t,
        evidence: [AuthenticationClientEvent],
        completedIdentifiers: Set<AuthenticationRequestIdentifier>,
        existingMappings: [
            AuthenticationPromptSessionKey: AuthenticationRequestIdentifier
        ],
        promptKey: AuthenticationPromptSessionKey
    ) -> AuthenticationRequestIdentifier? {
        let identifiersUsedByOtherPrompts = Set(
            existingMappings.compactMap { key, identifier in
                key == promptKey ? nil : identifier
            }
        )
        let eligibleIdentifiers = Set(
            evidence.compactMap { event -> AuthenticationRequestIdentifier? in
                guard event.processID == requesterProcessID,
                      let identifier = event.requestIdentifier,
                      !completedIdentifiers.contains(identifier),
                      !identifiersUsedByOtherPrompts.contains(identifier) else {
                    return nil
                }
                return identifier
            }
        )
        guard eligibleIdentifiers.count == 1 else {
            return nil
        }
        return eligibleIdentifiers.first
    }

    static func unassignedCompletedIdentifier(
        requesterProcessID: pid_t,
        evidence: [AuthenticationClientEvent],
        currentEvidence: [AuthenticationClientEvent],
        completedIdentifiers: Set<AuthenticationRequestIdentifier>,
        existingMappings: [
            AuthenticationPromptSessionKey: AuthenticationRequestIdentifier
        ],
        promptKey: AuthenticationPromptSessionKey
    ) -> AuthenticationRequestIdentifier? {
        let identifiersUsedByOtherPrompts = Set(
            existingMappings.compactMap { key, identifier in
                key == promptKey ? nil : identifier
            }
        )
        let matchingIdentifiers = Set(
            evidence.compactMap { event -> AuthenticationRequestIdentifier? in
                guard event.processID == requesterProcessID,
                      let identifier = event.requestIdentifier,
                      !identifiersUsedByOtherPrompts.contains(identifier) else {
                    return nil
                }
                return identifier
            }
        )
        guard matchingIdentifiers.count == 1,
              let identifier = matchingIdentifiers.first,
              completedIdentifiers.contains(identifier) else {
            return nil
        }
        let competingActiveIdentifierExists = currentEvidence.contains { event in
            guard event.processID == requesterProcessID else {
                return false
            }
            guard let currentIdentifier = event.requestIdentifier else {
                return true
            }
            return currentIdentifier != identifier
                && !completedIdentifiers.contains(currentIdentifier)
        }
        guard !competingActiveIdentifierExists else {
            return nil
        }
        return identifier
    }

    static func transferMapping(
        in mappings: inout [
            AuthenticationPromptSessionKey: AuthenticationRequestIdentifier
        ],
        from oldKey: AuthenticationPromptSessionKey,
        to newKey: AuthenticationPromptSessionKey
    ) {
        guard oldKey != newKey else {
            return
        }
        let previousIdentifier = mappings.removeValue(forKey: oldKey)
        if mappings[newKey] == nil,
           let previousIdentifier {
            mappings[newKey] = previousIdentifier
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
    private struct ActivePAMPasswordRequest {
        let request: PAMPasswordRequest
        let lease: PAMConversationLease
        let snapshot: AuthenticationProcessSnapshot
        var terminalWindow: TerminalPromptWindowSnapshot?
        let promptSequence: Int
        var offersAppInput: Bool
        let passwordHandler: @MainActor (Data) -> Void
        let useTerminalHandler: @MainActor () -> Void
    }
    private struct SuspendedTerminalPrompt {
        let identity: ProcessIdentity
        let snapshot: AuthenticationProcessSnapshot
        let terminalWindow: TerminalPromptWindowSnapshot?
        let promptSequence: Int
    }
    private lazy var eventMonitor = AuthenticationEventMonitor { [weak self] event in
        self?.recordAuthenticationEvent(event)
    }
    private var timer: Timer?
    private var target: AuthenticationWindowSnapshot?
    private var promptSessions = AuthenticationPromptSessionStore()
    private var coveredSystemPromptKeys: [AuthenticationPromptSessionKey] = []
    private var requestIdentifiersByPromptKey: [
        AuthenticationPromptSessionKey: AuthenticationRequestIdentifier
    ] = [:]
    private var completedRequestIdentifiers: [AuthenticationRequestIdentifier: Date] = [:]
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
    private var activeNotchVisibleFrame: CGRect?
    private var nextActiveNotchScreenCheckTime: TimeInterval = 0
    private var isCurrentSystemPromptIgnored = false
    private var activePAMPasswordRequest: ActivePAMPasswordRequest?
    private var pendingPAMPasswordRequestIdentifier: PAMRequestIdentifier?
    private var terminalPromptSuppression = TerminalPromptSuppressionState()
    private var suspendedTerminalPrompt: SuspendedTerminalPrompt?

    init(
        displayMode: ProcessDisplayMode = .simple,
        ignoredApplications: IgnoredApplicationsStore,
        displayModeRequestHandler: @escaping (ProcessDisplayMode) -> Void = { _ in },
        pamSetupActionProvider: @escaping @MainActor () -> PAMNotchAction? = { nil },
        pamSetupActionHandler: @escaping @MainActor (PAMSettingsAction) -> Void = { _ in },
        statusHandler: @escaping (AuthorizationMonitorStatus) -> Void
    ) {
        panel = ProcessTreePanelController(
            displayMode: displayMode,
            displayModeRequestHandler: displayModeRequestHandler,
            pamSetupActionProvider: pamSetupActionProvider,
            pamSetupActionHandler: pamSetupActionHandler
        )
        self.ignoredApplications = ignoredApplications
        self.statusHandler = statusHandler
        super.init()
        panel.onNotchDismissRequest = { [weak self] in
            self?.dismissVisibleNotch()
        }
    }

    func setDisplayMode(_ mode: ProcessDisplayMode) {
        panel.setDisplayMode(mode)
    }

    func offerPAMPasswordRequest(
        _ request: PAMPasswordRequest,
        lease: PAMConversationLease,
        passwordHandler: @escaping @MainActor (Data) -> Void,
        useTerminalHandler: @escaping @MainActor () -> Void
    ) async -> Bool {
        guard lease.isActive,
              AccessibilityFocusReader.isTrusted,
              PAMPromptPolicy.isAccountPasswordPrompt(request.prompt) else {
            return false
        }
        if let active = activePAMPasswordRequest {
            if active.request.identifier == request.identifier {
                return active.offersAppInput
            }
            guard let activeIdentity = active.snapshot.candidates.first?
                .requesterProcess.identity,
                  PAMRequestReplacementPolicy.canSupersede(
                      activeRequest: active.request,
                      activeIdentity: activeIdentity,
                      incomingRequest: request,
                      currentIdentity: ProcessIdentityLiveness.currentIdentity(
                          processID: request.processID
                      )
                  ) else {
                return false
            }
            panel.dismissVerifiedPAMPasswordRequest(active.request.identifier.uuid)
            activePAMPasswordRequest = nil
            logger.notice(
                "Superseding a completed PAM conversation for PID \(request.processID, privacy: .public)"
            )
        }
        guard pendingPAMPasswordRequestIdentifier == nil else {
            return false
        }
        let retainedTerminalIdentity = terminalPromptIdentity
        let retainedTerminalWindow = terminalPromptWindow
            ?? frontmostApplicationProcessID.flatMap {
                TerminalPromptWindowLocator.focusedWindow(processID: $0)
            }
        let retainedPromptSequence = promptSequence
        pendingPAMPasswordRequestIdentifier = request.identifier
        defer {
            if pendingPAMPasswordRequestIdentifier == request.identifier {
                pendingPAMPasswordRequestIdentifier = nil
            }
        }

        let observed = await scanner.pamSudoSnapshot(
            processID: request.processID,
            realUserID: request.realUserID
        )
        guard pendingPAMPasswordRequestIdentifier == request.identifier,
              lease.isActive,
              activePAMPasswordRequest == nil,
              let unfilteredChain = observed.candidates.first,
              unfilteredChain.requesterProcess.pid == request.processID,
              terminalPromptSuppression.allowsVerifiedPAMRequest(
                  unfilteredChain.requesterProcess.identity
              ) else {
            return false
        }
        let filtered = IgnoredApplicationsPolicy.filtering(
            observed,
            by: ignoredApplications.rules
        )
        let chain = filtered.candidates.first
        let preservedWindow: TerminalPromptWindowSnapshot?
        if let retainedTerminalWindow,
           chain?.requesterProcess.identity == retainedTerminalIdentity {
            preservedWindow = retainedTerminalWindow
        } else if let retainedTerminalWindow,
                  chain?.processes.contains(where: {
                      $0.pid == retainedTerminalWindow.processID
                  }) == true {
            preservedWindow = retainedTerminalWindow
        } else if chain?.requesterProcess.identity == terminalPromptIdentity {
            preservedWindow = terminalPromptWindow
        } else if chain?.requesterProcess.identity == suspendedTerminalPrompt?.identity {
            preservedWindow = suspendedTerminalPrompt?.terminalWindow
        } else {
            preservedWindow = nil
        }
        guard pendingPAMPasswordRequestIdentifier == request.identifier,
              lease.isActive,
              activePAMPasswordRequest == nil,
              let chain else {
            return false
        }
        let terminalWindow = TerminalPromptWindowLocator.retainedWindow(
            for: chain,
            preserving: preservedWindow
        )

        guard pendingPAMPasswordRequestIdentifier == request.identifier,
              lease.isActive,
              activePAMPasswordRequest == nil,
              terminalPromptSuppression.beginVerifiedPAMRequest(
                  chain.requesterProcess.identity
              ) else {
            return false
        }

        cancelTerminalPromptScan()
        terminalPromptStability.recordConfirmation()
        let passwordPromptSequence: Int
        if retainedTerminalIdentity == chain.requesterProcess.identity {
            passwordPromptSequence = retainedPromptSequence
        } else if terminalPromptIdentity == chain.requesterProcess.identity {
            passwordPromptSequence = promptSequence
        } else if let suspendedTerminalPrompt,
                  suspendedTerminalPrompt.identity == chain.requesterProcess.identity {
            passwordPromptSequence = suspendedTerminalPrompt.promptSequence
        } else {
            passwordPromptSequence = nextTerminalPromptSequence
            nextTerminalPromptSequence -= 1
        }
        let passwordSnapshot = AuthenticationProcessSnapshot(
            candidates: [chain],
            inspectionState: filtered.inspectionState
        )
        suspendedTerminalPrompt = nil
        let activeRequest = ActivePAMPasswordRequest(
            request: request,
            lease: lease,
            snapshot: passwordSnapshot,
            terminalWindow: terminalWindow,
            promptSequence: passwordPromptSequence,
            offersAppInput: true,
            passwordHandler: passwordHandler,
            useTerminalHandler: useTerminalHandler
        )
        activePAMPasswordRequest = activeRequest
        if target == nil {
            cancelProcessScan()
            terminalPromptIdentity = chain.requesterProcess.identity
            self.terminalPromptWindow = terminalWindow
            promptSequence = passwordPromptSequence
            lastProcessSnapshot = passwordSnapshot
            presentPAMPasswordRequest(activeRequest)
        }
        guard lease.isActive,
              activePAMPasswordRequest?.request.identifier == request.identifier else {
            panel.dismissVerifiedPAMPasswordRequest(request.identifier.uuid)
            if activePAMPasswordRequest?.request.identifier == request.identifier {
                activePAMPasswordRequest = nil
            }
            if target == nil {
                resetTerminalPrompt(hidePanel: true, promptPresent: false)
            }
            return false
        }
        if target == nil {
            report(isShowingPanel: true)
        }
        logger.notice(
            "Verified PAM password request received for PID \(request.processID, privacy: .public)"
        )
        return true
    }

    func endPAMPasswordRequest(_ requestIdentifier: PAMRequestIdentifier) {
        if pendingPAMPasswordRequestIdentifier == requestIdentifier {
            pendingPAMPasswordRequestIdentifier = nil
        }
        guard let active = activePAMPasswordRequest,
              active.request.identifier == requestIdentifier else {
            return
        }
        if let identity = active.snapshot.candidates.first?.requesterProcess.identity {
            terminalPromptSuppression.recordPAMCompletion(identity)
        }
        panel.dismissVerifiedPAMPasswordRequest(requestIdentifier.uuid)
        activePAMPasswordRequest = nil
        suspendedTerminalPrompt = nil
        logger.notice(
            "Verified PAM password request ended for PID \(active.request.processID, privacy: .public)"
        )
        if target == nil {
            resetTerminalPrompt(hidePanel: true, promptPresent: false)
        }
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
        pendingPAMPasswordRequestIdentifier = nil
        terminalPromptSuppression.removeAll()
        suspendedTerminalPrompt = nil
        abandonActivePAMPasswordRequest()
        resetTerminalPrompt(hidePanel: false, promptPresent: false)
        promptSessions.removeAll()
        coveredSystemPromptKeys.removeAll()
        resetAuthenticationEventCorrelation()
        eventMonitor.stop()
        DistributedNotificationCenter.default().removeObserver(self)
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        NotificationCenter.default.removeObserver(self)
        panel.hide(
            promptPresent: false,
            accessibilityTrusted: AccessibilityFocusReader.isTrusted
        )
    }

    private func dismissVisibleNotch() {
        guard panel.isNotchPresented else {
            return
        }

        if var active = activePAMPasswordRequest,
           let identity = active.snapshot.candidates.first?.requesterProcess.identity {
            terminalPromptSuppression.recordUserDismissal(identity)
            if active.offersAppInput {
                active.offersAppInput = false
                activePAMPasswordRequest = active
                active.useTerminalHandler()
            }
        } else if let terminalPromptIdentity {
            terminalPromptSuppression.recordUserDismissal(terminalPromptIdentity)
        }

        panel.hide(promptPresent: true, accessibilityTrusted: true)
        report(isShowingPanel: false)
        logger.notice("Notch dismissed by user")
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
        activeNotchVisibleFrame = nil
        nextActiveNotchScreenCheckTime = 0
        refresh(forceDiscovery: true)
    }

    private func refresh(forceDiscovery: Bool) {
        guard AccessibilityFocusReader.isTrusted else {
            eventMonitor.stop()
            cancelProcessScan()
            cancelTerminalPromptScan()
            abandonActivePAMPasswordRequest()
            target = nil
            terminalPromptIdentity = nil
            terminalPromptWindow = nil
            suspendedTerminalPrompt = nil
            promptSessions.removeAll()
            coveredSystemPromptKeys.removeAll()
            resetAuthenticationEventCorrelation()
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
        updateActiveNotchScreenIfNeeded(now: now, force: forceDiscovery)
        let inspectsCoreGraphics = AuthenticationWindowDiscoveryPolicy
            .shouldInspectCoreGraphics(
                forceDiscovery: forceDiscovery,
                hasActiveSystemPrompt: target != nil,
                isInFastDiscoveryBurst: now < fastCoreGraphicsDiscoveryUntil,
                now: now,
                nextFallbackTime: nextDiscoveryTime
            )
        let frontmostCandidate: AuthenticationWindowSnapshot?
        let observedSystemWindows: [AuthenticationWindowSnapshot]
        if inspectsCoreGraphics {
            if target == nil {
                nextDiscoveryTime = now + AuthenticationWindowDiscoveryPolicy.fallbackInterval
            }
            let observationDate = Date()
            var preservedPromptKeys = Set(coveredSystemPromptKeys)
            if let target {
                preservedPromptKeys.insert(
                    AuthenticationPromptSessionKey(window: target)
                )
            }
            let visibleCoreGraphicsWindows = AuthenticationWindowLocator
                .onScreenCoreGraphicsCandidates()
            promptSessions.observeVisibleCoreGraphicsWindows(
                visibleCoreGraphicsWindows,
                at: observationDate,
                preserving: preservedPromptKeys
            )
            let visibleAccessibilityWindows = promptSessions.accessibilityWindowIdentities
                .compactMap { AuthenticationWindowLocator.snapshot(identity: $0) }
            promptSessions.observeVisibleAccessibilityWindows(
                visibleAccessibilityWindows,
                at: observationDate,
                preserving: preservedPromptKeys
            )
            observedSystemWindows = visibleCoreGraphicsWindows
                + visibleAccessibilityWindows
            pruneCoveredSystemPrompts(
                observedPromptKeys: Set(
                    observedSystemWindows.map(
                        AuthenticationPromptSessionKey.init(window:)
                    )
                )
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
            observedSystemWindows = frontmostCandidate.map { [$0] } ?? []
        }

        if let currentTarget = target {
            if let frontmostCandidate {
                switch AuthenticationWindowFocusTransition.resolve(
                    from: currentTarget,
                    to: frontmostCandidate
                ) {
                case let .differentPrompt(candidate):
                    coverSystemPrompt(currentTarget)
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

            let current = AuthenticationWindowLocator.snapshot(
                tracking: currentTarget
            )
            if SystemPromptTeardownPolicy.shouldEnd(
                requestHasCompleted: currentSystemRequestHasCompleted(currentTarget),
                requesterIsRunning: !currentSystemRequesterHasExited,
                promptIsObserved: current != nil
            ) {
                endSystemPrompt(
                    currentTarget,
                    replacementCandidate: frontmostCandidate,
                    observedCandidates: observedSystemWindows,
                    now: now
                )
                return
            }

            guard let current else {
                let absenceResolution = AuthenticationWindowAbsenceResolution.resolve(
                    presenterIsRunning: AuthenticationWindowLocator
                        .isPresenterRunning(currentTarget),
                    presenterIsActive: NSRunningApplication(
                        processIdentifier: currentTarget.processID
                    )?.isActive == true,
                    requesterIsFrontmost: isFrontmostApplicationInCurrentProcessTree
                )
                switch absenceResolution {
                case .retain:
                    observationStability.reset()
                    return
                case .countMiss:
                    guard observationStability.recordMiss() else {
                        return
                    }
                case .endImmediately:
                    break
                }
                if let replacement = AuthenticationWindowRecovery.continuousReplacement(
                    for: currentTarget,
                    candidate: frontmostCandidate
                ) {
                    transferPromptSession(from: currentTarget, to: replacement, at: Date())
                    logger.notice(
                        "Authentication window representation recovered for PID \(replacement.processID, privacy: .public)"
                    )
                    updatePanel(for: replacement, now: now)
                    return
                }
                endSystemPrompt(
                    currentTarget,
                    replacementCandidate: frontmostCandidate,
                    observedCandidates: observedSystemWindows,
                    now: now
                )
                return
            }
            observationStability.recordConfirmation()
            target = current
            promptSessions.touch(window: current, at: Date())
            updatePanel(for: current, now: now)
            return
        }

        if let active = activePAMPasswordRequest {
            if let candidate = frontmostCandidate {
                activatePrompt(candidate, at: Date())
                logger.notice(
                    "Authentication window temporarily covered PAM password input for PID \(candidate.processID, privacy: .public)"
                )
                updatePanel(for: candidate, now: now)
                return
            }
            updatePAMPasswordRequest(active)
            return
        }

        if terminalPromptIdentity != nil {
            if let candidate = frontmostCandidate {
                suspendTerminalPrompt()
                activatePrompt(candidate, at: Date())
                logger.notice(
                    "Authentication window temporarily covered terminal password prompt for PID \(candidate.processID, privacy: .public)"
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
        now: TimeInterval
    ) {
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
            let promptKey = AuthenticationPromptSessionKey(window: window)
            if self.requestIdentifiersByPromptKey[promptKey] == nil,
               let requesterProcessID = newSnapshot.candidates.first?
                   .requesterProcess.pid {
                let completedIdentifiers = Set(
                    self.completedRequestIdentifiers.keys
                )
                let requestIdentifier = AuthenticationRequestAssociation
                    .unassignedActiveIdentifier(
                        requesterProcessID: requesterProcessID,
                        evidence: evidence,
                        completedIdentifiers: completedIdentifiers,
                        existingMappings: self.requestIdentifiersByPromptKey,
                        promptKey: promptKey
                    )
                    ?? AuthenticationRequestAssociation
                        .unassignedCompletedIdentifier(
                            requesterProcessID: requesterProcessID,
                            evidence: evidence,
                            currentEvidence: self.recentEvents,
                            completedIdentifiers: completedIdentifiers,
                            existingMappings: self.requestIdentifiersByPromptKey,
                            promptKey: promptKey
                        )
                if let requestIdentifier {
                    self.requestIdentifiersByPromptKey[promptKey] = requestIdentifier
                }
            }
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
            if self.currentSystemRequestHasCompleted(window) {
                self.refresh(forceDiscovery: true)
                return
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
        guard !terminalPromptSuppression.suppressesHeuristicPrompt(identity) else {
            hideTerminalPromptPanel()
            return
        }
        let retainedWindow = TerminalPromptWindowLocator.retainedWindow(
            for: chain,
            preserving: terminalPromptWindow
        )
        self.terminalPromptWindow = retainedWindow
        guard let presentationVisibleFrame = notchPresentationVisibleFrame(
            terminalWindow: retainedWindow
        ) else {
            hideTerminalPromptPanel()
            return
        }

        panel.showNotch(
            snapshot: AuthenticationProcessSnapshot(
                candidates: [chain],
                inspectionState: lastProcessSnapshot.inspectionState
            ),
            promptSequence: promptSequence,
            anchorFrame: presentationVisibleFrame,
            visibleFrame: presentationVisibleFrame
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
              activePAMPasswordRequest == nil,
              pendingPAMPasswordRequestIdentifier == nil,
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

            let allObservedIdentities = Set(observed.candidates.map {
                $0.requesterProcess.identity
            })
            self.terminalPromptSuppression.refresh(
                observed: allObservedIdentities,
                isRunning: ProcessIdentityLiveness.isRunning
            )
            let eligibleCandidates = observed.candidates.filter { chain in
                let identity = chain.requesterProcess.identity
                return identity == self.terminalPromptIdentity
                    || !self.terminalPromptSuppression.suppressesHeuristicPrompt(identity)
            }
            let observedIdentities = eligibleCandidates.map {
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
            for chain in eligibleCandidates {
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
                      let chain = eligibleCandidates.first(where: {
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
                guard let chain = eligibleCandidates.first(where: {
                    $0.requesterProcess.identity == identity
                }) else {
                    return
                }
                self.terminalPromptStability.recordConfirmation()
                self.terminalPromptIdentity = identity
                self.terminalPromptWindow = activeWindows[identity]
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

    private func recordAuthenticationEvent(_ lifecycle: AuthenticationLifecycleEvent) {
        let eventDate: Date
        switch lifecycle {
        case let .began(event):
            eventDate = event.receivedAt
            AuthenticationCompletionHistory.recordBegin(
                event.requestIdentifier,
                in: &completedRequestIdentifiers
            )
            recentEvents.append(event)
        case let .ended(requestIdentifier, receivedAt):
            eventDate = receivedAt
            completedRequestIdentifiers[requestIdentifier] = receivedAt
            recentEvents.removeAll {
                $0.requestIdentifier == requestIdentifier
            }
        case .reset:
            nextProcessScanTime = 0
            beginFastDiscoveryBurst()
            refresh(forceDiscovery: true)
            return
        }
        let evidenceCutoff = eventDate.addingTimeInterval(-10)
        recentEvents.removeAll { $0.receivedAt < evidenceCutoff }
        let completionCutoff = eventDate.addingTimeInterval(-600)
        completedRequestIdentifiers = completedRequestIdentifiers.filter {
            $0.value >= completionCutoff
        }
        if recentEvents.count > 64 {
            recentEvents.removeFirst(recentEvents.count - 64)
        }
        nextProcessScanTime = 0
        beginFastDiscoveryBurst()
        refresh(forceDiscovery: true)
    }

    private func resetAuthenticationEventCorrelation() {
        recentEvents.removeAll()
        requestIdentifiersByPromptKey.removeAll()
        completedRequestIdentifiers.removeAll()
    }

    private func beginFastDiscoveryBurst() {
        let now = ProcessInfo.processInfo.systemUptime
        fastCoreGraphicsDiscoveryUntil = max(
            fastCoreGraphicsDiscoveryUntil,
            now + 0.75
        )
    }

    private var isFrontmostApplicationInCurrentProcessTree: Bool {
        guard let frontmostApplicationProcessID else {
            return false
        }
        return lastProcessSnapshot.candidates.contains { chain in
            chain.processes.contains {
                $0.pid == frontmostApplicationProcessID
            } || chain.descendants.contains {
                $0.process.pid == frontmostApplicationProcessID
            }
        }
    }

    private var currentSystemRequesterHasExited: Bool {
        guard let requester = lastProcessSnapshot.candidates.first?
            .requesterProcess else {
            return false
        }
        return !ProcessIdentityLiveness.isRunning(requester.identity)
    }

    private func currentSystemRequestHasCompleted(
        _ window: AuthenticationWindowSnapshot
    ) -> Bool {
        let key = AuthenticationPromptSessionKey(window: window)
        guard let requestIdentifier = requestIdentifiersByPromptKey[key] else {
            return false
        }
        return completedRequestIdentifiers[requestIdentifier] != nil
    }

    private func endSystemPrompt(
        _ window: AuthenticationWindowSnapshot,
        replacementCandidate: AuthenticationWindowSnapshot?,
        observedCandidates: [AuthenticationWindowSnapshot],
        now: TimeInterval
    ) {
        logger.notice("Authentication request ended")
        cancelProcessScan()
        let endedKey = AuthenticationPromptSessionKey(window: window)
        promptSessions.remove(key: endedKey)
        coveredSystemPromptKeys.removeAll { $0 == endedKey }
        if let requestIdentifier = requestIdentifiersByPromptKey.removeValue(
            forKey: endedKey
        ) {
            completedRequestIdentifiers.removeValue(forKey: requestIdentifier)
            recentEvents.removeAll {
                $0.requestIdentifier == requestIdentifier
            }
        }
        target = nil
        targetFirstSeenAt = nil
        lastProcessSnapshot = .pending
        isCurrentSystemPromptIgnored = false
        observationStability.reset()
        if let replacement = CoveredSystemPromptSelection.replacement(
            frontmost: replacementCandidate,
            observed: observedCandidates,
            coveredKeys: coveredSystemPromptKeys,
            excluding: endedKey
        ) {
            activatePrompt(replacement, at: Date())
            updatePanel(for: replacement, now: now)
            return
        }
        if restoreInterruptedTerminalPrompt(now: now) {
            logger.notice("Terminal password prompt restored after authentication request ended")
            return
        }
        panel.hide(promptPresent: false, accessibilityTrusted: true)
        nextDiscoveryTime = 0
        report(isShowingPanel: false)
    }

    private func coverSystemPrompt(_ window: AuthenticationWindowSnapshot) {
        let key = AuthenticationPromptSessionKey(window: window)
        coveredSystemPromptKeys.removeAll { $0 == key }
        coveredSystemPromptKeys.append(key)
    }

    private func pruneCoveredSystemPrompts(
        observedPromptKeys: Set<AuthenticationPromptSessionKey>
    ) {
        var keysToRemove: [AuthenticationPromptSessionKey] = []
        for key in coveredSystemPromptKeys {
            guard let session = promptSessions.sessions[key] else {
                keysToRemove.append(key)
                continue
            }
            let requestHasCompleted = requestIdentifiersByPromptKey[key].map {
                completedRequestIdentifiers[$0] != nil
            } ?? false
            let requesterIsRunning = session.processSnapshot.candidates.first.map {
                ProcessIdentityLiveness.isRunning($0.requesterProcess.identity)
            } ?? true
            if SystemPromptTeardownPolicy.shouldEnd(
                requestHasCompleted: requestHasCompleted,
                requesterIsRunning: requesterIsRunning,
                promptKey: key,
                observedPromptKeys: observedPromptKeys
            ) {
                keysToRemove.append(key)
            }
        }
        guard !keysToRemove.isEmpty else {
            return
        }
        let removed = Set(keysToRemove)
        for key in keysToRemove {
            promptSessions.remove(key: key)
            if let requestIdentifier = requestIdentifiersByPromptKey.removeValue(
                forKey: key
            ) {
                completedRequestIdentifiers.removeValue(
                    forKey: requestIdentifier
                )
                recentEvents.removeAll {
                    $0.requestIdentifier == requestIdentifier
                }
            }
        }
        coveredSystemPromptKeys.removeAll { removed.contains($0) }
    }

    private func updateActiveNotchScreenIfNeeded(
        now: TimeInterval,
        force: Bool
    ) {
        let tracksTerminalRequest = panel.isNotchPresented
            || activePAMPasswordRequest != nil
            || terminalPromptIdentity != nil
            || suspendedTerminalPrompt != nil
        guard force || (tracksTerminalRequest && now >= nextActiveNotchScreenCheckTime) else {
            return
        }
        nextActiveNotchScreenCheckTime = now + 0.10
        if let visibleFrame = ActiveApplicationScreenLocator.visibleFrame(
            processID: frontmostApplicationProcessID
        ) {
            activeNotchVisibleFrame = visibleFrame
        }
    }

    private func suspendTerminalPrompt() {
        guard let identity = terminalPromptIdentity,
              lastProcessSnapshot.candidates.contains(where: {
                  $0.requesterProcess.identity == identity
              }) else {
            return
        }
        suspendedTerminalPrompt = SuspendedTerminalPrompt(
            identity: identity,
            snapshot: lastProcessSnapshot,
            terminalWindow: terminalPromptWindow,
            promptSequence: promptSequence
        )
    }

    private func restoreInterruptedTerminalPrompt(now: TimeInterval) -> Bool {
        if let active = activePAMPasswordRequest {
            guard active.lease.isActive else {
                finishExpiredPAMPasswordRequest(active)
                suspendedTerminalPrompt = nil
                return false
            }
            terminalPromptIdentity = active.snapshot.candidates.first?
                .requesterProcess.identity
            terminalPromptWindow = active.terminalWindow
            promptSequence = active.promptSequence
            lastProcessSnapshot = active.snapshot
            terminalPromptStability.recordConfirmation()
            nextTerminalPromptScanTime = 0
            updatePAMPasswordRequest(active)
            return panel.isNotchPresented
        }

        guard let suspended = suspendedTerminalPrompt else {
            return false
        }
        suspendedTerminalPrompt = nil
        terminalPromptIdentity = suspended.identity
        terminalPromptWindow = suspended.terminalWindow
        promptSequence = suspended.promptSequence
        lastProcessSnapshot = suspended.snapshot
        terminalPromptStability.recordConfirmation()
        nextTerminalPromptScanTime = 0
        updateTerminalPrompt(now: now)
        return panel.isNotchPresented
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
        let key = AuthenticationPromptSessionKey(window: window)
        coveredSystemPromptKeys.removeAll { $0 == key }
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
        let oldKey = AuthenticationPromptSessionKey(window: oldWindow)
        let newKey = AuthenticationPromptSessionKey(window: newWindow)
        let session = promptSessions.transfer(
            from: oldWindow,
            to: newWindow,
            at: date
        )
        AuthenticationRequestAssociation.transferMapping(
            in: &requestIdentifiersByPromptKey,
            from: oldKey,
            to: newKey
        )
        if let coveredIndex = coveredSystemPromptKeys.firstIndex(of: oldKey) {
            coveredSystemPromptKeys[coveredIndex] = newKey
        }
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
        suspendedTerminalPrompt = nil
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

    private func updatePAMPasswordRequest(_ active: ActivePAMPasswordRequest) {
        guard active.lease.isActive else {
            finishExpiredPAMPasswordRequest(active)
            resetTerminalPrompt(hidePanel: true, promptPresent: false)
            return
        }
        guard let chain = active.snapshot.candidates.first else {
            abandonActivePAMPasswordRequest()
            resetTerminalPrompt(hidePanel: true, promptPresent: false)
            return
        }
        guard !terminalPromptSuppression.suppressesActivePAMRequest(
            chain.requesterProcess.identity
        ) else {
            hideTerminalPromptPanel()
            return
        }
        let updatedWindow = TerminalPromptWindowLocator.retainedWindow(
            for: chain,
            preserving: active.terminalWindow
        )
        var updated = active
        updated.terminalWindow = updatedWindow
        activePAMPasswordRequest = updated
        terminalPromptWindow = updatedWindow
        presentPAMPasswordRequest(updated)
    }

    private func presentPAMPasswordRequest(_ active: ActivePAMPasswordRequest) {
        if active.offersAppInput,
           !panel.isPresentingVerifiedPAMPasswordRequest {
            panel.presentVerifiedPAMPasswordRequest(
                VerifiedPAMPasswordRequest(id: active.request.identifier.uuid),
                onPassword: { [weak self] requestID, password in
                    self?.submitPAMPassword(requestID: requestID, password: password)
                }
            )
        }
        guard let presentationVisibleFrame = notchPresentationVisibleFrame(
            terminalWindow: active.terminalWindow
        ) else {
            hideTerminalPromptPanel()
            return
        }
        panel.showNotch(
            snapshot: active.snapshot,
            promptSequence: active.promptSequence,
            anchorFrame: presentationVisibleFrame,
            visibleFrame: presentationVisibleFrame,
            allowsPAMSetupAction: false
        )
        report(isShowingPanel: true)
    }

    private func notchPresentationVisibleFrame(
        terminalWindow: TerminalPromptWindowSnapshot?
    ) -> CGRect? {
        activeNotchVisibleFrame
            ?? terminalWindow?.visibleFrame
            ?? AuthenticationWindowLocator.currentDisplays().first?.visibleFrame
    }

    private func submitPAMPassword(requestID: UUID, password: String) {
        guard var active = activePAMPasswordRequest,
              active.request.identifier.uuid == requestID,
              active.lease.isActive,
              active.offersAppInput,
              let passwordData = password.data(using: .utf8),
              !passwordData.isEmpty,
              passwordData.count <= PAMConversationWire.maximumPasswordLength else {
            return
        }
        active.offersAppInput = false
        activePAMPasswordRequest = active
        active.passwordHandler(passwordData)
    }

    private func useTerminalForPAMRequest(requestID: UUID) {
        guard var active = activePAMPasswordRequest,
              active.request.identifier.uuid == requestID,
              active.offersAppInput else {
            return
        }
        active.offersAppInput = false
        activePAMPasswordRequest = active
        active.useTerminalHandler()
    }

    private func abandonActivePAMPasswordRequest() {
        guard let active = activePAMPasswordRequest else {
            return
        }
        if active.offersAppInput {
            active.useTerminalHandler()
        }
        panel.dismissVerifiedPAMPasswordRequest(active.request.identifier.uuid)
        activePAMPasswordRequest = nil
    }

    private func finishExpiredPAMPasswordRequest(
        _ active: ActivePAMPasswordRequest
    ) {
        if let identity = active.snapshot.candidates.first?
            .requesterProcess.identity {
            terminalPromptSuppression.recordPAMCompletion(identity)
        }
        panel.dismissVerifiedPAMPasswordRequest(active.request.identifier.uuid)
        if activePAMPasswordRequest?.request.identifier == active.request.identifier {
            activePAMPasswordRequest = nil
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

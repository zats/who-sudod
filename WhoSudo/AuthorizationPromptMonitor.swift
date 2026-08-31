import AppKit
import Foundation
import os

struct AuthorizationMonitorStatus: Equatable {
    let message: String
    let accessibilityTrusted: Bool
    let isShowingPanel: Bool
}

@MainActor
final class AuthorizationPromptMonitor: NSObject {
    private static let securityAgentShownNotification = Notification.Name(
        "com.apple.SecurityAgent.consoleLogin.UIShown"
    )

    private let logger = Logger(subsystem: "com.zats.WhoSudo", category: "AuthorizationMonitor")
    private let scanner = SudoProcessScanner()
    private let panel = ProcessTreePanelController()
    private let statusHandler: (AuthorizationMonitorStatus) -> Void
    private var timer: Timer?
    private var target: SecurityAgentWindowSnapshot?
    private var lastProcessSnapshot = SudoProcessSnapshot.pending
    private var nextDiscoveryTime: TimeInterval = 0
    private var nextProcessScanTime: TimeInterval = 0
    private var processScanTask: Task<Void, Never>?
    private var processScanSequence = 0

    init(statusHandler: @escaping (AuthorizationMonitorStatus) -> Void) {
        self.statusHandler = statusHandler
        super.init()
    }

    func start() {
        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(securityAgentDidShow),
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
        DistributedNotificationCenter.default().removeObserver(self)
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        panel.hide()
    }

    @objc
    private func tick() {
        refresh(forceDiscovery: false)
    }

    @objc
    private func securityAgentDidShow() {
        logger.notice("SecurityAgent UI notification received")
        refresh(forceDiscovery: true)
    }

    @objc
    private func frontmostApplicationDidChange() {
        refresh(forceDiscovery: false)
    }

    private func refresh(forceDiscovery: Bool) {
        guard AccessibilityFocusReader.isTrusted else {
            cancelProcessScan()
            target = nil
            lastProcessSnapshot = .pending
            panel.hide()
            report(message: "Accessibility access is required", isShowingPanel: false)
            return
        }

        let now = ProcessInfo.processInfo.systemUptime

        if let currentTarget = target {
            guard let current = SecurityAgentWindowLocator.snapshot(windowID: currentTarget.windowID) else {
                logger.notice("SecurityAgent window closed")
                cancelProcessScan()
                target = nil
                lastProcessSnapshot = .pending
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

        guard let candidate = SecurityAgentWindowLocator.frontmostCandidate() else {
            report(message: waitingMessage, isShowingPanel: false)
            return
        }

        target = candidate
        nextProcessScanTime = 0
        logger.notice("SecurityAgent window detected: \(candidate.windowID, privacy: .public)")
        updatePanel(for: candidate, now: now)
    }

    private func updatePanel(for window: SecurityAgentWindowSnapshot, now: TimeInterval) {
        guard let focused = AccessibilityFocusReader.isFocusedWindow(
            processID: window.processID,
            matchingCoreGraphicsFrame: window.coreGraphicsFrame
        ) else {
            panel.hide()
            report(message: "Unable to read the focused authentication dialog", isShowingPanel: false)
            return
        }

        guard focused else {
            panel.hide()
            report(message: "Authentication dialog is not focused", isShowingPanel: false)
            return
        }

        if now >= nextProcessScanTime, processScanTask == nil {
            nextProcessScanTime = now + 0.15
            startProcessScan(forWindowID: window.windowID)
        }

        panel.show(
            snapshot: lastProcessSnapshot,
            authenticationFrame: window.frame,
            visibleFrame: window.visibleFrame
        )
        let count = lastProcessSnapshot.candidates.count
        let requestText = count == 1 ? "request" : "requests"
        let freshness = lastProcessSnapshot.inspectionState == .unavailable
            ? "last known"
            : "live"
        report(message: "Showing \(count) \(freshness) sudo \(requestText)", isShowingPanel: true)
    }

    private func startProcessScan(forWindowID windowID: CGWindowID) {
        processScanSequence += 1
        let sequence = processScanSequence
        let preferredIdentity = lastProcessSnapshot.candidates.first?.sudoProcess.identity
        processScanTask = Task { [weak self, scanner] in
            let newSnapshot = await scanner.snapshot(preferredIdentity: preferredIdentity)
            guard !Task.isCancelled, let self,
                  self.processScanSequence == sequence else {
                return
            }
            self.processScanTask = nil
            guard self.target?.windowID == windowID else {
                return
            }

            let refreshedSnapshot = ProcessSnapshotSelection.refreshingLive(
                current: self.lastProcessSnapshot,
                observed: newSnapshot
            )
            if refreshedSnapshot != self.lastProcessSnapshot {
                self.logger.notice(
                    "Process snapshot has \(newSnapshot.candidates.count, privacy: .public) sudo candidate(s)"
                )
                self.lastProcessSnapshot = refreshedSnapshot
            }
        }
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
            ? "Waiting for an administrator dialog…"
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

import AppKit
import CoreGraphics
import Darwin

enum AuthenticationSurfaceKind: Hashable, Sendable {
    case securityAgent
    case localAuthentication
    case terminalPassword
}

enum AuthenticationWindowIdentity: Hashable, Sendable {
    case coreGraphics(CGWindowID)
    case accessibility(processID: pid_t)
}

struct AuthenticationWindowSnapshot: Equatable {
    let identity: AuthenticationWindowIdentity
    let processID: pid_t
    let surfaceKind: AuthenticationSurfaceKind
    let coreGraphicsFrame: CGRect
    let frame: CGRect
    let visibleFrame: CGRect
}

struct TerminalPromptWindowSnapshot: Equatable {
    let windowID: CGWindowID
    let processID: pid_t
    let coreGraphicsFrame: CGRect
    let frame: CGRect
    let visibleFrame: CGRect
}

@MainActor
enum TerminalPromptWindowLocator {
    static func focusedWindow(
        for chain: ProcessChain,
        preserving currentWindow: TerminalPromptWindowSnapshot?
    ) -> TerminalPromptWindowSnapshot? {
        guard let currentWindow else {
            return focusedWindow(for: chain)
        }
        if let focused = focusedSnapshot(for: currentWindow) {
            return focused
        }
        guard currentSnapshot(for: currentWindow) == nil else {
            return nil
        }
        return focusedWindow(for: chain)
    }

    static func focusedWindow(for chain: ProcessChain) -> TerminalPromptWindowSnapshot? {
        for process in chain.processes.reversed() {
            guard process.pid != chain.requesterProcess.pid,
                  let executablePath = process.executablePath,
                  ProcessTablePresentationBuilder.enclosingApplicationPath(
                      for: executablePath
                  ) != nil,
                  NSRunningApplication(processIdentifier: process.pid)?.isActive == true,
                  let focusedFrame = AccessibilityFocusReader.focusedWindowFrame(
                      processID: process.pid
                  ),
                  focusedFrame.width >= 180,
                  focusedFrame.height >= 120,
                  let window = frontmostMatchingWindow(
                      processID: process.pid,
                      focusedFrame: focusedFrame
                  ), AccessibilityFocusReader.isFocusedWindow(
                      processID: window.processID,
                      matchingCoreGraphicsFrame: window.coreGraphicsFrame,
                      tolerance: 8
                  ) == true else {
                continue
            }
            return window
        }
        return nil
    }

    static func focusedSnapshot(
        for window: TerminalPromptWindowSnapshot
    ) -> TerminalPromptWindowSnapshot? {
        guard let updated = currentSnapshot(for: window), NSRunningApplication(
            processIdentifier: updated.processID
        )?.isActive == true, AccessibilityFocusReader.isFocusedWindow(
            processID: updated.processID,
            matchingCoreGraphicsFrame: updated.coreGraphicsFrame,
            tolerance: 8
        ) == true else {
            return nil
        }
        return updated
    }

    static func existingWindow(
        for window: TerminalPromptWindowSnapshot
    ) -> TerminalPromptWindowSnapshot? {
        currentSnapshot(for: window)
    }

    private static func currentSnapshot(
        for window: TerminalPromptWindowSnapshot
    ) -> TerminalPromptWindowSnapshot? {
        let windowInfo = CGWindowListCopyWindowInfo(
            [.optionIncludingWindow],
            window.windowID
        ) as? [[String: Any]] ?? []
        return snapshot(
            from: windowInfo,
            expectedProcessID: window.processID
        )
    }

    private static func frontmostMatchingWindow(
        processID: pid_t,
        focusedFrame: CGRect
    ) -> TerminalPromptWindowSnapshot? {
        let windowInfo = CGWindowListCopyWindowInfo(
            [.optionOnScreenOnly, .excludeDesktopElements],
            .zero
        ) as? [[String: Any]] ?? []
        let candidates = windowInfo.compactMap { info -> TerminalPromptWindowSnapshot? in
            snapshot(
                from: [info],
                expectedProcessID: processID
            )
        }
        return frontmostMatch(in: candidates, focusedFrame: focusedFrame)
    }

    static func frontmostMatch(
        in candidates: [TerminalPromptWindowSnapshot],
        focusedFrame: CGRect
    ) -> TerminalPromptWindowSnapshot? {
        candidates.first {
            framesMatch($0.coreGraphicsFrame, focusedFrame)
        }
    }

    private static func framesMatch(_ lhs: CGRect, _ rhs: CGRect) -> Bool {
        abs(lhs.minX - rhs.minX) <= 8
            && abs(lhs.minY - rhs.minY) <= 8
            && abs(lhs.width - rhs.width) <= 8
            && abs(lhs.height - rhs.height) <= 8
    }

    private static func snapshot(
        from windowInfo: [[String: Any]],
        expectedProcessID: pid_t
    ) -> TerminalPromptWindowSnapshot? {
        let displays = AuthenticationWindowLocator.currentDisplays()
        for info in windowInfo {
            guard let processIDNumber = info[kCGWindowOwnerPID as String] as? NSNumber,
                  processIDNumber.int32Value == expectedProcessID,
                  let windowIDNumber = info[kCGWindowNumber as String] as? NSNumber,
                  let bounds = info[kCGWindowBounds as String] as? [String: Any],
                  (info[kCGWindowIsOnscreen as String] as? NSNumber)?.boolValue == true else {
                continue
            }
            let frame = CGRect(
                x: number(bounds["X"]),
                y: number(bounds["Y"]),
                width: number(bounds["Width"]),
                height: number(bounds["Height"])
            )
            guard frame.width >= 180,
                  frame.height >= 120,
                  let geometry = WindowGeometry.convert(
                      coreGraphicsFrame: frame,
                      displays: displays
                  ) else {
                continue
            }
            return TerminalPromptWindowSnapshot(
                windowID: CGWindowID(windowIDNumber.uint32Value),
                processID: expectedProcessID,
                coreGraphicsFrame: frame,
                frame: geometry.frame,
                visibleFrame: geometry.visibleFrame
            )
        }
        return nil
    }

    private static func number(_ value: Any?) -> CGFloat {
        CGFloat((value as? NSNumber)?.doubleValue ?? 0)
    }
}

enum AuthenticationWindowContinuity {
    static func representsSamePrompt(
        _ lhs: AuthenticationWindowSnapshot,
        _ rhs: AuthenticationWindowSnapshot,
        frameTolerance: CGFloat = 8
    ) -> Bool {
        guard usesDifferentIdentitySources(lhs.identity, rhs.identity) else {
            return false
        }
        return matchesPresenterAndFrame(lhs, rhs, frameTolerance: frameTolerance)
    }

    static func matchesPresenterAndFrame(
        _ lhs: AuthenticationWindowSnapshot,
        _ rhs: AuthenticationWindowSnapshot,
        frameTolerance: CGFloat = 8
    ) -> Bool {
        guard lhs.processID == rhs.processID,
              lhs.surfaceKind == rhs.surfaceKind else {
            return false
        }
        return abs(lhs.coreGraphicsFrame.minX - rhs.coreGraphicsFrame.minX) <= frameTolerance
            && abs(lhs.coreGraphicsFrame.minY - rhs.coreGraphicsFrame.minY) <= frameTolerance
            && abs(lhs.coreGraphicsFrame.width - rhs.coreGraphicsFrame.width) <= frameTolerance
            && abs(lhs.coreGraphicsFrame.height - rhs.coreGraphicsFrame.height) <= frameTolerance
    }

    private static func usesDifferentIdentitySources(
        _ lhs: AuthenticationWindowIdentity,
        _ rhs: AuthenticationWindowIdentity
    ) -> Bool {
        switch (lhs, rhs) {
        case (.coreGraphics, .accessibility), (.accessibility, .coreGraphics):
            true
        default:
            false
        }
    }
}

enum AuthenticationWindowAccessibilityFallback {
    static func resolve(
        coreGraphicsCandidates: [AuthenticationWindowSnapshot],
        accessibilityCandidate: AuthenticationWindowSnapshot?
    ) -> AuthenticationWindowSnapshot? {
        guard let accessibilityCandidate else {
            return nil
        }
        let matches = coreGraphicsCandidates.filter {
            AuthenticationWindowContinuity.matchesPresenterAndFrame(
                $0,
                accessibilityCandidate
            )
        }
        if matches.count == 1 {
            return matches[0]
        }
        return coreGraphicsCandidates.isEmpty ? accessibilityCandidate : nil
    }
}

enum AuthenticationWindowSnapshotFactory {
    static func accessibilitySnapshot(
        processID: pid_t,
        bundleIdentifier: String?,
        executablePath: String?,
        focusedFrame: CGRect?,
        displays: [DisplayGeometry]
    ) -> AuthenticationWindowSnapshot? {
        guard AuthenticationPresenterMatcher.kind(
            bundleIdentifier: bundleIdentifier,
            executablePath: executablePath
        ) == .localAuthentication,
        let focusedFrame,
        focusedFrame.width >= 180,
        focusedFrame.height >= 120,
        let geometry = WindowGeometry.convert(
            coreGraphicsFrame: focusedFrame,
            displays: displays
        ) else {
            return nil
        }

        return AuthenticationWindowSnapshot(
            identity: .accessibility(processID: processID),
            processID: processID,
            surfaceKind: .localAuthentication,
            coreGraphicsFrame: focusedFrame,
            frame: geometry.frame,
            visibleFrame: geometry.visibleFrame
        )
    }
}

enum AuthenticationPresenterMatcher {
    static let securityAgentPath = "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent"
    static let coreAuthenticationPath = "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreautha.bundle/Contents/MacOS/coreautha"
    static let remoteServicePath = "/System/Library/PrivateFrameworks/LocalAuthenticationUI.framework/Versions/A/XPCServices/LocalAuthenticationRemoteService.xpc/Contents/MacOS/LocalAuthenticationRemoteService"
    private static let coreGraphicsProcessNames: Set<String> = [
        "SecurityAgent",
        "coreautha",
        "LocalAuthenticationRemoteService"
    ]

    static func isPossibleCoreGraphicsPresenter(processName: String?) -> Bool {
        processName.map(coreGraphicsProcessNames.contains) ?? false
    }

    static func kind(
        bundleIdentifier: String?,
        executablePath: String?
    ) -> AuthenticationSurfaceKind? {
        if executablePath == securityAgentPath {
            guard bundleIdentifier == nil || bundleIdentifier == "com.apple.SecurityAgent" else {
                return nil
            }
            return .securityAgent
        }
        if executablePath == coreAuthenticationPath {
            guard bundleIdentifier == nil || bundleIdentifier == "com.apple.LocalAuthentication.UIAgent" else {
                return nil
            }
            return .localAuthentication
        }
        if executablePath == remoteServicePath {
            guard bundleIdentifier == nil || bundleIdentifier == "com.apple.LocalAuthenticationRemoteService" else {
                return nil
            }
            return .localAuthentication
        }
        return nil
    }
}

@MainActor
enum AuthenticationWindowLocator {
    private static var displayCache: [DisplayGeometry]?

    static func invalidateDisplayCache() {
        displayCache = nil
    }

    static func onScreenCoreGraphicsCandidates() -> [AuthenticationWindowSnapshot] {
        let windowInfo = CGWindowListCopyWindowInfo(
            [.optionOnScreenOnly, .excludeDesktopElements],
            .zero
        ) as? [[String: Any]] ?? []
        return snapshots(from: windowInfo, requiresKnownOwnerName: true)
    }

    static func frontmostCandidate(
        from coreGraphicsCandidates: [AuthenticationWindowSnapshot]? = nil,
        frontmostProcessID: pid_t?
    ) -> AuthenticationWindowSnapshot? {
        let candidates = coreGraphicsCandidates ?? onScreenCoreGraphicsCandidates()

        if let candidate = candidates.first(where: isFocused) {
            return candidate
        }
        return AuthenticationWindowAccessibilityFallback.resolve(
            coreGraphicsCandidates: candidates,
            accessibilityCandidate: accessibilityCandidate(
                frontmostProcessID: frontmostProcessID
            )
        )
    }

    static func frontmostAccessibilityCandidate(
        processID: pid_t?
    ) -> AuthenticationWindowSnapshot? {
        accessibilityCandidate(frontmostProcessID: processID)
    }

    static func snapshot(identity: AuthenticationWindowIdentity) -> AuthenticationWindowSnapshot? {
        switch identity {
        case let .coreGraphics(windowID):
            let windowInfo = CGWindowListCopyWindowInfo(
                [.optionIncludingWindow],
                windowID
            ) as? [[String: Any]] ?? []
            return snapshots(
                from: windowInfo,
                requiresKnownOwnerName: false
            ).first { $0.identity == identity }
        case let .accessibility(processID):
            return accessibilitySnapshot(processID: processID)
        }
    }

    private static func snapshots(
        from windowInfo: [[String: Any]],
        requiresKnownOwnerName: Bool
    ) -> [AuthenticationWindowSnapshot] {
        let displays = currentDisplays()
        var surfaceKindsByProcessID: [pid_t: AuthenticationSurfaceKind] = [:]
        var unsupportedProcessIDs: Set<pid_t> = []
        return windowInfo.compactMap { info in
            guard
                let processIDNumber = info[kCGWindowOwnerPID as String] as? NSNumber,
                let windowIDNumber = info[kCGWindowNumber as String] as? NSNumber,
                let bounds = info[kCGWindowBounds as String] as? [String: Any],
                (info[kCGWindowIsOnscreen as String] as? NSNumber)?.boolValue == true
            else {
                return nil
            }
            if requiresKnownOwnerName,
               !AuthenticationPresenterMatcher.isPossibleCoreGraphicsPresenter(
                   processName: info[kCGWindowOwnerName as String] as? String
               ) {
                return nil
            }

            let processID = pid_t(processIDNumber.int32Value)
            let surfaceKind: AuthenticationSurfaceKind
            if let cached = surfaceKindsByProcessID[processID] {
                surfaceKind = cached
            } else {
                guard !unsupportedProcessIDs.contains(processID),
                      let resolved = authenticationSurfaceKind(processID: processID) else {
                    unsupportedProcessIDs.insert(processID)
                    return nil
                }
                surfaceKindsByProcessID[processID] = resolved
                surfaceKind = resolved
            }

            let frame = CGRect(
                x: number(bounds["X"]),
                y: number(bounds["Y"]),
                width: number(bounds["Width"]),
                height: number(bounds["Height"])
            )
            guard frame.width >= 180, frame.height >= 120 else {
                return nil
            }
            guard let geometry = WindowGeometry.convert(coreGraphicsFrame: frame, displays: displays) else {
                return nil
            }

            return AuthenticationWindowSnapshot(
                identity: .coreGraphics(CGWindowID(windowIDNumber.uint32Value)),
                processID: processID,
                surfaceKind: surfaceKind,
                coreGraphicsFrame: frame,
                frame: geometry.frame,
                visibleFrame: geometry.visibleFrame
            )
        }
    }

    private static func accessibilityCandidate(
        frontmostProcessID: pid_t?
    ) -> AuthenticationWindowSnapshot? {
        guard let frontmostProcessID else {
            return nil
        }
        guard let snapshot = accessibilitySnapshot(processID: frontmostProcessID),
              isFocused(snapshot) else {
            return nil
        }
        return snapshot
    }

    private static func isFocused(_ snapshot: AuthenticationWindowSnapshot) -> Bool {
        AccessibilityFocusReader.isFocusedWindow(
            processID: snapshot.processID,
            matchingCoreGraphicsFrame: snapshot.coreGraphicsFrame
        ) == true
    }

    private static func accessibilitySnapshot(
        processID: pid_t
    ) -> AuthenticationWindowSnapshot? {
        return accessibilitySnapshot(
            processID: processID,
            bundleIdentifier: nil
        )
    }

    private static func accessibilitySnapshot(
        processID: pid_t,
        bundleIdentifier: String?
    ) -> AuthenticationWindowSnapshot? {
        let verifiedExecutablePath = executablePath(for: processID)
        guard AuthenticationPresenterMatcher.kind(
            bundleIdentifier: bundleIdentifier,
            executablePath: verifiedExecutablePath
        ) == .localAuthentication else {
            return nil
        }
        return AuthenticationWindowSnapshotFactory.accessibilitySnapshot(
            processID: processID,
            bundleIdentifier: bundleIdentifier,
            executablePath: verifiedExecutablePath,
            focusedFrame: AccessibilityFocusReader.focusedWindowFrame(
                processID: processID
            ),
            displays: currentDisplays()
        )
    }

    private static func authenticationSurfaceKind(processID: pid_t) -> AuthenticationSurfaceKind? {
        return AuthenticationPresenterMatcher.kind(
            bundleIdentifier: nil,
            executablePath: executablePath(for: processID)
        )
    }

    private static func executablePath(for processID: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let length = buffer.withUnsafeMutableBytes { bytes in
            proc_pidpath(processID, bytes.baseAddress, UInt32(bytes.count))
        }
        guard length > 0 else {
            return nil
        }
        return String(
            decoding: buffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)),
            as: UTF8.self
        )
    }

    static func currentDisplays() -> [DisplayGeometry] {
        if let displayCache {
            return displayCache
        }
        let displays: [DisplayGeometry] = NSScreen.screens.compactMap { screen in
            guard let number = screen.deviceDescription[.init("NSScreenNumber")] as? NSNumber else {
                return nil
            }
            return DisplayGeometry(
                appKitFrame: screen.frame,
                visibleFrame: screen.visibleFrame,
                coreGraphicsFrame: CGDisplayBounds(CGDirectDisplayID(number.uint32Value))
            )
        }
        displayCache = displays
        return displays
    }

    private static func number(_ value: Any?) -> CGFloat {
        CGFloat((value as? NSNumber)?.doubleValue ?? 0)
    }
}

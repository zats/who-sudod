import ApplicationServices
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
    case accessibility(processID: pid_t, elementIdentifier: UInt)
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
enum ActiveApplicationScreenLocator {
    private static var lastFrontmostProcessID: pid_t?

    static func invalidate() {
        lastFrontmostProcessID = nil
    }

    static func visibleFrame(processID: pid_t?) -> CGRect? {
        guard let processID else {
            lastFrontmostProcessID = nil
            return nil
        }
        let allowsPointerFallback = lastFrontmostProcessID != processID
        lastFrontmostProcessID = processID
        let displays = AuthenticationWindowLocator.currentDisplays()

        if let visibleFrame = displayVisibleFrame(
            for: AccessibilityFocusReader.focusedWindowFrame(
                processID: processID
            ),
            displays: displays
        ) {
            return visibleFrame
        }
        if let visibleFrame = displayVisibleFrame(
            for: mainWindowFrame(processID: processID),
            displays: displays
        ) {
            return visibleFrame
        }

        return visibleFrame(
            focusedWindowFrame: nil,
            orderedOnScreenWindowFrames: orderedOnScreenWindowFrames(
                processID: processID
            ),
            pointerLocation: NSEvent.mouseLocation,
            allowsPointerFallback: allowsPointerFallback,
            displays: displays
        )
    }

    static func visibleFrame(
        focusedWindowFrame: CGRect?,
        mainWindowFrame: CGRect? = nil,
        orderedOnScreenWindowFrames: [CGRect] = [],
        pointerLocation: CGPoint? = nil,
        allowsPointerFallback: Bool = false,
        displays: [DisplayGeometry]
    ) -> CGRect? {
        let windowFrames = [focusedWindowFrame, mainWindowFrame].compactMap { $0 }
            + orderedOnScreenWindowFrames
        for windowFrame in windowFrames {
            if let visibleFrame = displayVisibleFrame(
                for: windowFrame,
                displays: displays
            ) {
                return visibleFrame
            }
        }
        guard allowsPointerFallback, let pointerLocation else {
            return nil
        }
        return displays.first(where: {
            $0.appKitFrame.contains(pointerLocation)
        })?.visibleFrame
    }

    private static func orderedOnScreenWindowFrames(
        processID: pid_t
    ) -> [CGRect] {
        let windowInfo = CGWindowListCopyWindowInfo(
            [.optionOnScreenOnly, .excludeDesktopElements],
            .zero
        ) as? [[String: Any]] ?? []
        let normalWindowLevel = CGWindowLevelForKey(.normalWindow)
        return windowInfo.compactMap { info in
            guard let ownerProcessID = info[kCGWindowOwnerPID as String] as? NSNumber,
                  ownerProcessID.int32Value == processID,
                  let layer = info[kCGWindowLayer as String] as? NSNumber,
                  layer.int32Value == normalWindowLevel,
                  (info[kCGWindowIsOnscreen as String] as? NSNumber)?.boolValue == true,
                  ((info[kCGWindowAlpha as String] as? NSNumber)?.doubleValue ?? 1) > 0,
                  let bounds = info[kCGWindowBounds as String] as? [String: Any] else {
                return nil
            }
            let frame = CGRect(
                x: number(bounds["X"]),
                y: number(bounds["Y"]),
                width: number(bounds["Width"]),
                height: number(bounds["Height"])
            )
            return frame.width >= 180 && frame.height >= 120 ? frame : nil
        }
    }

    private static func mainWindowFrame(processID: pid_t) -> CGRect? {
        guard AccessibilityFocusReader.isTrusted else {
            return nil
        }
        let application = AXUIElementCreateApplication(processID)
        var windowValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(
            application,
            kAXMainWindowAttribute as CFString,
            &windowValue
        ) == .success,
        let windowValue,
        CFGetTypeID(windowValue) == AXUIElementGetTypeID() else {
            return nil
        }
        let window = unsafeDowncast(windowValue, to: AXUIElement.self)
        guard let position = pointAttribute(kAXPositionAttribute, from: window),
              let size = sizeAttribute(kAXSizeAttribute, from: window) else {
            return nil
        }
        return CGRect(origin: position, size: size)
    }

    private static func displayVisibleFrame(
        for coreGraphicsFrame: CGRect?,
        displays: [DisplayGeometry]
    ) -> CGRect? {
        guard let coreGraphicsFrame else {
            return nil
        }
        return WindowGeometry.convert(
            coreGraphicsFrame: coreGraphicsFrame,
            displays: displays
        )?.visibleFrame
    }

    private static func pointAttribute(
        _ attribute: String,
        from element: AXUIElement
    ) -> CGPoint? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(
            element,
            attribute as CFString,
            &value
        ) == .success,
        let value,
        CFGetTypeID(value) == AXValueGetTypeID() else {
            return nil
        }
        let axValue = unsafeDowncast(value, to: AXValue.self)
        guard AXValueGetType(axValue) == .cgPoint else {
            return nil
        }
        var point = CGPoint.zero
        return AXValueGetValue(axValue, .cgPoint, &point) ? point : nil
    }

    private static func sizeAttribute(
        _ attribute: String,
        from element: AXUIElement
    ) -> CGSize? {
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(
            element,
            attribute as CFString,
            &value
        ) == .success,
        let value,
        CFGetTypeID(value) == AXValueGetTypeID() else {
            return nil
        }
        let axValue = unsafeDowncast(value, to: AXValue.self)
        guard AXValueGetType(axValue) == .cgSize else {
            return nil
        }
        var size = CGSize.zero
        return AXValueGetValue(axValue, .cgSize, &size) ? size : nil
    }

    private static func number(_ value: Any?) -> CGFloat {
        CGFloat((value as? NSNumber)?.doubleValue ?? 0)
    }
}

@MainActor
enum TerminalPromptWindowLocator {
    static func retainedWindow(
        for chain: ProcessChain,
        preserving currentWindow: TerminalPromptWindowSnapshot?
    ) -> TerminalPromptWindowSnapshot? {
        guard let currentWindow else {
            return availableWindow(for: chain)
        }
        let updatedSameWindow = currentSnapshot(for: currentWindow)
        let ownerIsRunning = NSRunningApplication(
            processIdentifier: currentWindow.processID
        )?.isTerminated == false
        return retainedCandidate(
            previous: currentWindow,
            updatedSameWindow: updatedSameWindow,
            ownerIsRunning: ownerIsRunning
        )
    }

    static func retainedCandidate(
        previous: TerminalPromptWindowSnapshot,
        updatedSameWindow: TerminalPromptWindowSnapshot?,
        ownerIsRunning: Bool
    ) -> TerminalPromptWindowSnapshot? {
        if let updatedSameWindow,
           updatedSameWindow.windowID == previous.windowID,
           updatedSameWindow.processID == previous.processID {
            return updatedSameWindow
        }
        return ownerIsRunning ? previous : nil
    }

    static func initialCandidate(
        focused: TerminalPromptWindowSnapshot?,
        available: [TerminalPromptWindowSnapshot],
        offscreen: [TerminalPromptWindowSnapshot] = []
    ) -> TerminalPromptWindowSnapshot? {
        if let focused {
            return focused
        }
        if let available = available.first {
            return available
        }
        return offscreen.count == 1 ? offscreen[0] : nil
    }

    static func availableWindow(for chain: ProcessChain) -> TerminalPromptWindowSnapshot? {
        if let focused = focusedWindow(for: chain) {
            return focused
        }
        for process in chain.processes.reversed() {
            guard process.pid != chain.requesterProcess.pid,
                  let executablePath = process.executablePath,
                  ProcessTablePresentationBuilder.enclosingApplicationPath(
                      for: executablePath
                  ) != nil else {
                continue
            }
            let candidates = windowSnapshots(
                processID: process.pid,
                requiresOnScreen: true
            )
            if let candidate = initialCandidate(
                focused: nil,
                available: candidates
            ) {
                return candidate
            }
            let offscreenCandidates = windowSnapshots(
                processID: process.pid,
                requiresOnScreen: false
            )
            if let candidate = initialCandidate(
                focused: nil,
                available: [],
                offscreen: offscreenCandidates
            ) {
                return candidate
            }
        }
        return nil
    }

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
                  let window = focusedWindow(processID: process.pid) else {
                continue
            }
            return window
        }
        return nil
    }

    static func focusedWindow(
        processID: pid_t
    ) -> TerminalPromptWindowSnapshot? {
        guard NSRunningApplication(processIdentifier: processID)?.isActive == true,
              let focusedFrame = AccessibilityFocusReader.focusedWindowFrame(
                  processID: processID
              ),
              focusedFrame.width >= 180,
              focusedFrame.height >= 120,
              let window = frontmostMatchingWindow(
                  processID: processID,
                  focusedFrame: focusedFrame
              ), AccessibilityFocusReader.isFocusedWindow(
                  processID: window.processID,
                  matchingCoreGraphicsFrame: window.coreGraphicsFrame,
                  tolerance: 8
              ) == true else {
            return nil
        }
        return window
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
        let candidates = windowSnapshots(
            processID: processID,
            requiresOnScreen: true
        )
        return frontmostMatch(in: candidates, focusedFrame: focusedFrame)
    }

    private static func windowSnapshots(
        processID: pid_t,
        requiresOnScreen: Bool
    ) -> [TerminalPromptWindowSnapshot] {
        let options: CGWindowListOption = requiresOnScreen
            ? [.optionOnScreenOnly, .excludeDesktopElements]
            : [.excludeDesktopElements]
        let windowInfo = CGWindowListCopyWindowInfo(options, .zero)
            as? [[String: Any]] ?? []
        return windowInfo.compactMap { info in
            if !requiresOnScreen {
                let isOnScreen = (info[kCGWindowIsOnscreen as String] as? NSNumber)?
                    .boolValue == true
                let layer = (info[kCGWindowLayer as String] as? NSNumber)?.int32Value
                let alpha = (info[kCGWindowAlpha as String] as? NSNumber)?
                    .doubleValue ?? 1
                guard !isOnScreen,
                      layer == CGWindowLevelForKey(.normalWindow),
                      alpha > 0 else {
                    return nil
                }
            }
            return snapshot(
                from: [info],
                expectedProcessID: processID,
                requiresOnScreen: requiresOnScreen
            )
        }
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
        expectedProcessID: pid_t,
        requiresOnScreen: Bool = true
    ) -> TerminalPromptWindowSnapshot? {
        let displays = AuthenticationWindowLocator.currentDisplays()
        for info in windowInfo {
            guard let processIDNumber = info[kCGWindowOwnerPID as String] as? NSNumber,
                  processIDNumber.int32Value == expectedProcessID,
                  let windowIDNumber = info[kCGWindowNumber as String] as? NSNumber,
                  let bounds = info[kCGWindowBounds as String] as? [String: Any],
                  AuthenticationCoreGraphicsWindowPolicy.includes(
                      isOnScreen: (info[kCGWindowIsOnscreen as String] as? NSNumber)?.boolValue,
                      requiresOnScreen: requiresOnScreen
                  ) else {
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
        _ rhs: AuthenticationWindowSnapshot
    ) -> Bool {
        lhs.identity == rhs.identity
            && lhs.processID == rhs.processID
            && lhs.surfaceKind == rhs.surfaceKind
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
        // Local Authentication can host several centered prompts in one long-
        // lived presenter process. Core Graphics cannot identify which of its
        // same-frame windows is focused, while AX supplies a stable per-window
        // identity. Keep AX canonical whenever it is available; downgrading a
        // unique match to a CGWindowID would discard that identity and make a
        // later topmost prompt look like the same window.
        _ = coreGraphicsCandidates
        return accessibilityCandidate
    }
}

enum AuthenticationWindowSnapshotFactory {
    static func accessibilitySnapshot(
        processID: pid_t,
        elementIdentifier: UInt,
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
            identity: .accessibility(
                processID: processID,
                elementIdentifier: elementIdentifier
            ),
            processID: processID,
            surfaceKind: .localAuthentication,
            coreGraphicsFrame: focusedFrame,
            frame: geometry.frame,
            visibleFrame: geometry.visibleFrame
        )
    }
}

enum AuthenticationTrackedWindowResolver {
    static func accessibilityFrame(
        matching previousFrame: CGRect,
        currentFrames: [CGRect],
        acceptsMovedSingleWindow: Bool = true,
        tolerance: CGFloat = 8
    ) -> CGRect? {
        let eligibleFrames = currentFrames.filter {
            $0.width >= 180 && $0.height >= 120
        }
        let matchingFrames = eligibleFrames.filter {
            abs($0.minX - previousFrame.minX) <= tolerance
                && abs($0.minY - previousFrame.minY) <= tolerance
                && abs($0.width - previousFrame.width) <= tolerance
                && abs($0.height - previousFrame.height) <= tolerance
        }
        if matchingFrames.count == 1 {
            return matchingFrames[0]
        }

        // Local Authentication presenters are dedicated system processes. If
        // they expose one eligible window, it is the tracked prompt even when
        // macOS moved or resized it while it was not frontmost.
        return acceptsMovedSingleWindow && eligibleFrames.count == 1
            ? eligibleFrames[0]
            : nil
    }
}

enum AuthenticationCoreGraphicsWindowPolicy {
    static func includes(
        isOnScreen: Bool?,
        requiresOnScreen: Bool
    ) -> Bool {
        !requiresOnScreen || isOnScreen == true
    }
}

enum AuthenticationCoreGraphicsFocusFallbackPolicy {
    static func permits(_ snapshot: AuthenticationWindowSnapshot) -> Bool {
        // SecurityAgent windows have a stable CGWindowID. Local Authentication
        // is hosted by a long-lived process that can own several identical,
        // centered windows, so only its focused AX identity is safe to select.
        snapshot.surfaceKind == .securityAgent
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
        ActiveApplicationScreenLocator.invalidate()
    }

    static func isPresenterRunning(
        _ window: AuthenticationWindowSnapshot
    ) -> Bool {
        AuthenticationPresenterMatcher.kind(
            bundleIdentifier: nil,
            executablePath: executablePath(for: window.processID)
        ) == window.surfaceKind
    }

    static func onScreenCoreGraphicsCandidates() -> [AuthenticationWindowSnapshot] {
        let windowInfo = CGWindowListCopyWindowInfo(
            [.optionOnScreenOnly, .excludeDesktopElements],
            .zero
        ) as? [[String: Any]] ?? []
        return snapshots(
            from: windowInfo,
            requiresKnownOwnerName: true,
            requiresOnScreen: true
        )
    }

    static func frontmostCandidate(
        from coreGraphicsCandidates: [AuthenticationWindowSnapshot]? = nil,
        frontmostProcessID: pid_t?
    ) -> AuthenticationWindowSnapshot? {
        let candidates = coreGraphicsCandidates ?? onScreenCoreGraphicsCandidates()

        if let candidate = AuthenticationWindowAccessibilityFallback.resolve(
            coreGraphicsCandidates: candidates,
            accessibilityCandidate: accessibilityCandidate(
                frontmostProcessID: frontmostProcessID
            )
        ) {
            return candidate
        }
        return candidates.first {
            AuthenticationCoreGraphicsFocusFallbackPolicy.permits($0)
                && isFocused($0)
        }
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
                requiresKnownOwnerName: false,
                requiresOnScreen: false
            ).first { $0.identity == identity }
        case let .accessibility(processID, elementIdentifier):
            return accessibilitySnapshot(
                processID: processID,
                elementIdentifier: elementIdentifier
            )
        }
    }

    static func snapshot(
        tracking previous: AuthenticationWindowSnapshot
    ) -> AuthenticationWindowSnapshot? {
        switch previous.identity {
        case .coreGraphics:
            guard let current = snapshot(identity: previous.identity),
                  current.processID == previous.processID,
                  current.surfaceKind == previous.surfaceKind else {
                return nil
            }
            return current
        case let .accessibility(processID, elementIdentifier):
            let verifiedExecutablePath = executablePath(for: processID)
            guard AuthenticationPresenterMatcher.kind(
                bundleIdentifier: nil,
                executablePath: verifiedExecutablePath
            ) == previous.surfaceKind else {
                return nil
            }
            guard let reference = AccessibilityFocusReader.windowReferences(
                processID: processID
            ).first(where: {
                $0.elementIdentifier == elementIdentifier
            }) else {
                return nil
            }
            return AuthenticationWindowSnapshotFactory.accessibilitySnapshot(
                processID: processID,
                elementIdentifier: reference.elementIdentifier,
                bundleIdentifier: nil,
                executablePath: verifiedExecutablePath,
                focusedFrame: reference.frame,
                displays: currentDisplays()
            )
        }
    }

    private static func coreGraphicsSnapshotsIncludingOffscreen()
        -> [AuthenticationWindowSnapshot] {
        let windowInfo = CGWindowListCopyWindowInfo(
            [.excludeDesktopElements],
            .zero
        ) as? [[String: Any]] ?? []
        return snapshots(
            from: windowInfo,
            requiresKnownOwnerName: false,
            requiresOnScreen: false
        )
    }

    private static func snapshots(
        from windowInfo: [[String: Any]],
        requiresKnownOwnerName: Bool,
        requiresOnScreen: Bool
    ) -> [AuthenticationWindowSnapshot] {
        let displays = currentDisplays()
        var surfaceKindsByProcessID: [pid_t: AuthenticationSurfaceKind] = [:]
        var unsupportedProcessIDs: Set<pid_t> = []
        return windowInfo.compactMap { info in
            guard let processIDNumber = info[kCGWindowOwnerPID as String] as? NSNumber,
                let windowIDNumber = info[kCGWindowNumber as String] as? NSNumber,
                let bounds = info[kCGWindowBounds as String] as? [String: Any] else {
                return nil
            }
            guard AuthenticationCoreGraphicsWindowPolicy.includes(
                isOnScreen: (info[kCGWindowIsOnscreen as String] as? NSNumber)?.boolValue,
                requiresOnScreen: requiresOnScreen
            ) else {
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
        guard let reference = AccessibilityFocusReader.focusedWindowReference(
            processID: processID
        ) else {
            return nil
        }
        return accessibilitySnapshot(
            processID: processID,
            elementIdentifier: reference.elementIdentifier,
            frame: reference.frame,
            bundleIdentifier: nil
        )
    }

    private static func accessibilitySnapshot(
        processID: pid_t,
        elementIdentifier: UInt,
        frame: CGRect? = nil,
        bundleIdentifier: String? = nil
    ) -> AuthenticationWindowSnapshot? {
        let verifiedExecutablePath = executablePath(for: processID)
        guard AuthenticationPresenterMatcher.kind(
            bundleIdentifier: bundleIdentifier,
            executablePath: verifiedExecutablePath
        ) == .localAuthentication else {
            return nil
        }
        let reference = frame.map {
            AccessibilityWindowReference(
                elementIdentifier: elementIdentifier,
                frame: $0
            )
        } ?? AccessibilityFocusReader.windowReferences(
            processID: processID
        ).first(where: {
            $0.elementIdentifier == elementIdentifier
        })
        guard let reference else {
            return nil
        }
        return AuthenticationWindowSnapshotFactory.accessibilitySnapshot(
            processID: processID,
            elementIdentifier: reference.elementIdentifier,
            bundleIdentifier: bundleIdentifier,
            executablePath: verifiedExecutablePath,
            focusedFrame: reference.frame,
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

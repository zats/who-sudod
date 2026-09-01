import AppKit
import CoreGraphics
import Darwin

enum AuthenticationSurfaceKind: Equatable, Sendable {
    case securityAgent
    case localAuthentication
}

enum AuthenticationWindowIdentity: Equatable, Sendable {
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
    static func frontmostCandidate() -> AuthenticationWindowSnapshot? {
        let windowInfo = CGWindowListCopyWindowInfo(
            [.optionOnScreenOnly, .excludeDesktopElements],
            .zero
        ) as? [[String: Any]] ?? []

        if let candidate = snapshots(from: windowInfo).first(where: isFocused) {
            return candidate
        }
        return accessibilityCandidate()
    }

    static func snapshot(identity: AuthenticationWindowIdentity) -> AuthenticationWindowSnapshot? {
        switch identity {
        case let .coreGraphics(windowID):
            let windowInfo = CGWindowListCopyWindowInfo(
                [.optionIncludingWindow],
                windowID
            ) as? [[String: Any]] ?? []
            return snapshots(from: windowInfo).first { $0.identity == identity }
        case let .accessibility(processID):
            return accessibilitySnapshot(processID: processID)
        }
    }

    private static func snapshots(from windowInfo: [[String: Any]]) -> [AuthenticationWindowSnapshot] {
        let displays = currentDisplays()
        return windowInfo.compactMap { info in
            guard
                let processIDNumber = info[kCGWindowOwnerPID as String] as? NSNumber,
                let windowIDNumber = info[kCGWindowNumber as String] as? NSNumber,
                let bounds = info[kCGWindowBounds as String] as? [String: Any],
                (info[kCGWindowIsOnscreen as String] as? NSNumber)?.boolValue == true
            else {
                return nil
            }

            let processID = pid_t(processIDNumber.int32Value)
            guard let surfaceKind = authenticationSurfaceKind(processID: processID) else {
                return nil
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

    private static func accessibilityCandidate() -> AuthenticationWindowSnapshot? {
        for application in NSWorkspace.shared.runningApplications {
            let processID = application.processIdentifier
            guard let snapshot = accessibilitySnapshot(processID: processID) else {
                continue
            }
            guard isFocused(snapshot) else {
                continue
            }
            return snapshot
        }
        return nil
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
        AuthenticationWindowSnapshotFactory.accessibilitySnapshot(
            processID: processID,
            bundleIdentifier: NSRunningApplication(
                processIdentifier: processID
            )?.bundleIdentifier,
            executablePath: executablePath(for: processID),
            focusedFrame: AccessibilityFocusReader.focusedWindowFrame(
                processID: processID
            ),
            displays: currentDisplays()
        )
    }

    private static func authenticationSurfaceKind(processID: pid_t) -> AuthenticationSurfaceKind? {
        let bundleIdentifier = NSRunningApplication(processIdentifier: processID)?.bundleIdentifier
        return AuthenticationPresenterMatcher.kind(
            bundleIdentifier: bundleIdentifier,
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

    private static func currentDisplays() -> [DisplayGeometry] {
        NSScreen.screens.compactMap { screen in
            guard let number = screen.deviceDescription[.init("NSScreenNumber")] as? NSNumber else {
                return nil
            }
            return DisplayGeometry(
                appKitFrame: screen.frame,
                visibleFrame: screen.visibleFrame,
                coreGraphicsFrame: CGDisplayBounds(CGDirectDisplayID(number.uint32Value))
            )
        }
    }

    private static func number(_ value: Any?) -> CGFloat {
        CGFloat((value as? NSNumber)?.doubleValue ?? 0)
    }
}

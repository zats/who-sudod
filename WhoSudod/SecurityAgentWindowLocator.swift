import AppKit
import CoreGraphics
import Darwin

struct SecurityAgentWindowSnapshot: Equatable {
    let windowID: CGWindowID
    let processID: pid_t
    let coreGraphicsFrame: CGRect
    let frame: CGRect
    let visibleFrame: CGRect
}

@MainActor
enum SecurityAgentWindowLocator {
    private static let bundleIdentifier = "com.apple.SecurityAgent"
    private static let executablePath = "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent"

    static func frontmostCandidate() -> SecurityAgentWindowSnapshot? {
        guard let windowInfo = CGWindowListCopyWindowInfo(
            [.optionOnScreenOnly, .excludeDesktopElements],
            .zero
        ) as? [[String: Any]] else {
            return nil
        }

        return snapshots(from: windowInfo).max { lhs, rhs in
            lhs.frame.width * lhs.frame.height < rhs.frame.width * rhs.frame.height
        }
    }

    static func snapshot(windowID: CGWindowID) -> SecurityAgentWindowSnapshot? {
        guard let windowInfo = CGWindowListCopyWindowInfo(
            [.optionIncludingWindow],
            windowID
        ) as? [[String: Any]] else {
            return nil
        }
        return snapshots(from: windowInfo).first { $0.windowID == windowID }
    }

    private static func snapshots(from windowInfo: [[String: Any]]) -> [SecurityAgentWindowSnapshot] {
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
            guard isSecurityAgent(processID: processID) else {
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

            return SecurityAgentWindowSnapshot(
                windowID: CGWindowID(windowIDNumber.uint32Value),
                processID: processID,
                coreGraphicsFrame: frame,
                frame: geometry.frame,
                visibleFrame: geometry.visibleFrame
            )
        }
    }

    private static func isSecurityAgent(processID: pid_t) -> Bool {
        if NSRunningApplication(processIdentifier: processID)?.bundleIdentifier == bundleIdentifier {
            return true
        }

        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let length = buffer.withUnsafeMutableBytes { bytes in
            proc_pidpath(processID, bytes.baseAddress, UInt32(bytes.count))
        }
        let path = String(
            decoding: buffer.prefix { $0 != 0 }.map(UInt8.init(bitPattern:)),
            as: UTF8.self
        )
        return length > 0 && path == executablePath
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

import AppKit
import ApplicationServices

enum AccessibilityWindowFocusResolver {
    static func resolve(
        frameMatches: Bool,
        focused: Bool?,
        main: Bool?,
        frontmost: Bool?
    ) -> Bool? {
        if frontmost == false {
            return false
        }

        let windowIsActive: Bool?
        if focused == true || main == true {
            windowIsActive = true
        } else if focused != nil || main != nil {
            windowIsActive = false
        } else {
            windowIsActive = nil
        }

        if windowIsActive == false {
            return false
        }
        if frameMatches {
            return windowIsActive ?? frontmost
        }

        // CG and AX can report adjacent frames while the window is moving.
        // A known presenter process that is active and frontmost is still the
        // same authentication surface during this short update gap.
        if windowIsActive == true, frontmost == true {
            return true
        }
        return nil
    }
}

enum AccessibilityFocusReader {
    static var isTrusted: Bool {
        AXIsProcessTrusted()
    }

    static func isFrontmost(processID: pid_t) -> Bool? {
        if let application = NSRunningApplication(processIdentifier: processID) {
            return application.isActive
        }
        guard isTrusted else {
            return nil
        }

        let application = AXUIElementCreateApplication(processID)
        var value: CFTypeRef?
        guard AXUIElementCopyAttributeValue(
            application,
            kAXFrontmostAttribute as CFString,
            &value
        ) == .success else {
            return nil
        }
        return (value as? NSNumber)?.boolValue
    }

    /// Returns the focused AX window frame in the global, top-left-origin
    /// coordinate space used by `CGWindow` bounds.
    static func focusedWindowFrame(processID: pid_t) -> CGRect? {
        guard isTrusted else {
            return nil
        }
        guard let focusedWindow = focusedWindow(processID: processID) else {
            return nil
        }
        guard let position = pointAttribute(kAXPositionAttribute, from: focusedWindow),
              let size = sizeAttribute(kAXSizeAttribute, from: focusedWindow) else {
            return nil
        }
        return CGRect(origin: position, size: size)
    }

    static func isFocusedWindow(
        processID: pid_t,
        matchingCoreGraphicsFrame expectedFrame: CGRect,
        tolerance: CGFloat = 2
    ) -> Bool? {
        guard isTrusted,
              let focusedWindow = focusedWindow(processID: processID),
              let position = pointAttribute(kAXPositionAttribute, from: focusedWindow),
              let size = sizeAttribute(kAXSizeAttribute, from: focusedWindow) else {
            return nil
        }
        let focusedFrame = CGRect(origin: position, size: size)

        let frameMatches = abs(focusedFrame.minX - expectedFrame.minX) <= tolerance
            && abs(focusedFrame.minY - expectedFrame.minY) <= tolerance
            && abs(focusedFrame.width - expectedFrame.width) <= tolerance
            && abs(focusedFrame.height - expectedFrame.height) <= tolerance
        let focused = booleanAttribute(kAXFocusedAttribute, from: focusedWindow)
        let main = booleanAttribute(kAXMainAttribute, from: focusedWindow)
        return AccessibilityWindowFocusResolver.resolve(
            frameMatches: frameMatches,
            focused: focused,
            main: main,
            frontmost: isFrontmost(processID: processID)
        )
    }

    private static func focusedWindow(processID: pid_t) -> AXUIElement? {
        let application = AXUIElementCreateApplication(processID)
        var focusedWindowValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(
            application,
            kAXFocusedWindowAttribute as CFString,
            &focusedWindowValue
        ) == .success,
        let focusedWindowValue,
        CFGetTypeID(focusedWindowValue) == AXUIElementGetTypeID() else {
            return nil
        }
        return unsafeDowncast(focusedWindowValue, to: AXUIElement.self)
    }

    private static func booleanAttribute(
        _ attribute: String,
        from element: AXUIElement
    ) -> Bool? {
        var attributeValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(
            element,
            attribute as CFString,
            &attributeValue
        ) == .success else {
            return nil
        }
        return (attributeValue as? NSNumber)?.boolValue
    }

    private static func pointAttribute(
        _ attribute: String,
        from element: AXUIElement
    ) -> CGPoint? {
        var attributeValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(
            element,
            attribute as CFString,
            &attributeValue
        ) == .success,
        let attributeValue,
        CFGetTypeID(attributeValue) == AXValueGetTypeID() else {
            return nil
        }

        let value = unsafeDowncast(attributeValue, to: AXValue.self)
        guard AXValueGetType(value) == .cgPoint else {
            return nil
        }
        var point = CGPoint.zero
        return AXValueGetValue(value, .cgPoint, &point) ? point : nil
    }

    private static func sizeAttribute(
        _ attribute: String,
        from element: AXUIElement
    ) -> CGSize? {
        var attributeValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(
            element,
            attribute as CFString,
            &attributeValue
        ) == .success,
        let attributeValue,
        CFGetTypeID(attributeValue) == AXValueGetTypeID() else {
            return nil
        }

        let value = unsafeDowncast(attributeValue, to: AXValue.self)
        guard AXValueGetType(value) == .cgSize else {
            return nil
        }
        var size = CGSize.zero
        return AXValueGetValue(value, .cgSize, &size) ? size : nil
    }
}

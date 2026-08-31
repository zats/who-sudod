import AppKit
import ApplicationServices

enum AccessibilityFocusReader {
    static var isTrusted: Bool {
        AXIsProcessTrusted()
    }

    static func isFrontmost(processID: pid_t) -> Bool? {
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

        let focusedWindow = unsafeDowncast(focusedWindowValue, to: AXUIElement.self)
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
        guard let frontmost = isFrontmost(processID: processID) else {
            return nil
        }
        guard frontmost else {
            return false
        }
        guard let focusedFrame = focusedWindowFrame(processID: processID) else {
            return nil
        }

        return abs(focusedFrame.minX - expectedFrame.minX) <= tolerance
            && abs(focusedFrame.minY - expectedFrame.minY) <= tolerance
            && abs(focusedFrame.width - expectedFrame.width) <= tolerance
            && abs(focusedFrame.height - expectedFrame.height) <= tolerance
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

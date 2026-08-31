import CoreGraphics

enum AuthorizationPanelMetrics {
    static let dialogPadding: CGFloat = 20
    static let systemDialogCornerRadius: CGFloat = 26
    static var envelopeCornerRadius: CGFloat {
        systemDialogCornerRadius + dialogPadding
    }
}

struct DisplayGeometry: Equatable, Sendable {
    let appKitFrame: CGRect
    let visibleFrame: CGRect
    let coreGraphicsFrame: CGRect
}

struct ConvertedWindowGeometry: Equatable, Sendable {
    let frame: CGRect
    let visibleFrame: CGRect
}

enum SidecarSide: Equatable, Sendable {
    case left
    case right
}

struct SidecarGeometry: Equatable, Sendable {
    let frame: CGRect
    let side: SidecarSide
    let reservedDialogWidth: CGFloat
}

enum WindowGeometry {
    static func convert(
        coreGraphicsFrame: CGRect,
        displays: [DisplayGeometry]
    ) -> ConvertedWindowGeometry? {
        guard let display = displays.max(by: { lhs, rhs in
            intersectionArea(lhs.coreGraphicsFrame, coreGraphicsFrame)
                < intersectionArea(rhs.coreGraphicsFrame, coreGraphicsFrame)
        }), intersectionArea(display.coreGraphicsFrame, coreGraphicsFrame) > 0 else {
            return nil
        }

        let localX = coreGraphicsFrame.minX - display.coreGraphicsFrame.minX
        let localY = coreGraphicsFrame.minY - display.coreGraphicsFrame.minY
        let frame = CGRect(
            x: display.appKitFrame.minX + localX,
            y: display.appKitFrame.maxY - localY - coreGraphicsFrame.height,
            width: coreGraphicsFrame.width,
            height: coreGraphicsFrame.height
        )
        return ConvertedWindowGeometry(frame: frame, visibleFrame: display.visibleFrame)
    }

    static func sidecarFrame(
        authenticationFrame: CGRect,
        visibleFrame: CGRect,
        desiredContentWidth: CGFloat = 640,
        dialogPadding: CGFloat = AuthorizationPanelMetrics.dialogPadding,
        margin: CGFloat = 8
    ) -> SidecarGeometry {
        let rightContentSpace = max(
            0,
            visibleFrame.maxX - margin - authenticationFrame.maxX - dialogPadding
        )
        let leftContentSpace = max(
            0,
            authenticationFrame.minX - dialogPadding - visibleFrame.minX - margin
        )
        let contentWidth = min(
            desiredContentWidth,
            max(rightContentSpace, leftContentSpace)
        )
        let reservedDialogWidth = authenticationFrame.width + 2 * dialogPadding
        let width = reservedDialogWidth + contentWidth
        let useRight = rightContentSpace >= contentWidth
        let x = useRight
            ? authenticationFrame.minX - dialogPadding
            : authenticationFrame.maxX + dialogPadding - width

        return SidecarGeometry(
            frame: CGRect(
                x: x,
                y: authenticationFrame.minY - dialogPadding,
                width: width,
                height: authenticationFrame.height + 2 * dialogPadding
            ),
            side: useRight ? .right : .left,
            reservedDialogWidth: reservedDialogWidth
        )
    }

    private static func intersectionArea(_ lhs: CGRect, _ rhs: CGRect) -> CGFloat {
        let intersection = lhs.intersection(rhs)
        guard !intersection.isNull else {
            return 0
        }
        return intersection.width * intersection.height
    }
}

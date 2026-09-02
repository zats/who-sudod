import CoreGraphics

enum AuthorizationPanelMetrics {
    static let dialogPadding: CGFloat = 20
    static let systemDialogCornerRadius: CGFloat = 26
    static var envelopeCornerRadius: CGFloat {
        systemDialogCornerRadius + dialogPadding
    }
}

enum ProcessPanelMetrics {
    static let regularWindowCornerRadius: CGFloat = 12
    static let tableHorizontalInset: CGFloat = 12
    static let advancedContentWidth: CGFloat = 640
    static let simpleTableWidthFraction: CGFloat = 0.30
    static let modeControlDiameter: CGFloat = 28
    static let modeControlWindowMargin: CGFloat = modeControlDiameter / 2
    static let modeControlSymbolOpticalOffset: CGFloat = 1

    static func contentWidth(
        for mode: ProcessDisplayMode,
        availableAdvancedContentWidth: CGFloat
    ) -> CGFloat {
        let availableWidth = max(0, availableAdvancedContentWidth)
        guard mode == .simple else {
            return availableWidth
        }

        let horizontalInsets = min(2 * tableHorizontalInset, availableWidth)
        let tableWidth = max(0, availableWidth - horizontalInsets)
        return horizontalInsets + tableWidth * simpleTableWidthFraction
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

struct SidecarTransitionGeometry: Equatable, Sendable {
    let destination: SidecarGeometry
    let departureBridge: SidecarGeometry?
    let arrivalBridge: SidecarGeometry?
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
        displayMode: ProcessDisplayMode = .fullTree,
        desiredAdvancedContentWidth: CGFloat = ProcessPanelMetrics.advancedContentWidth,
        dialogPadding: CGFloat = AuthorizationPanelMetrics.dialogPadding,
        margin: CGFloat = 8
    ) -> SidecarGeometry {
        let controlMargin = ProcessPanelMetrics.modeControlWindowMargin
        let rightContentSpace = max(
            0,
            visibleFrame.maxX
                - margin
                - authenticationFrame.maxX
                - dialogPadding
                - controlMargin
        )
        let leftContentSpace = max(
            0,
            authenticationFrame.minX
                - dialogPadding
                - visibleFrame.minX
                - margin
                - controlMargin
        )
        let desiredContentWidth = ProcessPanelMetrics.contentWidth(
            for: displayMode,
            availableAdvancedContentWidth: desiredAdvancedContentWidth
        )
        let useRight: Bool
        if rightContentSpace >= desiredContentWidth {
            useRight = true
        } else if leftContentSpace >= desiredContentWidth {
            useRight = false
        } else {
            useRight = rightContentSpace >= leftContentSpace
        }
        let availableContentWidth = useRight ? rightContentSpace : leftContentSpace
        let contentWidth = min(desiredContentWidth, availableContentWidth)
        return sidecarFrame(
            authenticationFrame: authenticationFrame,
            side: useRight ? .right : .left,
            contentWidth: contentWidth,
            dialogPadding: dialogPadding
        )
    }

    static func sidecarFrame(
        authenticationFrame: CGRect,
        side: SidecarSide,
        contentWidth: CGFloat,
        dialogPadding: CGFloat = AuthorizationPanelMetrics.dialogPadding
    ) -> SidecarGeometry {
        let controlMargin = ProcessPanelMetrics.modeControlWindowMargin
        let reservedDialogWidth = authenticationFrame.width + 2 * dialogPadding
        let clampedContentWidth = max(0, contentWidth)
        let materialWidth = reservedDialogWidth + clampedContentWidth
        let width = materialWidth + controlMargin
        let materialX = switch side {
        case .right:
            authenticationFrame.minX - dialogPadding
        case .left:
            authenticationFrame.maxX + dialogPadding - materialWidth
        }
        let x = side == .right ? materialX : materialX - controlMargin

        return SidecarGeometry(
            frame: CGRect(
                x: x,
                y: authenticationFrame.minY - dialogPadding,
                width: width,
                height: authenticationFrame.height + 2 * dialogPadding
            ),
            side: side,
            reservedDialogWidth: reservedDialogWidth
        )
    }

    static func standaloneSidecarFrame(
        anchorFrame: CGRect,
        visibleFrame: CGRect,
        displayMode: ProcessDisplayMode,
        desiredAdvancedContentWidth: CGFloat = ProcessPanelMetrics.advancedContentWidth,
        desiredHeight: CGFloat = 320,
        margin: CGFloat = 8
    ) -> SidecarGeometry {
        let controlMargin = ProcessPanelMetrics.modeControlWindowMargin
        let maximumContentWidth = max(
            0,
            visibleFrame.width - 2 * margin - controlMargin
        )
        let desiredContentWidth = ProcessPanelMetrics.contentWidth(
            for: displayMode,
            availableAdvancedContentWidth: desiredAdvancedContentWidth
        )
        let contentWidth = min(desiredContentWidth, maximumContentWidth)
        let panelWidth = contentWidth + controlMargin
        let panelHeight = min(
            desiredHeight,
            max(0, visibleFrame.height - 2 * margin)
        )
        let rightSpace = max(0, visibleFrame.maxX - margin - anchorFrame.maxX)
        let leftSpace = max(0, anchorFrame.minX - visibleFrame.minX - margin)

        let side: SidecarSide
        let x: CGFloat
        if rightSpace >= panelWidth {
            side = .right
            x = anchorFrame.maxX + margin
        } else if leftSpace >= panelWidth {
            side = .left
            x = anchorFrame.minX - margin - panelWidth
        } else if anchorFrame.midX <= visibleFrame.midX {
            side = .right
            x = min(
                visibleFrame.maxX - margin - panelWidth,
                max(visibleFrame.minX + margin, anchorFrame.maxX - panelWidth)
            )
        } else {
            side = .left
            x = min(
                visibleFrame.maxX - margin - panelWidth,
                max(visibleFrame.minX + margin, anchorFrame.minX)
            )
        }
        let y = min(
            visibleFrame.maxY - margin - panelHeight,
            max(visibleFrame.minY + margin, anchorFrame.midY - panelHeight / 2)
        )

        return SidecarGeometry(
            frame: CGRect(x: x, y: y, width: panelWidth, height: panelHeight),
            side: side,
            reservedDialogWidth: 0
        )
    }

    static func transition(
        from source: SidecarGeometry,
        to destination: SidecarGeometry,
        authenticationFrame: CGRect
    ) -> SidecarTransitionGeometry {
        guard source.side != destination.side else {
            return SidecarTransitionGeometry(
                destination: destination,
                departureBridge: nil,
                arrivalBridge: nil
            )
        }

        let bridgeContentWidth = min(
            2 * ProcessPanelMetrics.tableHorizontalInset,
            contentWidth(in: source),
            contentWidth(in: destination)
        )
        return SidecarTransitionGeometry(
            destination: destination,
            departureBridge: sidecarFrame(
                authenticationFrame: authenticationFrame,
                side: source.side,
                contentWidth: bridgeContentWidth
            ),
            arrivalBridge: sidecarFrame(
                authenticationFrame: authenticationFrame,
                side: destination.side,
                contentWidth: bridgeContentWidth
            )
        )
    }

    static func standaloneTransition(
        from source: SidecarGeometry,
        to destination: SidecarGeometry
    ) -> SidecarTransitionGeometry {
        guard source.side != destination.side else {
            return SidecarTransitionGeometry(
                destination: destination,
                departureBridge: nil,
                arrivalBridge: nil
            )
        }

        let bridgeContentWidth = min(
            2 * ProcessPanelMetrics.tableHorizontalInset,
            contentWidth(in: source),
            contentWidth(in: destination)
        )
        return SidecarTransitionGeometry(
            destination: destination,
            departureBridge: standaloneBridge(
                from: source,
                contentWidth: bridgeContentWidth
            ),
            arrivalBridge: standaloneBridge(
                from: destination,
                contentWidth: bridgeContentWidth
            )
        )
    }

    static func contentWidth(in geometry: SidecarGeometry) -> CGFloat {
        max(
            0,
            geometry.frame.width
                - geometry.reservedDialogWidth
                - ProcessPanelMetrics.modeControlWindowMargin
        )
    }

    private static func standaloneBridge(
        from geometry: SidecarGeometry,
        contentWidth: CGFloat
    ) -> SidecarGeometry {
        let width = max(0, contentWidth) + ProcessPanelMetrics.modeControlWindowMargin
        let x = switch geometry.side {
        case .right:
            geometry.frame.minX
        case .left:
            geometry.frame.maxX - width
        }
        return SidecarGeometry(
            frame: CGRect(
                x: x,
                y: geometry.frame.minY,
                width: width,
                height: geometry.frame.height
            ),
            side: geometry.side,
            reservedDialogWidth: 0
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

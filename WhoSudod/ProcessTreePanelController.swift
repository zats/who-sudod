import AppKit
import os
import QuartzCore

@MainActor
final class ProcessTreePanelController: NSWindowController {
    private let content: CompanionContentView
    private var displayMode: ProcessDisplayMode
    private var currentSnapshot: AuthenticationProcessSnapshot?
    private var currentSurfaceKind: AuthenticationSurfaceKind?
    private var currentAuthenticationFrame: CGRect?
    private var currentVisibleFrame: CGRect?
    private var currentSidecar: SidecarGeometry?
    private var currentAttachmentSide: SidecarSide?
    private var geometryTransitionGeneration = 0
    private var activeGeometryTransitionGeneration: Int?
    private var activeGeometryTransitionTarget: SidecarGeometry?
    private var currentPromptSequence = 0
    private(set) var isPresented = false
#if DEBUG
    private let logger = Logger(subsystem: "com.zats.WhoSudo", category: "LiveTreeDiagnostics")
    private var liveTreeDiagnostics = LiveTreeDiagnostics()
#endif

    init(
        displayMode: ProcessDisplayMode = .simple,
        displayModeRequestHandler: @escaping (ProcessDisplayMode) -> Void = { _ in }
    ) {
        self.displayMode = displayMode
        content = CompanionContentView(
            displayMode: displayMode,
            displayModeRequestHandler: displayModeRequestHandler
        )
        let panel = PassivePanel(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 320),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        super.init(window: panel)
        configure(panel)
        panel.contentView = content
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func show(
        snapshot: AuthenticationProcessSnapshot,
        promptSequence: Int,
        surfaceKind: AuthenticationSurfaceKind,
        authenticationFrame: CGRect,
        visibleFrame: CGRect
    ) {
        guard let window else {
            return
        }

        if snapshot != currentSnapshot {
            currentSnapshot = snapshot
            content.update(snapshot: snapshot)
        }
        currentPromptSequence = promptSequence
        currentSurfaceKind = surfaceKind
        currentAuthenticationFrame = authenticationFrame
        currentVisibleFrame = visibleFrame

        let target = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame,
            displayMode: displayMode
        )
        if let activeGeometryTransitionTarget {
            if !approximatelyEqual(target, activeGeometryTransitionTarget) {
                cancelGeometryTransition()
                applyPanelGeometry(target)
            }
        } else {
            applyPanelGeometry(target)
        }
        if !isPresented {
            window.orderFrontRegardless()
            isPresented = true
        }
#if DEBUG
        if activeGeometryTransitionGeneration == nil, window.isVisible {
            window.displayIfNeeded()
            recordVisibleLiveTree()
        }
#endif
    }

    func hide(promptPresent: Bool, accessibilityTrusted: Bool) {
        cancelGeometryTransition()
        if isPresented {
            window?.orderOut(nil)
            isPresented = false
        }
#if DEBUG
        do {
            try liveTreeDiagnostics?.recordHidden(
                accessibilityTrusted: accessibilityTrusted,
                promptSequence: currentPromptSequence,
                promptPresent: promptPresent
            )
        } catch {
            logger.error("Could not write live tree state: \(error.localizedDescription, privacy: .public)")
            liveTreeDiagnostics = nil
        }
#endif
    }

    func setDisplayMode(_ mode: ProcessDisplayMode) {
        guard mode != displayMode else {
            return
        }
        displayMode = mode
        content.setDisplayMode(mode)
        guard isPresented,
              let window,
              let currentAuthenticationFrame,
              let currentVisibleFrame else {
            return
        }

        let destination = WindowGeometry.sidecarFrame(
            authenticationFrame: currentAuthenticationFrame,
            visibleFrame: currentVisibleFrame,
            displayMode: mode
        )
        let source = SidecarGeometry(
            frame: window.frame,
            side: currentAttachmentSide ?? currentSidecar?.side ?? destination.side,
            reservedDialogWidth: destination.reservedDialogWidth
        )
        let transition = WindowGeometry.transition(
            from: source,
            to: destination,
            authenticationFrame: currentAuthenticationFrame
        )
        startGeometryTransition(transition)
    }

    func recordReadiness(accessibilityTrusted: Bool) {
#if DEBUG
        guard !isPresented else {
            return
        }
        do {
            try liveTreeDiagnostics?.recordReadiness(
                accessibilityTrusted: accessibilityTrusted,
                promptSequence: currentPromptSequence
            )
        } catch {
            logger.error("Could not write live tree state: \(error.localizedDescription, privacy: .public)")
            liveTreeDiagnostics = nil
        }
#endif
    }

    private func configure(_ panel: NSPanel) {
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.level = .statusBar
        panel.hasShadow = true
        panel.hidesOnDeactivate = false
        panel.ignoresMouseEvents = false
        panel.animationBehavior = .none
        panel.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle, .fullScreenAuxiliary]
        panel.setAccessibilityIdentifier("who-sudod.process-tree.panel")
    }

    private func applyPanelGeometry(_ sidecar: SidecarGeometry) {
        guard let window else {
            return
        }
        content.setAttachmentSide(
            sidecar.side,
            reservedDialogWidth: sidecar.reservedDialogWidth
        )
        currentAttachmentSide = sidecar.side
        currentSidecar = sidecar

        guard window.frame != sidecar.frame else {
            return
        }
        if window.frame.size == sidecar.frame.size {
            window.setFrameOrigin(sidecar.frame.origin)
        } else {
            window.setFrame(sidecar.frame, display: isPresented)
            content.frame = NSRect(origin: .zero, size: sidecar.frame.size)
        }
    }

    private func startGeometryTransition(_ transition: SidecarTransitionGeometry) {
        guard let window else {
            return
        }
        cancelGeometryTransition()

        if window.frame == transition.destination.frame,
           currentAttachmentSide == transition.destination.side {
            setAttachment(for: transition.destination)
            currentSidecar = transition.destination
#if DEBUG
            if window.isVisible {
                window.displayIfNeeded()
                recordVisibleLiveTree()
            }
#endif
            return
        }

        let generation = geometryTransitionGeneration
        activeGeometryTransitionGeneration = generation
        activeGeometryTransitionTarget = transition.destination
        if let departureBridge = transition.departureBridge,
           let arrivalBridge = transition.arrivalBridge {
            setAttachment(for: departureBridge)
            animateWindow(
                to: departureBridge.frame,
                duration: 0.10,
                generation: generation
            ) { [weak self] in
                self?.continueTransition(
                    from: arrivalBridge,
                    to: transition.destination,
                    generation: generation
                )
            }
        } else {
            setAttachment(for: transition.destination)
            animateWindow(
                to: transition.destination.frame,
                duration: 0.22,
                generation: generation
            ) { [weak self] in
                self?.finishTransition(
                    at: transition.destination,
                    generation: generation
                )
            }
        }
    }

    private func continueTransition(
        from arrivalBridge: SidecarGeometry,
        to destination: SidecarGeometry,
        generation: Int
    ) {
        guard activeGeometryTransitionGeneration == generation,
              let window else {
            return
        }
        setAttachment(for: arrivalBridge)
        window.setFrame(arrivalBridge.frame, display: true)
        content.frame = NSRect(origin: .zero, size: arrivalBridge.frame.size)
        animateWindow(
            to: destination.frame,
            duration: 0.18,
            generation: generation
        ) { [weak self] in
            self?.finishTransition(at: destination, generation: generation)
        }
    }

    private func finishTransition(
        at destination: SidecarGeometry,
        generation: Int
    ) {
        guard activeGeometryTransitionGeneration == generation,
              let window else {
            return
        }
        activeGeometryTransitionGeneration = nil
        activeGeometryTransitionTarget = nil
        setAttachment(for: destination)
        currentSidecar = destination
        window.setFrame(destination.frame, display: true)
        content.frame = NSRect(origin: .zero, size: destination.frame.size)
#if DEBUG
        if window.isVisible {
            window.displayIfNeeded()
            recordVisibleLiveTree()
        }
#endif
    }

    private func setAttachment(for geometry: SidecarGeometry) {
        content.setAttachmentSide(
            geometry.side,
            reservedDialogWidth: geometry.reservedDialogWidth
        )
        currentAttachmentSide = geometry.side
    }

    private func animateWindow(
        to frame: CGRect,
        duration: TimeInterval,
        generation: Int,
        completion: @escaping @MainActor () -> Void
    ) {
        guard let window else {
            return
        }
        NSAnimationContext.runAnimationGroup { context in
            context.duration = duration
            context.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
            window.animator().setFrame(frame, display: true)
        } completionHandler: { [weak self] in
            Task { @MainActor in
                guard self?.activeGeometryTransitionGeneration == generation else {
                    return
                }
                completion()
            }
        }
    }

    private func cancelGeometryTransition() {
        if activeGeometryTransitionGeneration != nil, let window {
            window.setFrame(window.frame, display: true)
            content.frame = NSRect(origin: .zero, size: window.frame.size)
        }
        geometryTransitionGeneration += 1
        activeGeometryTransitionGeneration = nil
        activeGeometryTransitionTarget = nil
    }

    private func approximatelyEqual(
        _ lhs: SidecarGeometry,
        _ rhs: SidecarGeometry,
        tolerance: CGFloat = 1
    ) -> Bool {
        lhs.side == rhs.side
            && abs(lhs.reservedDialogWidth - rhs.reservedDialogWidth) <= tolerance
            && abs(lhs.frame.minX - rhs.frame.minX) <= tolerance
            && abs(lhs.frame.minY - rhs.frame.minY) <= tolerance
            && abs(lhs.frame.width - rhs.frame.width) <= tolerance
            && abs(lhs.frame.height - rhs.frame.height) <= tolerance
    }

#if DEBUG
    private func recordVisibleLiveTree() {
        guard let snapshot = currentSnapshot,
              let surfaceKind = currentSurfaceKind else {
            return
        }
        do {
            try liveTreeDiagnostics?.recordVisible(
                promptSequence: currentPromptSequence,
                surfaceKind: surfaceKind,
                snapshot: snapshot,
                renderedTable: content.renderedTable
            )
        } catch {
            logger.error("Could not write live tree state: \(error.localizedDescription, privacy: .public)")
            liveTreeDiagnostics = nil
        }
    }
#endif
}

private final class PassivePanel: NSPanel {
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

@MainActor
final class CompanionContentView: NSView {
    private let processTable: ProcessTableView
    private let material = NSVisualEffectView()
    private let tint = PanelTintView()
    private let body = HoverTrackingView()
    private let modeControl = ProcessModeToggleControl()
    private var materialSideConstraints: [NSLayoutConstraint] = []
    private var bodySideConstraints: [NSLayoutConstraint] = []
    private var tableSideConstraints: [NSLayoutConstraint] = []
    private var modeControlSideConstraints: [NSLayoutConstraint] = []
    private var attachmentSide: SidecarSide?
    private var reservedDialogWidth: CGFloat = 0

    init(
        frame frameRect: NSRect = .zero,
        displayMode: ProcessDisplayMode,
        displayModeRequestHandler: @escaping (ProcessDisplayMode) -> Void = { _ in }
    ) {
        processTable = ProcessTableView(frame: .zero, displayMode: displayMode)
        super.init(frame: frameRect)
        modeControl.onModeRequest = { mode in
            displayModeRequestHandler(mode)
        }
        modeControl.setDisplayMode(displayMode)
        configure()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(snapshot: AuthenticationProcessSnapshot) {
        processTable.update(snapshot: snapshot)
    }

    func setDisplayMode(_ mode: ProcessDisplayMode) {
        processTable.setDisplayMode(mode)
        modeControl.setDisplayMode(mode)
    }

    var renderedTable: RenderedProcessTable {
        processTable.renderedTable()
    }

    func setAttachmentSide(_ side: SidecarSide, reservedDialogWidth: CGFloat) {
        guard side != attachmentSide || reservedDialogWidth != self.reservedDialogWidth else {
            return
        }
        NSLayoutConstraint.deactivate(materialSideConstraints)
        NSLayoutConstraint.deactivate(bodySideConstraints)
        NSLayoutConstraint.deactivate(tableSideConstraints)
        NSLayoutConstraint.deactivate(modeControlSideConstraints)
        if side == .right {
            materialSideConstraints = [
                material.leadingAnchor.constraint(equalTo: leadingAnchor),
                material.trailingAnchor.constraint(
                    equalTo: trailingAnchor,
                    constant: -ProcessPanelMetrics.modeControlWindowMargin
                )
            ]
            bodySideConstraints = [
                body.leadingAnchor.constraint(
                    equalTo: material.leadingAnchor,
                    constant: reservedDialogWidth
                ),
                body.trailingAnchor.constraint(equalTo: trailingAnchor)
            ]
            tableSideConstraints = [
                processTable.leadingAnchor.constraint(
                    equalTo: body.leadingAnchor,
                    constant: ProcessPanelMetrics.tableHorizontalInset
                ),
                processTable.trailingAnchor.constraint(
                    equalTo: material.trailingAnchor,
                    constant: -ProcessPanelMetrics.tableHorizontalInset
                )
            ]
            modeControlSideConstraints = [
                modeControl.centerXAnchor.constraint(equalTo: material.trailingAnchor)
            ]
        } else {
            materialSideConstraints = [
                material.leadingAnchor.constraint(
                    equalTo: leadingAnchor,
                    constant: ProcessPanelMetrics.modeControlWindowMargin
                ),
                material.trailingAnchor.constraint(equalTo: trailingAnchor)
            ]
            bodySideConstraints = [
                body.leadingAnchor.constraint(equalTo: leadingAnchor),
                body.trailingAnchor.constraint(
                    equalTo: material.trailingAnchor,
                    constant: -reservedDialogWidth
                )
            ]
            tableSideConstraints = [
                processTable.leadingAnchor.constraint(
                    equalTo: material.leadingAnchor,
                    constant: ProcessPanelMetrics.tableHorizontalInset
                ),
                processTable.trailingAnchor.constraint(
                    equalTo: body.trailingAnchor,
                    constant: -ProcessPanelMetrics.tableHorizontalInset
                )
            ]
            modeControlSideConstraints = [
                modeControl.centerXAnchor.constraint(equalTo: material.leadingAnchor)
            ]
        }
        NSLayoutConstraint.activate(materialSideConstraints)
        NSLayoutConstraint.activate(bodySideConstraints)
        NSLayoutConstraint.activate(tableSideConstraints)
        NSLayoutConstraint.activate(modeControlSideConstraints)
        modeControl.setAttachmentSide(side)
        attachmentSide = side
        self.reservedDialogWidth = reservedDialogWidth
    }

    private func configure() {
        wantsLayer = true
        layer?.backgroundColor = NSColor.clear.cgColor
        autoresizingMask = [.width, .height]

        material.translatesAutoresizingMaskIntoConstraints = false
        material.material = .popover
        material.blendingMode = .behindWindow
        material.state = .active
        material.wantsLayer = true
        material.layer?.cornerRadius = AuthorizationPanelMetrics.envelopeCornerRadius
        material.layer?.cornerCurve = .continuous
        material.layer?.masksToBounds = true
        material.layer?.borderWidth = 0.5
        addSubview(material)

        tint.translatesAutoresizingMaskIntoConstraints = false
        material.addSubview(tint)

        processTable.translatesAutoresizingMaskIntoConstraints = false
        material.addSubview(processTable)

        body.translatesAutoresizingMaskIntoConstraints = false
        body.onHoverChange = { [weak modeControl] isHovered in
            modeControl?.setHovered(isHovered)
        }
        addSubview(body)

        modeControl.translatesAutoresizingMaskIntoConstraints = false
        body.addSubview(modeControl)
        NSLayoutConstraint.activate([
            material.topAnchor.constraint(equalTo: topAnchor),
            material.bottomAnchor.constraint(equalTo: bottomAnchor),

            tint.topAnchor.constraint(equalTo: material.topAnchor),
            tint.leadingAnchor.constraint(equalTo: material.leadingAnchor),
            tint.trailingAnchor.constraint(equalTo: material.trailingAnchor),
            tint.bottomAnchor.constraint(equalTo: material.bottomAnchor),

            body.topAnchor.constraint(equalTo: material.topAnchor),
            body.bottomAnchor.constraint(equalTo: material.bottomAnchor),

            processTable.topAnchor.constraint(equalTo: body.topAnchor),
            processTable.bottomAnchor.constraint(equalTo: body.bottomAnchor),

            modeControl.centerYAnchor.constraint(equalTo: body.centerYAnchor),
            modeControl.widthAnchor.constraint(
                equalToConstant: ProcessPanelMetrics.modeControlDiameter
            ),
            modeControl.heightAnchor.constraint(
                equalToConstant: ProcessPanelMetrics.modeControlDiameter
            )
        ])
        setAttachmentSide(.right, reservedDialogWidth: 0)
        updateAppearanceColors()
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        updateAppearanceColors()
    }

    private func updateAppearanceColors() {
        effectiveAppearance.performAsCurrentDrawingAppearance { [material] in
            material.layer?.borderColor = NSColor.separatorColor
                .withAlphaComponent(0.28)
                .cgColor
        }
    }
}

@MainActor
final class PanelTintView: NSView {
    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        wantsLayer = true
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override var wantsUpdateLayer: Bool {
        true
    }

    override func updateLayer() {
        effectiveAppearance.performAsCurrentDrawingAppearance { [layer] in
            layer?.backgroundColor = NSColor.windowBackgroundColor
                .withAlphaComponent(0.94)
                .cgColor
        }
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }
}

@MainActor
final class HoverTrackingView: NSView {
    var onHoverChange: ((Bool) -> Void)?
    private var hoverTrackingArea: NSTrackingArea?

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let hoverTrackingArea {
            removeTrackingArea(hoverTrackingArea)
        }
        let area = NSTrackingArea(
            rect: .zero,
            options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect],
            owner: self
        )
        addTrackingArea(area)
        hoverTrackingArea = area
    }

    override func mouseEntered(with event: NSEvent) {
        onHoverChange?(true)
    }

    override func mouseExited(with event: NSEvent) {
        onHoverChange?(false)
    }

    override func hitTest(_ point: NSPoint) -> NSView? {
        guard let superview else {
            return nil
        }
        let localPoint = convert(point, from: superview)
        for subview in subviews.reversed() where !subview.isHidden {
            if let hitView = subview.hitTest(localPoint) {
                return hitView
            }
        }
        return nil
    }
}

enum ProcessModeControlDirection: Equatable {
    case left
    case right

    var systemSymbolName: String {
        switch self {
        case .left:
            "arrowtriangle.left.fill"
        case .right:
            "arrowtriangle.right.fill"
        }
    }
}

@MainActor
final class ProcessModeToggleControl: NSButton {
    var onModeRequest: ((ProcessDisplayMode) -> Void)?
    private(set) var direction: ProcessModeControlDirection = .right
    private(set) var symbolImage: NSImage?
    private var displayMode: ProcessDisplayMode = .simple
    private var attachmentSide: SidecarSide = .right
    private var isHovered = false

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        title = ""
        isBordered = false
        focusRingType = .none
        setButtonType(.momentaryPushIn)
        wantsLayer = true
        layer?.cornerRadius = ProcessPanelMetrics.modeControlDiameter / 2
        layer?.cornerCurve = .continuous
        layer?.masksToBounds = true
        layer?.borderWidth = 0
        setAccessibilityIdentifier("who-sudod.process-tree.mode-toggle")
        target = self
        action = #selector(toggleMode)
        updatePresentation()
        updateAppearanceColors()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool {
        true
    }

    override var alignmentRectInsets: NSEdgeInsets {
        NSEdgeInsets(top: 0, left: 0, bottom: 0, right: 0)
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        updatePresentation()
        updateAppearanceColors()
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        effectiveAppearance.performAsCurrentDrawingAppearance { [self] in
            let lineWidth = 1 / (window?.backingScaleFactor ?? 2)
            let radius = min(bounds.width, bounds.height) / 2 - lineWidth / 2
            let stroke = NSBezierPath()
            stroke.lineWidth = lineWidth
            stroke.lineCapStyle = .butt
            stroke.appendArc(
                withCenter: NSPoint(x: bounds.midX, y: bounds.midY),
                radius: radius,
                startAngle: outerStrokeAngles.lowerBound,
                endAngle: outerStrokeAngles.upperBound,
                clockwise: false
            )
            NSColor.separatorColor.withAlphaComponent(0.28).setStroke()
            stroke.stroke()

            symbolImage?.draw(
                in: symbolDrawingRect,
                from: .zero,
                operation: .sourceOver,
                fraction: isEnabled ? 1 : 0.4,
                respectFlipped: true,
                hints: nil
            )
        }
    }

    func setDisplayMode(_ displayMode: ProcessDisplayMode) {
        guard displayMode != self.displayMode else {
            return
        }
        self.displayMode = displayMode
        updatePresentation()
    }

    func setAttachmentSide(_ attachmentSide: SidecarSide) {
        guard attachmentSide != self.attachmentSide else {
            return
        }
        self.attachmentSide = attachmentSide
        updatePresentation()
    }

    func setHovered(_ isHovered: Bool) {
        self.isHovered = isHovered
        updateVisibility()
    }

    @objc
    private func toggleMode() {
        onModeRequest?(requestedMode)
    }

    private var requestedMode: ProcessDisplayMode {
        displayMode == .simple ? .fullTree : .simple
    }

    var outerStrokeAngles: ClosedRange<CGFloat> {
        switch attachmentSide {
        case .left:
            90 ... 270
        case .right:
            -90 ... 90
        }
    }

    var symbolDrawingRect: NSRect {
        guard let symbolImage,
              symbolImage.size.width > 0,
              symbolImage.size.height > 0 else {
            return .zero
        }
        let maximumDimension: CGFloat = 10
        let scale = min(
            maximumDimension / symbolImage.size.width,
            maximumDimension / symbolImage.size.height
        )
        let size = NSSize(
            width: symbolImage.size.width * scale,
            height: symbolImage.size.height * scale
        )
        let horizontalOffset: CGFloat = switch direction {
        case .left:
            -ProcessPanelMetrics.modeControlSymbolOpticalOffset
        case .right:
            ProcessPanelMetrics.modeControlSymbolOpticalOffset
        }
        return NSRect(
            x: bounds.midX - size.width / 2 + horizontalOffset,
            y: bounds.midY - size.height / 2,
            width: size.width,
            height: size.height
        )
    }

    private func updatePresentation() {
        let isExpanding = requestedMode == .fullTree
        let label: String
        let help: String
        if isExpanding {
            label = String(
                localized: "Advanced",
                comment: "Tooltip for the control that expands the process table"
            )
            help = String(
                localized: "Show PID and executable details",
                comment: "Accessibility help for the Advanced process-table control"
            )
        } else {
            label = String(
                localized: "Collapse",
                comment: "Tooltip for the control that collapses the process table"
            )
            help = String(
                localized: "Show the Simple process table",
                comment: "Accessibility help for the collapsed process-table control"
            )
        }

        direction = switch (displayMode, attachmentSide) {
        case (.simple, .right), (.fullTree, .left):
            .right
        case (.simple, .left), (.fullTree, .right):
            .left
        }
        let sizeConfiguration = NSImage.SymbolConfiguration(
            pointSize: 10,
            weight: .semibold
        )
        let colorConfiguration = NSImage.SymbolConfiguration(
            hierarchicalColor: .secondaryLabelColor
        )
        symbolImage = NSImage(
            systemSymbolName: direction.systemSymbolName,
            accessibilityDescription: label
        )?.withSymbolConfiguration(
            sizeConfiguration.applying(colorConfiguration)
        )
        toolTip = label
        setAccessibilityLabel(label)
        setAccessibilityHelp(help)
        updateVisibility()
        needsDisplay = true
    }

    private func updateVisibility() {
        let isVisible = displayMode == .fullTree || isHovered
        isHidden = false
        alphaValue = isVisible ? 1 : 0
        setAccessibilityHidden(!isVisible)
    }

    private func updateAppearanceColors() {
        effectiveAppearance.performAsCurrentDrawingAppearance { [layer] in
            layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        }
        needsDisplay = true
    }
}

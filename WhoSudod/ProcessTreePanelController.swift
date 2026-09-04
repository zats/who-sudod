import AppKit
import os
import QuartzCore

enum ProcessTableAnimationPolicy {
    static func animatesContentChange(
        panelIsPresented: Bool,
        currentPromptSequence: Int,
        nextPromptSequence: Int
    ) -> Bool {
        panelIsPresented && currentPromptSequence == nextPromptSequence
    }
}

/// Identifies a password conversation that the installed Who Sudo'd PAM module
/// verified as live. Heuristic sudo detection must never create this value.
struct VerifiedPAMPasswordRequest: Equatable, Sendable {
    let id: UUID

    init(id: UUID) {
        self.id = id
    }
}

private struct AuthenticationPanelPlacement {
    let frame: CGRect
    let visibleFrame: CGRect

    func geometry(displayMode: ProcessDisplayMode) -> SidecarGeometry {
        WindowGeometry.sidecarFrame(
            authenticationFrame: frame,
            visibleFrame: visibleFrame,
            displayMode: displayMode
        )
    }

    func transition(
        from source: SidecarGeometry,
        to destination: SidecarGeometry
    ) -> SidecarTransitionGeometry {
        WindowGeometry.transition(
            from: source,
            to: destination,
            authenticationFrame: frame
        )
    }
}

@MainActor
final class ProcessTreePanelController: NSWindowController {
    private let content: CompanionContentView
    private let notch: ProcessNotchController
    private var displayMode: ProcessDisplayMode
    private var currentSnapshot: AuthenticationProcessSnapshot?
    private var currentSurfaceKind: AuthenticationSurfaceKind?
    private var currentPlacement: AuthenticationPanelPlacement?
    private var currentSidecar: SidecarGeometry?
    private var currentAttachmentSide: SidecarSide?
    private var geometryTransitionGeneration = 0
    private var activeGeometryTransitionGeneration: Int?
    private var activeGeometryTransitionTarget: SidecarGeometry?
    private var currentPromptSequence = 0
    private var activePAMPasswordRequestID: UUID?
    private var passwordSubmissionHandler: (@MainActor (UUID, String) -> Void)?
    private let pamSetupActionProvider: @MainActor () -> PAMNotchAction?
    private var sidecarIsPresented = false
    var onNotchDismissRequest: (() -> Void)? {
        didSet { notch.onDismissRequest = onNotchDismissRequest }
    }
    var isPresented: Bool { sidecarIsPresented || notch.isPresented }
    var isNotchPresented: Bool { notch.isPresented }
    var notchWindow: NSWindow? { notch.window }
#if DEBUG
    private let logger = Logger(subsystem: "com.zats.WhoSudo", category: "LiveTreeDiagnostics")
    private var liveTreeDiagnostics = LiveTreeDiagnostics()
#endif

    init(
        displayMode: ProcessDisplayMode = .simple,
        displayModeRequestHandler: @escaping (ProcessDisplayMode) -> Void = { _ in },
        pamSetupActionProvider: @escaping @MainActor () -> PAMNotchAction? = { nil },
        pamSetupActionHandler: @escaping @MainActor (PAMSettingsAction) -> Void = { _ in }
    ) {
        self.displayMode = displayMode
        self.pamSetupActionProvider = pamSetupActionProvider
        content = CompanionContentView(
            displayMode: displayMode,
            displayModeRequestHandler: displayModeRequestHandler
        )
        notch = ProcessNotchController(
            displayMode: displayMode,
            displayModeRequestHandler: displayModeRequestHandler,
            pamActionRequestHandler: pamSetupActionHandler
        )
        let panel = PassivePanel(
            contentRect: NSRect(x: 0, y: 0, width: 520, height: 320),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        super.init(window: panel)
        notch.onPasswordSubmit = { [weak self] password in
            self?.submitPassword(password)
        }
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
        show(
            snapshot: snapshot,
            promptSequence: promptSequence,
            surfaceKind: surfaceKind,
            placement: AuthenticationPanelPlacement(
                frame: authenticationFrame,
                visibleFrame: visibleFrame
            )
        )
    }

    func showNotch(
        snapshot: AuthenticationProcessSnapshot,
        promptSequence: Int,
        anchorFrame: CGRect,
        visibleFrame: CGRect,
        allowsPAMSetupAction: Bool = true
    ) {
        guard let screen = NSScreen.screens.first(where: { $0.visibleFrame == visibleFrame })
            ?? NSScreen.screens.max(by: {
                $0.frame.intersection(anchorFrame).width * $0.frame.intersection(anchorFrame).height
                    < $1.frame.intersection(anchorFrame).width * $1.frame.intersection(anchorFrame).height
            }) else { return }
        let animated = ProcessTableAnimationPolicy.animatesContentChange(
            panelIsPresented: notch.isPresented,
            currentPromptSequence: currentPromptSequence,
            nextPromptSequence: promptSequence
        )
        cancelGeometryTransition()
        content.setHovered(false)
        window?.orderOut(nil)
        sidecarIsPresented = false
        currentPlacement = nil
        currentSnapshot = snapshot
        currentPromptSequence = promptSequence
        currentSurfaceKind = .terminalPassword
        notch.show(
            snapshot: snapshot,
            screen: screen,
            animated: animated,
            pamAction: allowsPAMSetupAction && activePAMPasswordRequestID == nil
                ? pamSetupActionProvider()
                : nil
        )
#if DEBUG
        recordVisibleLiveTree()
#endif
    }

    /// Enables password input only for a request authenticated by the PAM IPC
    /// layer. This does not take keyboard focus from the calling terminal.
    func presentVerifiedPAMPasswordRequest(
        _ request: VerifiedPAMPasswordRequest,
        onPassword: @escaping @MainActor (UUID, String) -> Void
    ) {
        let replacesRequest = activePAMPasswordRequestID != request.id
        activePAMPasswordRequestID = request.id
        passwordSubmissionHandler = onPassword

        notch.presentPasswordEntry(clearExistingInput: replacesRequest)
    }

    func dismissVerifiedPAMPasswordRequest(_ requestID: UUID) {
        guard activePAMPasswordRequestID == requestID else {
            return
        }
        endPAMPasswordPresentation()
    }

    var isPresentingVerifiedPAMPasswordRequest: Bool {
        activePAMPasswordRequestID != nil
    }

    var isPAMPasswordEntryFocused: Bool {
        activePAMPasswordRequestID != nil && notch.isPasswordEntryFocused
    }

    private func show(
        snapshot: AuthenticationProcessSnapshot,
        promptSequence: Int,
        surfaceKind: AuthenticationSurfaceKind,
        placement: AuthenticationPanelPlacement
    ) {
        guard let window else {
            return
        }

        endPAMPasswordPresentation()
        notch.hide()
        let animatesTableChange = ProcessTableAnimationPolicy.animatesContentChange(
            panelIsPresented: sidecarIsPresented,
            currentPromptSequence: currentPromptSequence,
            nextPromptSequence: promptSequence
        )
        if snapshot != currentSnapshot || !sidecarIsPresented {
            currentSnapshot = snapshot
            content.update(snapshot: snapshot, animated: animatesTableChange)
        }
        currentPromptSequence = promptSequence
        currentSurfaceKind = surfaceKind
        currentPlacement = placement

        let target = placement.geometry(displayMode: displayMode)
        if let activeGeometryTransitionTarget {
            if !approximatelyEqual(target, activeGeometryTransitionTarget) {
                cancelGeometryTransition()
                applyPanelGeometry(target)
            }
        } else {
            applyPanelGeometry(target)
        }
        if !sidecarIsPresented {
            window.orderFrontRegardless()
            sidecarIsPresented = true
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
        content.setHovered(false)
        endPAMPasswordPresentation()
        notch.hide()
        if sidecarIsPresented {
            window?.orderOut(nil)
            sidecarIsPresented = false
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
        notch.setDisplayMode(mode)
        guard sidecarIsPresented,
              let window,
              let currentPlacement else {
            return
        }

        let destination = currentPlacement.geometry(displayMode: mode)
        let source = SidecarGeometry(
            frame: window.frame,
            side: currentAttachmentSide ?? currentSidecar?.side ?? destination.side,
            reservedDialogWidth: destination.reservedDialogWidth
        )
        let transition = currentPlacement.transition(
            from: source,
            to: destination
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
        panel.becomesKeyOnlyIfNeeded = true
        panel.setAccessibilityIdentifier("who-sudod.process-tree.panel")
    }

    private func submitPassword(_ password: String) {
        guard let requestID = activePAMPasswordRequestID,
              let handler = passwordSubmissionHandler,
              !password.isEmpty,
              !password.contains("\0"),
              password.lengthOfBytes(using: .utf8)
                  <= PAMConversationWire.maximumPasswordLength else {
            NSSound.beep()
            return
        }
        endPAMPasswordPresentation()
        handler(requestID, password)
    }

    private func endPAMPasswordPresentation() {
        guard activePAMPasswordRequestID != nil else {
            return
        }
        notch.dismissPasswordEntry()
        activePAMPasswordRequestID = nil
        passwordSubmissionHandler = nil
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
                presentation: notch.isPresented ? "notch" : "dialog",
                passwordInputVisible: notch.isPresented && notch.passwordInputVisible,
                snapshot: snapshot,
                renderedTable: notch.isPresented ? notch.renderedTable : content.renderedTable
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
    private let modeControl: ProcessDisplayModeButton
    private var tableSideConstraints: [NSLayoutConstraint] = []
    private var modeControlSideConstraints: [NSLayoutConstraint] = []
    private var hoverTrackingArea: NSTrackingArea?
    private var attachmentSide: SidecarSide?
    private var reservedDialogWidth: CGFloat = 0

    init(
        frame frameRect: NSRect = .zero,
        displayMode: ProcessDisplayMode,
        displayModeRequestHandler: @escaping (ProcessDisplayMode) -> Void = { _ in }
    ) {
        processTable = ProcessTableView(frame: .zero, displayMode: displayMode)
        modeControl = ProcessDisplayModeButton(
            displayMode: displayMode,
            presentation: .panelCorner
        )
        super.init(frame: frameRect)
        modeControl.onModeRequest = { mode in
            displayModeRequestHandler(mode)
        }
        modeControl.setAccessibilityIdentifier("who-sudod.process-tree.mode-toggle")
        configure()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(
        snapshot: AuthenticationProcessSnapshot,
        animated: Bool
    ) {
        processTable.update(snapshot: snapshot, animated: animated)
    }

    func setDisplayMode(_ mode: ProcessDisplayMode) {
        processTable.setDisplayMode(mode)
        modeControl.setDisplayMode(mode)
    }

    func setHovered(_ isHovered: Bool) {
        modeControl.setHovered(isHovered)
    }

    var renderedTable: RenderedProcessTable {
        processTable.renderedTable()
    }

    func setAttachmentSide(_ side: SidecarSide, reservedDialogWidth: CGFloat) {
        guard side != attachmentSide || reservedDialogWidth != self.reservedDialogWidth else {
            return
        }
        NSLayoutConstraint.deactivate(tableSideConstraints)
        NSLayoutConstraint.deactivate(modeControlSideConstraints)
        if side == .right {
            tableSideConstraints = [
                processTable.leadingAnchor.constraint(
                    equalTo: material.leadingAnchor,
                    constant: reservedDialogWidth + ProcessPanelMetrics.tableHorizontalInset
                ),
                processTable.trailingAnchor.constraint(
                    equalTo: material.trailingAnchor,
                    constant: -ProcessPanelMetrics.tableHorizontalInset
                )
            ]
            modeControlSideConstraints = [
                modeControl.trailingAnchor.constraint(
                    equalTo: material.trailingAnchor,
                    constant: -ProcessPanelMetrics.dialogModeButtonInset
                )
            ]
        } else {
            tableSideConstraints = [
                processTable.leadingAnchor.constraint(
                    equalTo: material.leadingAnchor,
                    constant: ProcessPanelMetrics.tableHorizontalInset
                ),
                processTable.trailingAnchor.constraint(
                    equalTo: material.trailingAnchor,
                    constant: -reservedDialogWidth - ProcessPanelMetrics.tableHorizontalInset
                )
            ]
            modeControlSideConstraints = [
                modeControl.leadingAnchor.constraint(
                    equalTo: material.leadingAnchor,
                    constant: ProcessPanelMetrics.dialogModeButtonInset
                )
            ]
        }
        NSLayoutConstraint.activate(tableSideConstraints)
        NSLayoutConstraint.activate(modeControlSideConstraints)
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

        modeControl.translatesAutoresizingMaskIntoConstraints = false
        material.addSubview(modeControl)
        NSLayoutConstraint.activate([
            material.topAnchor.constraint(equalTo: topAnchor),
            material.leadingAnchor.constraint(equalTo: leadingAnchor),
            material.trailingAnchor.constraint(equalTo: trailingAnchor),
            material.bottomAnchor.constraint(equalTo: bottomAnchor),

            tint.topAnchor.constraint(equalTo: material.topAnchor),
            tint.leadingAnchor.constraint(equalTo: material.leadingAnchor),
            tint.trailingAnchor.constraint(equalTo: material.trailingAnchor),
            tint.bottomAnchor.constraint(equalTo: material.bottomAnchor),

            processTable.topAnchor.constraint(equalTo: material.topAnchor),
            processTable.bottomAnchor.constraint(equalTo: material.bottomAnchor),

            modeControl.topAnchor.constraint(
                equalTo: processTable.topAnchor,
                constant: ProcessPanelMetrics.dialogModeButtonInset
            )
        ])
        setAttachmentSide(.right, reservedDialogWidth: 0)
        updateAppearanceColors()
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let hoverTrackingArea {
            removeTrackingArea(hoverTrackingArea)
        }
        let trackingArea = NSTrackingArea(
            rect: .zero,
            options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect],
            owner: self,
            userInfo: nil
        )
        addTrackingArea(trackingArea)
        hoverTrackingArea = trackingArea
    }

    override func mouseEntered(with event: NSEvent) {
        super.mouseEntered(with: event)
        setHovered(true)
    }

    override func mouseExited(with event: NSEvent) {
        super.mouseExited(with: event)
        setHovered(false)
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
final class ProcessDisplayModeButton: NSButton {
    enum Presentation: Equatable {
        case plain
        case panelCorner
    }

    var onModeRequest: ((ProcessDisplayMode) -> Void)?
    private(set) var systemSymbolName = ""
    private var displayMode: ProcessDisplayMode
    private let presentation: Presentation
    private var pointerIsInside = false

    init(
        displayMode: ProcessDisplayMode,
        presentation: Presentation = .plain
    ) {
        self.displayMode = displayMode
        self.presentation = presentation
        super.init(frame: .zero)
        title = ""
        bezelStyle = .inline
        if presentation == .panelCorner {
            isBordered = false
            borderShape = .circle
            wantsLayer = true
            layer?.cornerRadius = ProcessPanelMetrics.dialogModeButtonDiameter / 2
            layer?.cornerCurve = .continuous
            layer?.masksToBounds = true
            layer?.borderWidth = 0
        }
        controlSize = .small
        imagePosition = .imageOnly
        focusRingType = .none
        target = self
        action = #selector(toggleMode)
        updatePresentation()
        updateVisibility()
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
        presentation == .panelCorner
            ? NSEdgeInsets(top: 0, left: 0, bottom: 0, right: 0)
            : super.alignmentRectInsets
    }

    override var intrinsicContentSize: NSSize {
        let size = presentation == .panelCorner
            ? ProcessPanelMetrics.dialogModeButtonDiameter
            : ProcessPanelMetrics.modeButtonHitSize
        return NSSize(
            width: size,
            height: size
        )
    }

    func setHovered(_ isHovered: Bool) {
        guard presentation == .panelCorner,
              pointerIsInside != isHovered else {
            return
        }
        pointerIsInside = isHovered
        updateVisibility()
    }

    func setDisplayMode(_ displayMode: ProcessDisplayMode) {
        guard displayMode != self.displayMode else {
            return
        }
        self.displayMode = displayMode
        updatePresentation()
        updateVisibility()
    }

    @objc
    private func toggleMode() {
        onModeRequest?(requestedMode)
    }

    private var requestedMode: ProcessDisplayMode {
        displayMode == .simple ? .fullTree : .simple
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
                localized: "Compact",
                comment: "Tooltip for the control that collapses the process table"
            )
            help = String(
                localized: "Show the Simple process table",
                comment: "Accessibility help for the collapsed process-table control"
            )
        }

        systemSymbolName = isExpanding
            ? "arrow.up.left.and.arrow.down.right"
            : "arrow.down.right.and.arrow.up.left"
        image = NSImage(
            systemSymbolName: systemSymbolName,
            accessibilityDescription: label
        )
        toolTip = label
        setAccessibilityLabel(label)
        setAccessibilityHelp(help)
    }

    private func updateVisibility() {
        alphaValue = presentation == .panelCorner
            && displayMode == .simple
            && !pointerIsInside
            ? 0
            : 1
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        updateAppearanceColors()
    }

    private func updateAppearanceColors() {
        guard presentation == .panelCorner else { return }
        effectiveAppearance.performAsCurrentDrawingAppearance { [layer] in
            layer?.backgroundColor = NSColor.windowBackgroundColor.cgColor
        }
    }
}

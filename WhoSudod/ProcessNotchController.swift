import AppKit
import DynamicNotchKit
import QuartzCore
import SwiftUI

/// Layout for the notch surface. Authentication and password eligibility
/// stay in the monitor; this type only sizes the already-approved content.
struct ProcessNotchLayout: Equatable {
    static let bottomInset: CGFloat = 8

    let size: CGSize
    let topInset: CGFloat
    let hasNotch: Bool
    let notchSize: CGSize?

    init(
        screenSize: CGSize,
        notchSize: CGSize?,
        displayMode: ProcessDisplayMode,
        rowCount: Int,
        passwordInputVisible: Bool,
        pamActionVisible: Bool = false
    ) {
        self.notchSize = notchSize
        hasNotch = notchSize != nil
        topInset = (notchSize?.height ?? 32) + 12
        let desiredWidth: CGFloat = displayMode == .fullTree ? 680 : 360
        let width = max(desiredWidth, passwordInputVisible ? 360 : 0)
        // The header and scroll-view chrome need six backing points beyond
        // the 28-point header so the final row is fully visible.
        let tableHeight = 34 + CGFloat(max(1, rowCount)) * 31
        let accessoryHeight: CGFloat = passwordInputVisible ? 50 : (pamActionVisible ? 44 : 0)
        size = CGSize(
            width: min(width, max(1, screenSize.width - 32)),
            height: min(
                topInset + tableHeight + accessoryHeight + Self.bottomInset,
                max(1, screenSize.height - 80)
            )
        )
    }
}

/// The content can scroll as one unit when a short display cannot fit both
/// the minimum table viewport and the optional password controls.
struct ProcessNotchBodyLayout: Equatable {
    let viewport: CGRect
    let documentSize: CGSize
    let table: CGRect
    let accessory: CGRect

    init(
        size: CGSize,
        topInset: CGFloat,
        passwordInputVisible: Bool,
        pamActionVisible: Bool = false
    ) {
        let width = max(1, size.width - 40)
        let viewportHeight = max(
            1,
            size.height - topInset - ProcessNotchLayout.bottomInset
        )
        let accessoryHeight: CGFloat = passwordInputVisible ? 50 : (pamActionVisible ? 44 : 0)
        let tableHeight = max(59, viewportHeight - accessoryHeight)
        viewport = CGRect(x: 20, y: topInset, width: width, height: viewportHeight)
        table = CGRect(x: 0, y: 0, width: width, height: tableHeight)
        accessory = CGRect(
            x: 0, y: tableHeight + 6, width: width,
            height: max(0, accessoryHeight - 6)
        )
        documentSize = CGSize(width: width, height: tableHeight + accessoryHeight)
    }
}

@MainActor
final class ProcessNotchController: NSWindowController {
    private let content: ProcessNotchContentView
    private var screen: NSScreen?
    private var snapshot = AuthenticationProcessSnapshot.pending
    private var displayMode: ProcessDisplayMode
    private var geometryTransitionID: UUID?
    private var geometryTransitionTarget: CGRect?
    private var localEscapeMonitor: Any?
    private var globalEscapeMonitor: Any?
    private(set) var isPresented = false

    init(
        displayMode: ProcessDisplayMode,
        displayModeRequestHandler: @escaping (ProcessDisplayMode) -> Void,
        pamActionRequestHandler: @escaping (PAMSettingsAction) -> Void = { _ in }
    ) {
        self.displayMode = displayMode
        let content = ProcessNotchContentView(
            displayMode: displayMode,
            displayModeRequestHandler: displayModeRequestHandler,
            pamActionRequestHandler: pamActionRequestHandler
        )
        self.content = content
        let panel = DynamicNotchPanel(
            contentRect: .zero,
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.acceptsKeyInput = false
        panel.isReleasedWhenClosed = false
        panel.isFloatingPanel = true
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hidesOnDeactivate = false
        panel.isMovable = false
        panel.hasShadow = false
        panel.animationBehavior = .none
        panel.level = NSWindow.Level.mainMenu + 3
        panel.collectionBehavior = [
            .canJoinAllSpaces,
            .stationary,
            .ignoresCycle,
            .fullScreenAuxiliary
        ]
        panel.acceptsMouseMovedEvents = true
        panel.becomesKeyOnlyIfNeeded = true
        super.init(window: panel)
        panel.contentView = content
        panel.appearance = NSAppearance(named: .darkAqua)
        panel.setAccessibilityIdentifier("who-sudod.process-tree.notch")
        panel.setAccessibilityLabel("Sudo process tree")
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    var onPasswordSubmit: ((String) -> Void)? {
        get { content.onPasswordSubmit }
        set { content.onPasswordSubmit = newValue }
    }

    var onDismissRequest: (() -> Void)? {
        get { content.onDismissRequest }
        set { content.onDismissRequest = newValue }
    }

    var passwordInputVisible: Bool { content.passwordInputVisible }
    var pamActionVisible: Bool { content.pamActionVisible }
    var isPasswordEntryFocused: Bool {
        passwordInputVisible && window?.isKeyWindow == true
    }
    var renderedTable: RenderedProcessTable { content.renderedTable }

    func show(
        snapshot: AuthenticationProcessSnapshot,
        screen: NSScreen,
        animated: Bool,
        pamAction: PAMNotchAction? = nil
    ) {
        let sameScreen = self.screen == screen
        if isPresented && (!animated || !sameScreen) {
            cancelGeometryTransition()
        }
        self.screen = screen
        content.setPAMAction(pamAction)
        if self.snapshot != snapshot {
            self.snapshot = snapshot
            content.update(snapshot: snapshot, animated: animated && sameScreen)
        }
        updateGeometry(animated: animated && sameScreen)
        if !isPresented {
            window?.orderFrontRegardless()
            isPresented = true
            content.animateArrival(notchSize: screen.dynamicNotchSize)
        }
        startEscapeMonitoring()
        window?.displayIfNeeded()
    }

    func setDisplayMode(_ mode: ProcessDisplayMode) {
        guard displayMode != mode else { return }
        displayMode = mode
        content.setDisplayMode(mode)
        updateGeometry(animated: isPresented)
    }

    func presentPasswordEntry(clearExistingInput: Bool) {
        content.presentPasswordEntry(clearExistingInput: clearExistingInput)
        (window as? DynamicNotchPanel)?.acceptsKeyInput = true
        updateGeometry(animated: isPresented)
    }

    func dismissPasswordEntry() {
        guard passwordInputVisible else { return }
        content.dismissPasswordEntry()
        (window as? DynamicNotchPanel)?.acceptsKeyInput = false
        updateGeometry(animated: isPresented)
    }

    func hide() {
        guard isPresented || passwordInputVisible else { return }
        isPresented = false
        stopEscapeMonitoring()
        dismissPasswordEntry()
        cancelGeometryTransition()
        window?.orderOut(nil)
    }

    @discardableResult
    func handleEscapeKeyDown(_ event: NSEvent) -> Bool {
        guard isPresented,
              event.type == .keyDown,
              event.keyCode == 53 else {
            return false
        }
        content.requestDismissal()
        return true
    }

    private func startEscapeMonitoring() {
        if localEscapeMonitor == nil {
            localEscapeMonitor = NSEvent.addLocalMonitorForEvents(
                matching: .keyDown
            ) { [weak self] event in
                guard let self else { return event }
                return self.handleEscapeKeyDown(event) ? nil : event
            }
        }
        if globalEscapeMonitor == nil {
            globalEscapeMonitor = NSEvent.addGlobalMonitorForEvents(
                matching: .keyDown
            ) { [weak self] event in
                Task { @MainActor in
                    _ = self?.handleEscapeKeyDown(event)
                }
            }
        }
    }

    private func stopEscapeMonitoring() {
        if let localEscapeMonitor {
            NSEvent.removeMonitor(localEscapeMonitor)
            self.localEscapeMonitor = nil
        }
        if let globalEscapeMonitor {
            NSEvent.removeMonitor(globalEscapeMonitor)
            self.globalEscapeMonitor = nil
        }
    }

    private func updateGeometry(animated: Bool) {
        guard let window, let screen else { return }
        let layout = ProcessNotchLayout(
            screenSize: screen.frame.size,
            notchSize: screen.dynamicNotchSize,
            displayMode: displayMode,
            rowCount: content.rowCount,
            passwordInputVisible: passwordInputVisible,
            pamActionVisible: pamActionVisible
        )
        let frame = DynamicNotchWindowLayout.topAnchoredFrame(
            on: screen,
            size: layout.size,
            yOffset: layout.hasNotch ? 1 : -3
        )
        if layout == content.notchLayout,
           frame == (geometryTransitionTarget ?? window.frame) {
            return
        }
        cancelGeometryTransition()
        content.notchLayout = layout
        guard animated, isPresented,
              !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion else {
            applyFrame(frame)
            return
        }

        // Animate the actual window so a collapse is not clipped by the final
        // smaller frame. The hit target stays bounded by the content frames.
        let transitionID = UUID()
        geometryTransitionID = transitionID
        geometryTransitionTarget = frame
        NSAnimationContext.runAnimationGroup { context in
            context.duration = 0.28
            context.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
            window.animator().setFrame(frame, display: true)
        } completionHandler: { [weak self] in
            Task { @MainActor in
                guard let self, self.geometryTransitionID == transitionID else { return }
                self.geometryTransitionID = nil
                self.geometryTransitionTarget = nil
                self.applyFrame(frame)
            }
        }
    }

    private func applyFrame(_ frame: CGRect) {
        window?.setFrame(frame, display: isPresented)
        content.frame = CGRect(origin: .zero, size: frame.size)
        content.layoutSubtreeIfNeeded()
    }

    private func cancelGeometryTransition() {
        geometryTransitionID = nil
        geometryTransitionTarget = nil
        content.cancelAnimations()
        guard let window else { return }
        NSAnimationContext.runAnimationGroup { context in
            context.duration = 0
            window.animator().setFrame(window.frame, display: isPresented)
        }
    }
}

@MainActor
private final class ProcessNotchContentView: NSView {
    var onPasswordSubmit: ((String) -> Void)?
    var onDismissRequest: (() -> Void)?
    var notchLayout: ProcessNotchLayout? {
        didSet { needsLayout = true }
    }
    private let processTable: ProcessTableView
    private let passwordEntry = PAMPasswordEntryView()
    private let pamActionButton = NSButton()
    private let bodyScrollView = NSScrollView()
    private let bodyView = ProcessNotchBodyView()
    private let modeButton: ProcessDisplayModeButton
    private let dismissButton = NotchDismissButton()
    private let surface = CAShapeLayer()
    private let surfaceMask = CAShapeLayer()
    private let displayModeRequestHandler: (ProcessDisplayMode) -> Void
    private let pamActionRequestHandler: (PAMSettingsAction) -> Void
    private var displayMode: ProcessDisplayMode
    private var pamAction: PAMNotchAction?

    init(
        displayMode: ProcessDisplayMode,
        displayModeRequestHandler: @escaping (ProcessDisplayMode) -> Void,
        pamActionRequestHandler: @escaping (PAMSettingsAction) -> Void
    ) {
        self.displayMode = displayMode
        self.displayModeRequestHandler = displayModeRequestHandler
        self.pamActionRequestHandler = pamActionRequestHandler
        modeButton = ProcessDisplayModeButton(displayMode: displayMode)
        processTable = ProcessTableView(frame: .zero, displayMode: displayMode)
        super.init(frame: .zero)
        autoresizingMask = [.width, .height]
        wantsLayer = true
        surface.fillColor = NSColor.black.cgColor
        layer?.addSublayer(surface)
        layer?.mask = surfaceMask
        bodyScrollView.drawsBackground = false
        bodyScrollView.hasVerticalScroller = true
        bodyScrollView.autohidesScrollers = true
        bodyScrollView.documentView = bodyView
        addSubview(bodyScrollView)
        processTable.translatesAutoresizingMaskIntoConstraints = true
        bodyView.addSubview(processTable)
        passwordEntry.translatesAutoresizingMaskIntoConstraints = true
        passwordEntry.isHidden = true
        passwordEntry.onSubmit = { [weak self] in self?.onPasswordSubmit?($0) }
        bodyView.addSubview(passwordEntry)
        pamActionButton.translatesAutoresizingMaskIntoConstraints = true
        pamActionButton.bezelStyle = .rounded
        pamActionButton.target = self
        pamActionButton.action = #selector(requestPAMAction)
        pamActionButton.setAccessibilityIdentifier("who-sudod.notch.pam-action")
        pamActionButton.isHidden = true
        bodyView.addSubview(pamActionButton)
        modeButton.onModeRequest = displayModeRequestHandler
        modeButton.setAccessibilityIdentifier("who-sudod.notch.display-mode")
        addSubview(modeButton)
        dismissButton.target = self
        dismissButton.action = #selector(requestDismissalFromButton)
        dismissButton.setAccessibilityIdentifier("who-sudod.notch.dismiss")
        addSubview(dismissButton)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override var isFlipped: Bool { true }
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
    override func cancelOperation(_ sender: Any?) { requestDismissal() }
    var passwordInputVisible: Bool { !passwordEntry.isHidden }
    var pamActionVisible: Bool { !pamActionButton.isHidden }
    var rowCount: Int { processTable.presentationRows.count }
    var renderedTable: RenderedProcessTable { processTable.renderedTable() }

    func requestDismissal() {
        onDismissRequest?()
    }

    func update(snapshot: AuthenticationProcessSnapshot, animated: Bool) {
        processTable.update(snapshot: snapshot, animated: animated)
    }

    func setDisplayMode(_ mode: ProcessDisplayMode) {
        displayMode = mode
        processTable.setDisplayMode(mode)
        modeButton.setDisplayMode(mode)
        needsLayout = true
    }

    func presentPasswordEntry(clearExistingInput: Bool) {
        if clearExistingInput { passwordEntry.clearPassword() }
        pamActionButton.isHidden = true
        passwordEntry.isHidden = false
        needsLayout = true
    }

    func dismissPasswordEntry() {
        passwordEntry.clearPassword()
        passwordEntry.isHidden = true
        // A completed verified conversation must not turn into a setup prompt.
        // A later generic sudo update supplies a fresh action if it is valid.
        pamAction = nil
        pamActionButton.title = ""
        pamActionButton.isHidden = true
        needsLayout = true
    }

    func setPAMAction(_ action: PAMNotchAction?) {
        guard pamAction != action else { return }
        pamAction = action
        pamActionButton.title = action?.title ?? ""
        pamActionButton.isHidden = action == nil || passwordInputVisible
        needsLayout = true
    }

    override func layout() {
        super.layout()
        guard let notchLayout else { return }
        let inset: CGFloat = 20
        let bodyLayout = ProcessNotchBodyLayout(
            size: bounds.size,
            topInset: notchLayout.topInset,
            passwordInputVisible: passwordInputVisible,
            pamActionVisible: pamActionVisible
        )
        bodyScrollView.frame = bodyLayout.viewport
        bodyView.frame = CGRect(origin: .zero, size: bodyLayout.documentSize)
        processTable.frame = bodyLayout.table
        passwordEntry.frame = bodyLayout.accessory
        pamActionButton.frame = bodyLayout.accessory
        modeButton.setFrameSize(CGSize(
            width: ProcessPanelMetrics.modeButtonHitSize,
            height: ProcessPanelMetrics.modeButtonHitSize
        ))
        modeButton.setFrameOrigin(CGPoint(
            x: bounds.maxX - inset - modeButton.frame.width,
            y: max(4, ((notchLayout.notchSize?.height ?? 32) - modeButton.frame.height) / 2)
        ))
        dismissButton.frame = CGRect(
            x: inset,
            y: modeButton.frame.minY,
            width: ProcessPanelMetrics.modeButtonHitSize,
            height: ProcessPanelMetrics.modeButtonHitSize
        )
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        surface.frame = bounds
        surface.path = surfacePath(in: bounds)
        surfaceMask.frame = bounds
        surfaceMask.path = surface.path
        CATransaction.commit()
    }

    func animateArrival(notchSize: CGSize?) {
        animateResize(from: notchSize ?? CGSize(width: 160, height: 32))
    }

    func animateResize(from size: CGSize) {
        guard !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion,
              size.width > 0, size.height > 0 else { return }
        let oldRect = CGRect(
            x: (bounds.width - size.width) / 2,
            y: 0, width: size.width, height: size.height
        )
        let resize = CABasicAnimation(keyPath: "path")
        resize.duration = 0.28
        resize.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        resize.fromValue = surfacePath(in: oldRect)
        resize.toValue = surfacePath(in: bounds)
        surface.add(resize, forKey: "notch-size")
        surfaceMask.add(resize, forKey: "notch-size")
    }

    func cancelAnimations() {
        surface.removeAllAnimations()
        surfaceMask.removeAllAnimations()
    }

    private func surfacePath(in rect: CGRect) -> CGPath {
        if notchLayout?.hasNotch == true {
            return NotchShape(
                topCornerRadius: 8,
                bottomCornerRadius: min(24, rect.height / 2)
            ).path(in: rect).cgPath
        }
        return RoundedRectangle(
            cornerRadius: min(24, rect.height / 2),
            style: .continuous
        ).path(in: rect).cgPath
    }

    @objc private func requestPAMAction() {
        guard let pamAction else { return }
        pamActionRequestHandler(pamAction.action)
    }

    @objc private func requestDismissalFromButton() {
        requestDismissal()
    }
}

@MainActor
private final class NotchDismissButton: NSButton {
    init() {
        super.init(frame: .zero)
        let label = String(
            localized: "Close",
            comment: "Tooltip for the control that dismisses the notch process view"
        )
        title = ""
        bezelStyle = .inline
        controlSize = .small
        imagePosition = .imageOnly
        focusRingType = .none
        image = NSImage(
            systemSymbolName: "xmark",
            accessibilityDescription: label
        )
        toolTip = label
        setAccessibilityLabel(label)
        setAccessibilityHelp(String(
            localized: "Dismiss the sudo process view",
            comment: "Accessibility help for the notch close control"
        ))
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool {
        true
    }
}

@MainActor
private final class ProcessNotchBodyView: NSView {
    override var isFlipped: Bool { true }
}

#if DEBUG
@MainActor
private enum ProcessNotchPreviewAccessory {
    case none
    case password
    case install
    case repair
}

@MainActor
private enum ProcessNotchPreviewFactory {
    static let standardScreenSize = CGSize(width: 1512, height: 982)
    static let constrainedScreenSize = CGSize(width: 700, height: 360)
    static let notchSize = CGSize(width: 180, height: 32)

    static func make(
        displayMode: ProcessDisplayMode,
        snapshot: AuthenticationProcessSnapshot = processSnapshot,
        accessory: ProcessNotchPreviewAccessory = .none,
        screenSize: CGSize = standardScreenSize,
        notchSize: CGSize? = notchSize
    ) -> NSView {
        let view = ProcessNotchContentView(
            displayMode: displayMode,
            displayModeRequestHandler: { _ in },
            pamActionRequestHandler: { _ in }
        )
        view.appearance = NSAppearance(named: .darkAqua)
        view.update(snapshot: snapshot, animated: false)

        switch accessory {
        case .none:
            break
        case .password:
            view.presentPasswordEntry(clearExistingInput: true)
        case .install:
            view.setPAMAction(PAMNotchAction(action: .install, title: "Install…"))
        case .repair:
            view.setPAMAction(PAMNotchAction(action: .repair, title: "Repair…"))
        }

        let layout = ProcessNotchLayout(
            screenSize: screenSize,
            notchSize: notchSize,
            displayMode: displayMode,
            rowCount: view.rowCount,
            passwordInputVisible: view.passwordInputVisible,
            pamActionVisible: view.pamActionVisible
        )
        view.notchLayout = layout
        view.frame = CGRect(origin: .zero, size: layout.size)
        view.layoutSubtreeIfNeeded()
        return view
    }

    private static let processSnapshot: AuthenticationProcessSnapshot = {
        let records = [
            record(
                pid: 1,
                parentPID: 0,
                name: "launchd",
                executablePath: "/sbin/launchd",
                startedAt: 100
            ),
            record(
                pid: 410,
                parentPID: 1,
                name: "Terminal",
                executablePath:
                    "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                startedAt: 200
            ),
            record(
                pid: 641,
                parentPID: 410,
                name: "login",
                executablePath: "/usr/bin/login",
                startedAt: 300
            ),
            record(
                pid: 642,
                parentPID: 641,
                name: "zsh",
                executablePath: "/bin/zsh",
                startedAt: 400
            ),
            record(
                pid: 718,
                parentPID: 642,
                name: "sudo",
                executablePath: "/usr/bin/sudo",
                startedAt: 500,
                processArguments: [
                    "/usr/bin/sudo", "--", "/bin/ls", "-la", "/var/root"
                ]
            )
        ]
        return ProcessTreeBuilder.build(
            records: records,
            requesterIdentities: [records[4].identity],
            requestKind: .sudo,
            attribution: .pamConversation
        )
    }()

    private static func record(
        pid: pid_t,
        parentPID: pid_t,
        name: String,
        executablePath: String,
        startedAt: UInt64,
        processArguments: [String]? = nil
    ) -> ProcessRecord {
        ProcessRecord(
            pid: pid,
            parentPID: parentPID,
            realUserID: getuid(),
            name: name,
            executablePath: executablePath,
            startTime: ProcessStartTime(seconds: startedAt, microseconds: 0),
            processArguments: processArguments
        )
    }
}

#Preview(
    "Compact - Process Only",
    traits: .fixedLayout(width: 360, height: 241)
) {
    ProcessNotchPreviewFactory.make(displayMode: .simple)
}

#Preview(
    "Advanced - Process Only",
    traits: .fixedLayout(width: 680, height: 272)
) {
    ProcessNotchPreviewFactory.make(displayMode: .fullTree)
}

#Preview(
    "Compact - Password",
    traits: .fixedLayout(width: 360, height: 291)
) {
    ProcessNotchPreviewFactory.make(displayMode: .simple, accessory: .password)
}

#Preview(
    "Advanced - Password",
    traits: .fixedLayout(width: 680, height: 322)
) {
    ProcessNotchPreviewFactory.make(displayMode: .fullTree, accessory: .password)
}

#Preview(
    "Compact - Install PAM",
    traits: .fixedLayout(width: 360, height: 285)
) {
    ProcessNotchPreviewFactory.make(displayMode: .simple, accessory: .install)
}

#Preview(
    "Advanced - Install PAM",
    traits: .fixedLayout(width: 680, height: 316)
) {
    ProcessNotchPreviewFactory.make(displayMode: .fullTree, accessory: .install)
}

#Preview(
    "Compact - Repair PAM",
    traits: .fixedLayout(width: 360, height: 285)
) {
    ProcessNotchPreviewFactory.make(displayMode: .simple, accessory: .repair)
}

#Preview(
    "Advanced - Repair PAM",
    traits: .fixedLayout(width: 680, height: 316)
) {
    ProcessNotchPreviewFactory.make(displayMode: .fullTree, accessory: .repair)
}

#Preview(
    "Pending Process Tree",
    traits: .fixedLayout(width: 360, height: 117)
) {
    ProcessNotchPreviewFactory.make(displayMode: .simple, snapshot: .pending)
}

#Preview(
    "External Display",
    traits: .fixedLayout(width: 360, height: 209)
) {
    ProcessNotchPreviewFactory.make(displayMode: .simple, notchSize: nil)
}

#Preview(
    "Constrained Display - Advanced Password",
    traits: .fixedLayout(width: 668, height: 280)
) {
    ProcessNotchPreviewFactory.make(
        displayMode: .fullTree,
        accessory: .password,
        screenSize: ProcessNotchPreviewFactory.constrainedScreenSize
    )
}
#endif

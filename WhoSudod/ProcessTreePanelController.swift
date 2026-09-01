import AppKit

@MainActor
final class ProcessTreePanelController: NSWindowController {
    private let content: CompanionContentView
    private var currentSnapshot: AuthenticationProcessSnapshot?
    private(set) var isPresented = false

    init() {
        content = CompanionContentView()
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

        let sidecar = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame
        )
        content.setAttachmentSide(
            sidecar.side,
            reservedDialogWidth: sidecar.reservedDialogWidth
        )

        if window.frame != sidecar.frame {
            if window.frame.size == sidecar.frame.size {
                window.setFrameOrigin(sidecar.frame.origin)
            } else {
                window.setFrame(sidecar.frame, display: isPresented)
                content.frame = NSRect(origin: .zero, size: sidecar.frame.size)
            }
        }
        if !isPresented {
            window.orderFrontRegardless()
            isPresented = true
        }
    }

    func hide() {
        guard isPresented else {
            return
        }
        window?.orderOut(nil)
        isPresented = false
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
    }
}

private final class PassivePanel: NSPanel {
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

@MainActor
private final class CompanionContentView: NSView {
    private let processTable = ProcessTableView()
    private let material = NSVisualEffectView()
    private let body = NSView()
    private var bodySideConstraints: [NSLayoutConstraint] = []
    private var attachmentSide: SidecarSide?
    private var reservedDialogWidth: CGFloat = 0

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        configure()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(snapshot: AuthenticationProcessSnapshot) {
        processTable.update(snapshot: snapshot)
    }

    func setAttachmentSide(_ side: SidecarSide, reservedDialogWidth: CGFloat) {
        guard side != attachmentSide || reservedDialogWidth != self.reservedDialogWidth else {
            return
        }
        NSLayoutConstraint.deactivate(bodySideConstraints)
        if side == .right {
            bodySideConstraints = [
                body.leadingAnchor.constraint(
                    equalTo: material.leadingAnchor,
                    constant: reservedDialogWidth
                ),
                body.trailingAnchor.constraint(equalTo: material.trailingAnchor)
            ]
        } else {
            bodySideConstraints = [
                body.leadingAnchor.constraint(equalTo: material.leadingAnchor),
                body.trailingAnchor.constraint(
                    equalTo: material.trailingAnchor,
                    constant: -reservedDialogWidth
                )
            ]
        }
        NSLayoutConstraint.activate(bodySideConstraints)
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
        material.layer?.borderColor = NSColor.separatorColor.withAlphaComponent(0.28).cgColor
        addSubview(material)

        let tint = NSView()
        tint.translatesAutoresizingMaskIntoConstraints = false
        tint.wantsLayer = true
        tint.layer?.backgroundColor = NSColor.windowBackgroundColor.withAlphaComponent(0.94).cgColor
        material.addSubview(tint)

        body.translatesAutoresizingMaskIntoConstraints = false
        material.addSubview(body)

        body.addSubview(processTable)
        NSLayoutConstraint.activate([
            material.topAnchor.constraint(equalTo: topAnchor),
            material.leadingAnchor.constraint(equalTo: leadingAnchor),
            material.trailingAnchor.constraint(equalTo: trailingAnchor),
            material.bottomAnchor.constraint(equalTo: bottomAnchor),

            tint.topAnchor.constraint(equalTo: material.topAnchor),
            tint.leadingAnchor.constraint(equalTo: material.leadingAnchor),
            tint.trailingAnchor.constraint(equalTo: material.trailingAnchor),
            tint.bottomAnchor.constraint(equalTo: material.bottomAnchor),

            body.topAnchor.constraint(equalTo: material.topAnchor),
            body.bottomAnchor.constraint(equalTo: material.bottomAnchor),

            processTable.topAnchor.constraint(equalTo: body.topAnchor, constant: 16),
            processTable.leadingAnchor.constraint(equalTo: body.leadingAnchor, constant: 12),
            processTable.trailingAnchor.constraint(equalTo: body.trailingAnchor, constant: -12),
            processTable.bottomAnchor.constraint(equalTo: body.bottomAnchor, constant: -16)
        ])
    }
}

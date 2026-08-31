import AppKit

@MainActor
final class ProcessTreePanelController: NSWindowController {
    private let content: CompanionContentView
    private var currentSnapshot: SudoProcessSnapshot?
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
        snapshot: SudoProcessSnapshot,
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
        content.fit(height: sidecar.frame.height)

        if window.frame != sidecar.frame {
            window.setFrame(sidecar.frame, display: isPresented)
            content.frame = NSRect(origin: .zero, size: sidecar.frame.size)
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
    private let titleLabel = NSTextField(labelWithString: "Administrator access requested")
    private let subtitleLabel = NSTextField(labelWithString: "")
    private let processTable = ProcessTableView()
    private let tableHeight: NSLayoutConstraint
    private let material = NSVisualEffectView()
    private let body = NSView()
    private let separator = NSBox()
    private let footer = NSTextField(
        labelWithString: "Read-only snapshot. No authentication data is read."
    )
    private var bodySideConstraints: [NSLayoutConstraint] = []
    private var textLeadingConstraint: NSLayoutConstraint?
    private var attachmentSide: SidecarSide?
    private var reservedDialogWidth: CGFloat = 0

    override init(frame frameRect: NSRect) {
        tableHeight = processTable.heightAnchor.constraint(equalToConstant: 84)
        super.init(frame: frameRect)
        configure()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(snapshot: SudoProcessSnapshot) {
        processTable.update(snapshot: snapshot)
        if snapshot.candidates.isEmpty {
            switch snapshot.inspectionState {
            case .pending:
                subtitleLabel.stringValue = "Looking for live sudo candidates…"
            case .complete:
                subtitleLabel.stringValue = "No verified live sudo candidate was found."
            case .partial:
                subtitleLabel.stringValue = "Process inspection was incomplete; no candidate was verified."
            case .unavailable:
                subtitleLabel.stringValue = "Process inspection is unavailable."
            }
            return
        }

        if snapshot.candidates.count == 1 {
            let chain = snapshot.candidates[0]
            let completeness = chain.isComplete
                ? ""
                : " Current parent chain may be incomplete."
            if snapshot.inspectionState == .unavailable {
                subtitleLabel.stringValue = "Last known sudo request. Live process inspection is unavailable.\(completeness)"
            } else {
                let requestState: String
                if !chain.descendants.isEmpty {
                    requestState = " Live descendants are shown."
                } else if chain.sudoProcess.requestedCommand != nil {
                    requestState = " The requested command has not started."
                } else {
                    requestState = " No live descendant is present."
                }
                let rescanNote = snapshot.inspectionState == .partial
                    ? " Inspection is incomplete."
                    : ""
                subtitleLabel.stringValue = "Likely live sudo request.\(requestState)\(completeness)\(rescanNote)"
            }
        } else {
            subtitleLabel.stringValue = "Likely live sudo request."
        }
    }

    func fit(height: CGFloat) {
        tableHeight.constant = max(58, height - 120)
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
        textLeadingConstraint?.constant = side == .left ? 26 : 16
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

        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.font = .systemFont(ofSize: 17, weight: .semibold)
        body.addSubview(titleLabel)

        subtitleLabel.translatesAutoresizingMaskIntoConstraints = false
        subtitleLabel.font = .systemFont(ofSize: 12)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.maximumNumberOfLines = 1
        subtitleLabel.lineBreakMode = .byTruncatingTail
        body.addSubview(subtitleLabel)

        body.addSubview(processTable)

        separator.translatesAutoresizingMaskIntoConstraints = false
        separator.boxType = .separator
        body.addSubview(separator)

        footer.translatesAutoresizingMaskIntoConstraints = false
        footer.font = .systemFont(ofSize: 11)
        footer.textColor = .tertiaryLabelColor
        body.addSubview(footer)

        tableHeight.isActive = true
        textLeadingConstraint = titleLabel.leadingAnchor.constraint(
            equalTo: body.leadingAnchor,
            constant: 16
        )
        textLeadingConstraint?.isActive = true
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

            titleLabel.topAnchor.constraint(equalTo: body.topAnchor, constant: 20),
            titleLabel.trailingAnchor.constraint(equalTo: body.trailingAnchor, constant: -16),

            subtitleLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 2),
            subtitleLabel.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),
            subtitleLabel.trailingAnchor.constraint(equalTo: titleLabel.trailingAnchor),

            processTable.topAnchor.constraint(equalTo: subtitleLabel.bottomAnchor, constant: 10),
            processTable.leadingAnchor.constraint(equalTo: body.leadingAnchor, constant: 12),
            processTable.trailingAnchor.constraint(equalTo: body.trailingAnchor, constant: -12),

            separator.topAnchor.constraint(equalTo: processTable.bottomAnchor, constant: 10),
            separator.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),
            separator.trailingAnchor.constraint(equalTo: titleLabel.trailingAnchor),

            footer.topAnchor.constraint(equalTo: separator.bottomAnchor, constant: 8),
            footer.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),
            footer.trailingAnchor.constraint(equalTo: titleLabel.trailingAnchor),
            footer.bottomAnchor.constraint(equalTo: body.bottomAnchor, constant: -20)
        ])
    }
}

import AppKit

@MainActor
final class PAMPasswordEntryView: NSView {
    var onSubmit: ((String) -> Void)?

    private let passwordField = NSSecureTextField()
    private let submitButton = NSButton()
    private let passwordFieldCell = TrailingAccessorySecureTextFieldCell(textCell: "")

    private enum Metrics {
        static let fieldHeight: CGFloat = 32
        static let submitWidth: CGFloat = 66
        static let submitTrailingInset: CGFloat = 4
        static let textToSubmitSpacing: CGFloat = 8
    }

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        configure()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func clearPassword() {
        currentPasswordEditor?.string = ""
        passwordField.abortEditing()
        passwordField.stringValue = ""
    }

    private var currentPasswordEditor: NSText? {
        passwordField.currentEditor()
    }

    private func configure() {
        setAccessibilityIdentifier("who-sudod.pam-password-entry")

        passwordField.cell = passwordFieldCell
        passwordField.isEditable = true
        passwordField.isSelectable = true
        passwordFieldCell.trailingAccessoryWidth = Metrics.submitWidth
            + Metrics.submitTrailingInset
            + Metrics.textToSubmitSpacing
        passwordField.translatesAutoresizingMaskIntoConstraints = false
        passwordField.placeholderString = "Password"
        passwordField.usesSingleLineMode = true
        passwordField.isBezeled = false
        passwordField.isBordered = false
        passwordField.drawsBackground = false
        passwordField.focusRingType = .none
        passwordField.wantsLayer = true
        passwordField.layer?.cornerRadius = 0
        passwordField.layer?.borderWidth = 0
        passwordField.layer?.borderColor = nil
        passwordField.layer?.backgroundColor = NSColor.white.withAlphaComponent(0.08).cgColor
        passwordField.target = self
        passwordField.action = #selector(submitPassword)
        passwordField.setAccessibilityIdentifier("who-sudod.pam-password-field")
        addSubview(passwordField)

        submitButton.translatesAutoresizingMaskIntoConstraints = false
        submitButton.title = "Submit"
        submitButton.bezelStyle = .rounded
        submitButton.controlSize = .small
        submitButton.keyEquivalent = "\r"
        submitButton.target = self
        submitButton.action = #selector(submitPassword)
        submitButton.setAccessibilityIdentifier("who-sudod.pam-password-submit")
        addSubview(submitButton)

        NSLayoutConstraint.activate([
            passwordField.leadingAnchor.constraint(equalTo: leadingAnchor),
            passwordField.trailingAnchor.constraint(equalTo: trailingAnchor),
            passwordField.centerYAnchor.constraint(equalTo: centerYAnchor),
            passwordField.heightAnchor.constraint(equalToConstant: Metrics.fieldHeight),

            submitButton.trailingAnchor.constraint(
                equalTo: passwordField.trailingAnchor,
                constant: -Metrics.submitTrailingInset
            ),
            submitButton.centerYAnchor.constraint(equalTo: passwordField.centerYAnchor),
            submitButton.widthAnchor.constraint(equalToConstant: Metrics.submitWidth)
        ])
    }

    @objc
    private func submitPassword() {
        passwordField.validateEditing()
        let password = passwordField.stringValue
        clearPassword()
        onSubmit?(password)
    }
}

@MainActor
private final class TrailingAccessorySecureTextFieldCell: NSSecureTextFieldCell {
    var trailingAccessoryWidth: CGFloat = 0

    override func drawingRect(forBounds rect: NSRect) -> NSRect {
        centeredTextRect(forBounds: rect)
    }

    override func titleRect(forBounds rect: NSRect) -> NSRect {
        centeredTextRect(forBounds: rect)
    }

    override func edit(
        withFrame rect: NSRect,
        in controlView: NSView,
        editor textObj: NSText,
        delegate: Any?,
        event: NSEvent?
    ) {
        super.edit(
            withFrame: centeredTextRect(forBounds: rect),
            in: controlView,
            editor: textObj,
            delegate: delegate,
            event: event
        )
    }

    override func select(
        withFrame rect: NSRect,
        in controlView: NSView,
        editor textObj: NSText,
        delegate: Any?,
        start selStart: Int,
        length selLength: Int
    ) {
        super.select(
            withFrame: centeredTextRect(forBounds: rect),
            in: controlView,
            editor: textObj,
            delegate: delegate,
            start: selStart,
            length: selLength
        )
    }

    private func centeredTextRect(forBounds rect: NSRect) -> NSRect {
        var textRect = insetTrailingEdge(of: super.titleRect(forBounds: rect))
        let textHeight = min(
            textRect.height,
            ceil(super.cellSize(forBounds: rect).height)
        )
        textRect.origin.y += (textRect.height - textHeight) / 2
        textRect.size.height = textHeight
        return textRect
    }

    private func insetTrailingEdge(of rect: NSRect) -> NSRect {
        var insetRect = rect
        let leadingInset: CGFloat = 10
        insetRect.origin.x += leadingInset
        insetRect.size.width = max(
            0,
            insetRect.width - leadingInset - trailingAccessoryWidth
        )
        return insetRect
    }
}

import AppKit
import UniformTypeIdentifiers

@MainActor
final class IgnoredApplicationsSettingsWindowController: NSWindowController, NSWindowDelegate {
    private let settingsViewController: IgnoredApplicationsSettingsViewController
    private let didClose: () -> Void

    init(
        store: IgnoredApplicationsStore,
        didClose: @escaping () -> Void
    ) {
        settingsViewController = IgnoredApplicationsSettingsViewController(store: store)
        self.didClose = didClose
        let window = NSWindow(contentViewController: settingsViewController)
        window.title = "Ignored Applications"
        window.styleMask = [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]
        window.titlebarAppearsTransparent = true
        window.toolbarStyle = .unified
        let toolbar = NSToolbar(identifier: "WhoSudodSettingsToolbar")
        toolbar.displayMode = .iconOnly
        window.toolbar = toolbar
        window.setContentSize(NSSize(width: 680, height: 540))
        window.minSize = NSSize(width: 560, height: 460)
        window.isReleasedWhenClosed = false
        window.setFrameAutosaveName("WhoSudodIgnoredApplicationsSettings")
        super.init(window: window)
        window.delegate = self
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func present() {
        settingsViewController.reload()
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        settingsViewController.focusApplicationList()
        DispatchQueue.main.async { [weak self] in
            self?.window?.makeKey()
            self?.settingsViewController.focusApplicationList()
        }
    }

    func windowWillClose(_ notification: Notification) {
        didClose()
    }
}

@MainActor
final class IgnoredApplicationsTableView: NSTableView {
    var deleteSelection: (() -> Void)?

    override func keyDown(with event: NSEvent) {
        switch event.keyCode {
        case 51, 117:
            deleteSelection?()
        default:
            super.keyDown(with: event)
        }
    }
}

@MainActor
private final class IgnoredApplicationsSettingsViewController: NSViewController,
    NSTableViewDataSource,
    NSTableViewDelegate {
    private let store: IgnoredApplicationsStore
    private let tableView = IgnoredApplicationsTableView()
    private let addButton = NSButton()
    private let removeButton = NSButton()
    private var rules: [IgnoredApplicationRule] = []
    private var sortColumn = IgnoredApplicationsSortColumn.application
    private var sortAscending = true

    init(store: IgnoredApplicationsStore) {
        self.store = store
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func loadView() {
        let root = NSView(frame: NSRect(x: 0, y: 0, width: 680, height: 540))
        root.translatesAutoresizingMaskIntoConstraints = false
        view = root

        let explanation = NSTextField(
            wrappingLabelWithString: "Who Sudo'd does not show a process tree when an application makes one of its selected authentication requests."
        )
        explanation.translatesAutoresizingMaskIntoConstraints = false
        explanation.isSelectable = false
        explanation.textColor = .secondaryLabelColor
        explanation.font = .systemFont(ofSize: 13)

        let applicationColumn = NSTableColumn(
            identifier: NSUserInterfaceItemIdentifier(IgnoredApplicationsSortColumn.application.rawValue)
        )
        applicationColumn.title = "Application"
        applicationColumn.minWidth = 220
        applicationColumn.width = 330
        applicationColumn.resizingMask = .autoresizingMask
        applicationColumn.sortDescriptorPrototype = NSSortDescriptor(
            key: IgnoredApplicationsSortColumn.application.rawValue,
            ascending: true
        )

        let dialogsColumn = NSTableColumn(
            identifier: NSUserInterfaceItemIdentifier(IgnoredApplicationsSortColumn.dialogs.rawValue)
        )
        dialogsColumn.title = "Ignored Dialogs"
        dialogsColumn.minWidth = 220
        dialogsColumn.width = 280
        dialogsColumn.resizingMask = .userResizingMask
        dialogsColumn.sortDescriptorPrototype = NSSortDescriptor(
            key: IgnoredApplicationsSortColumn.dialogs.rawValue,
            ascending: true
        )

        tableView.addTableColumn(applicationColumn)
        tableView.addTableColumn(dialogsColumn)
        tableView.headerView = NSTableHeaderView()
        tableView.sortDescriptors = [applicationColumn.sortDescriptorPrototype!]
        tableView.delegate = self
        tableView.dataSource = self
        tableView.rowHeight = 48
        tableView.intercellSpacing = NSSize(width: 0, height: 1)
        tableView.selectionHighlightStyle = .regular
        tableView.allowsEmptySelection = true
        tableView.backgroundColor = .clear
        tableView.gridStyleMask = .solidHorizontalGridLineMask
        tableView.gridColor = .separatorColor
        tableView.setAccessibilityIdentifier("who-sudod.settings.ignored-applications")
        tableView.setAccessibilityLabel("Ignored applications")
        tableView.deleteSelection = { [weak self] in
            self?.removeApplication()
        }

        let scrollView = NSScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.borderType = .noBorder
        scrollView.drawsBackground = false
        scrollView.contentView.drawsBackground = false

        configureListButton(
            addButton,
            symbolName: "plus",
            label: "Add application",
            action: #selector(addApplication)
        )
        configureListButton(
            removeButton,
            symbolName: "minus",
            label: "Remove selected application",
            action: #selector(removeApplication)
        )
        let listButtons = NSStackView(views: [addButton, removeButton])
        listButtons.translatesAutoresizingMaskIntoConstraints = false
        listButtons.orientation = .horizontal
        listButtons.spacing = 4

        let listGroup = makeGlassGroup()
        let listContent = listGroup.contentView ?? NSView()
        let footerSeparator = makeSeparator()
        for subview in [scrollView, footerSeparator, listButtons] {
            listContent.addSubview(subview)
        }

        root.addSubview(listGroup)
        root.addSubview(explanation)

        NSLayoutConstraint.activate([
            listGroup.topAnchor.constraint(equalTo: root.safeAreaLayoutGuide.topAnchor, constant: 18),
            listGroup.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
            listGroup.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
            listGroup.bottomAnchor.constraint(equalTo: explanation.topAnchor, constant: -12),
            listGroup.heightAnchor.constraint(greaterThanOrEqualToConstant: 360),

            scrollView.topAnchor.constraint(equalTo: listContent.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: listContent.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: listContent.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: footerSeparator.topAnchor),

            footerSeparator.leadingAnchor.constraint(equalTo: listContent.leadingAnchor),
            footerSeparator.trailingAnchor.constraint(equalTo: listContent.trailingAnchor),
            footerSeparator.bottomAnchor.constraint(equalTo: listButtons.topAnchor, constant: -2),
            footerSeparator.heightAnchor.constraint(equalToConstant: 1),

            listButtons.leadingAnchor.constraint(equalTo: listContent.leadingAnchor, constant: 10),
            listButtons.bottomAnchor.constraint(equalTo: listContent.bottomAnchor, constant: -6),
            listButtons.heightAnchor.constraint(equalToConstant: 28),

            explanation.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 36),
            explanation.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -36),
            explanation.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -24)
        ])

        reload()
    }

    private func makeGlassGroup() -> NSGlassEffectView {
        let glass = NSGlassEffectView()
        glass.translatesAutoresizingMaskIntoConstraints = false
        glass.style = .clear
        glass.cornerRadius = 16
        glass.tintColor = NSColor.controlBackgroundColor.withAlphaComponent(0.45)
        glass.contentView = NSView()
        if #available(macOS 27.0, *) {
            glass.effectIsInteractive = true
        }
        return glass
    }

    private func makeSeparator() -> NSView {
        let separator = NSView()
        separator.translatesAutoresizingMaskIntoConstraints = false
        separator.wantsLayer = true
        separator.layer?.backgroundColor = NSColor.separatorColor.cgColor
        return separator
    }

    func reload() {
        guard isViewLoaded else {
            return
        }
        let selectedIdentifier = selectedRule?.identifier
        rules = IgnoredApplicationRuleSorter.sorted(
            store.rules,
            by: sortColumn,
            ascending: sortAscending
        )
        tableView.reloadData()
        if let selectedIdentifier,
           let index = rules.firstIndex(where: { $0.identifier == selectedIdentifier }) {
            tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
        }
        updateControls()
    }

    func focusApplicationList() {
        view.window?.makeFirstResponder(tableView)
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        rules.count
    }

    func tableView(
        _ tableView: NSTableView,
        viewFor tableColumn: NSTableColumn?,
        row: Int
    ) -> NSView? {
        let rule = rules[row]
        switch tableColumn?.identifier.rawValue {
        case IgnoredApplicationsSortColumn.application.rawValue:
            let cell = IgnoredApplicationCellView()
            cell.configure(
                name: rule.displayName,
                icon: NSWorkspace.shared.icon(forFile: rule.applicationPath)
            )
            return cell
        case IgnoredApplicationsSortColumn.dialogs.rawValue:
            let cell = IgnoredDialogsCellView()
            cell.configure(requestKinds: rule.requestKinds) { [weak self] requestKinds in
                self?.setRequestKinds(requestKinds, for: rule.identifier)
            }
            return cell
        default:
            return nil
        }
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        updateControls()
    }

    func tableView(
        _ tableView: NSTableView,
        sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]
    ) {
        guard let descriptor = tableView.sortDescriptors.first,
              let key = descriptor.key,
              let column = IgnoredApplicationsSortColumn(rawValue: key) else {
            return
        }
        sortColumn = column
        sortAscending = descriptor.ascending
        reload()
    }

    @objc
    private func addApplication() {
        let panel = NSOpenPanel()
        panel.title = "Choose Applications to Ignore"
        panel.prompt = "Ignore"
        panel.message = "Select one or more applications. All authentication types are selected by default."
        panel.allowedContentTypes = [.application]
        panel.allowsMultipleSelection = true
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.treatsFilePackagesAsDirectories = false
        panel.directoryURL = URL(fileURLWithPath: "/Applications", isDirectory: true)

        let completion: (NSApplication.ModalResponse) -> Void = { [weak self] response in
            guard response == .OK, let self else {
                return
            }
            var lastIdentifier: String?
            var hadInvalidSelection = false
            for url in panel.urls {
                if let rule = self.store.addApplication(at: url) {
                    lastIdentifier = rule.identifier
                } else {
                    hadInvalidSelection = true
                }
            }
            self.rules = IgnoredApplicationRuleSorter.sorted(
                self.store.rules,
                by: self.sortColumn,
                ascending: self.sortAscending
            )
            self.tableView.reloadData()
            if let lastIdentifier,
               let index = self.rules.firstIndex(where: { $0.identifier == lastIdentifier }) {
                self.tableView.selectRowIndexes(
                    IndexSet(integer: index),
                    byExtendingSelection: false
                )
                self.tableView.scrollRowToVisible(index)
            }
            self.updateControls()
            if hadInvalidSelection {
                self.presentInvalidApplicationAlert()
            }
        }

        if let window = view.window {
            panel.beginSheetModal(for: window, completionHandler: completion)
        } else {
            completion(panel.runModal())
        }
    }

    @objc
    private func removeApplication() {
        guard let rule = selectedRule else {
            return
        }
        let previousIndex = tableView.selectedRow
        store.removeRule(identifier: rule.identifier)
        rules = IgnoredApplicationRuleSorter.sorted(
            store.rules,
            by: sortColumn,
            ascending: sortAscending
        )
        tableView.reloadData()
        if !rules.isEmpty {
            let nextIndex = min(previousIndex, rules.count - 1)
            tableView.selectRowIndexes(
                IndexSet(integer: nextIndex),
                byExtendingSelection: false
            )
        }
        updateControls()
    }

    private func setRequestKinds(
        _ requestKinds: Set<AuthenticationRequestKind>,
        for identifier: String
    ) {
        store.setRequestKinds(requestKinds, for: identifier)
        reload()
    }

    private var selectedRule: IgnoredApplicationRule? {
        let row = tableView.selectedRow
        guard rules.indices.contains(row) else {
            return nil
        }
        return rules[row]
    }

    private func updateControls() {
        removeButton.isEnabled = selectedRule != nil
    }

    private func configureListButton(
        _ button: NSButton,
        symbolName: String,
        label: String,
        action: Selector
    ) {
        button.translatesAutoresizingMaskIntoConstraints = false
        button.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: label)
        button.imagePosition = .imageOnly
        button.bezelStyle = .accessoryBarAction
        button.controlSize = .small
        button.target = self
        button.action = action
        button.toolTip = label
        button.setAccessibilityLabel(label)
        button.widthAnchor.constraint(equalToConstant: 30).isActive = true
    }

    private func presentInvalidApplicationAlert() {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "The selected item is not an application."
        alert.informativeText = "Select a macOS application bundle."
        if let window = view.window {
            alert.beginSheetModal(for: window)
        } else {
            alert.runModal()
        }
    }

}

extension AuthenticationRequestKind {
    static let settingsOrder: [AuthenticationRequestKind] = [
        .sudo,
        .authorization,
        .localAuthentication
    ]

    var settingsDisplayName: String {
        switch self {
        case .sudo:
            return "Sudo"
        case .authorization:
            return "Administrator access"
        case .localAuthentication:
            return "Local Authentication"
        }
    }
}

enum IgnoredApplicationsSortColumn: String {
    case application
    case dialogs
}

enum IgnoredApplicationRuleSorter {
    static func summary(_ requestKinds: Set<AuthenticationRequestKind>) -> String {
        if requestKinds == Set(AuthenticationRequestKind.allCases) {
            return "All dialogs"
        }
        return AuthenticationRequestKind.settingsOrder.compactMap { kind in
            requestKinds.contains(kind) ? kind.settingsDisplayName : nil
        }.joined(separator: ", ")
    }

    static func sorted(
        _ rules: [IgnoredApplicationRule],
        by column: IgnoredApplicationsSortColumn,
        ascending: Bool
    ) -> [IgnoredApplicationRule] {
        rules.sorted { left, right in
            let comparison: ComparisonResult
            switch column {
            case .application:
                comparison = left.displayName.localizedStandardCompare(right.displayName)
            case .dialogs:
                comparison = summary(left.requestKinds).localizedStandardCompare(
                    summary(right.requestKinds)
                )
            }

            if comparison != .orderedSame {
                return ascending
                    ? comparison == .orderedAscending
                    : comparison == .orderedDescending
            }

            let nameComparison = left.displayName.localizedStandardCompare(right.displayName)
            if nameComparison != .orderedSame {
                return nameComparison == .orderedAscending
            }
            return left.identifier < right.identifier
        }
    }
}

@MainActor
private final class IgnoredApplicationCellView: NSTableCellView {
    private let applicationIcon = NSImageView()
    private let nameLabel = NSTextField(labelWithString: "")

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        applicationIcon.translatesAutoresizingMaskIntoConstraints = false
        applicationIcon.imageScaling = .scaleProportionallyUpOrDown

        nameLabel.translatesAutoresizingMaskIntoConstraints = false
        nameLabel.font = .systemFont(ofSize: 14, weight: .regular)
        nameLabel.lineBreakMode = .byTruncatingTail

        addSubview(applicationIcon)
        addSubview(nameLabel)
        imageView = applicationIcon
        textField = nameLabel

        NSLayoutConstraint.activate([
            applicationIcon.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 10),
            applicationIcon.centerYAnchor.constraint(equalTo: centerYAnchor),
            applicationIcon.widthAnchor.constraint(equalToConstant: 30),
            applicationIcon.heightAnchor.constraint(equalToConstant: 30),

            nameLabel.leadingAnchor.constraint(equalTo: applicationIcon.trailingAnchor, constant: 10),
            nameLabel.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -10),
            nameLabel.centerYAnchor.constraint(equalTo: centerYAnchor)
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func configure(name: String, icon: NSImage) {
        nameLabel.stringValue = name
        nameLabel.toolTip = name
        applicationIcon.image = icon
        setAccessibilityLabel(name)
    }
}

@MainActor
private final class IgnoredDialogsCellView: NSTableCellView, NSMenuDelegate {
    private let popUpButton = NSPopUpButton(frame: .zero, pullsDown: false)
    private var summaryItem: NSMenuItem?
    private var requestKinds = Set<AuthenticationRequestKind>()
    private var didChange: ((Set<AuthenticationRequestKind>) -> Void)?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        popUpButton.translatesAutoresizingMaskIntoConstraints = false
        popUpButton.bezelStyle = .rounded
        popUpButton.controlSize = .regular
        popUpButton.alignment = .left
        popUpButton.menu?.autoenablesItems = false
        popUpButton.menu?.delegate = self
        addSubview(popUpButton)

        NSLayoutConstraint.activate([
            popUpButton.leadingAnchor.constraint(greaterThanOrEqualTo: leadingAnchor, constant: 10),
            popUpButton.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -10),
            popUpButton.centerYAnchor.constraint(equalTo: centerYAnchor),
            popUpButton.heightAnchor.constraint(equalToConstant: 30),
            popUpButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 170)
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func configure(
        requestKinds: Set<AuthenticationRequestKind>,
        didChange: @escaping (Set<AuthenticationRequestKind>) -> Void
    ) {
        self.requestKinds = requestKinds
        self.didChange = didChange
        rebuildMenu()
    }

    func menuWillOpen(_ menu: NSMenu) {
        summaryItem?.isHidden = true
    }

    func menuDidClose(_ menu: NSMenu) {
        summaryItem?.isHidden = false
        if let summaryItem {
            popUpButton.select(summaryItem)
        }
    }

    private func rebuildMenu() {
        guard let menu = popUpButton.menu else {
            return
        }
        menu.removeAllItems()
        menu.delegate = self
        menu.autoenablesItems = false

        let summary = IgnoredApplicationRuleSorter.summary(requestKinds)
        let summaryItem = NSMenuItem(
            title: summary,
            action: nil,
            keyEquivalent: ""
        )
        menu.addItem(summaryItem)
        self.summaryItem = summaryItem

        for kind in AuthenticationRequestKind.settingsOrder {
            let item = NSMenuItem(
                title: kind.settingsDisplayName,
                action: #selector(toggleDialog(_:)),
                keyEquivalent: ""
            )
            item.target = self
            item.representedObject = kind.rawValue
            item.state = requestKinds.contains(kind) ? .on : .off
            menu.addItem(item)
        }

        popUpButton.select(summaryItem)
        popUpButton.toolTip = summary
        popUpButton.setAccessibilityLabel("Ignored dialogs")
        popUpButton.setAccessibilityValue(summary)
    }

    @objc
    private func toggleDialog(_ sender: NSMenuItem) {
        guard let rawValue = sender.representedObject as? String,
              let kind = AuthenticationRequestKind(rawValue: rawValue) else {
            return
        }
        var updated = requestKinds
        if updated.contains(kind) {
            updated.remove(kind)
        } else {
            updated.insert(kind)
        }
        guard !updated.isEmpty else {
            NSSound.beep()
            return
        }
        apply(updated)
    }

    private func apply(_ updated: Set<AuthenticationRequestKind>) {
        requestKinds = updated
        didChange?(updated)
    }
}

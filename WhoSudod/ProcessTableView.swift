import AppKit
import UniformTypeIdentifiers

enum ProcessDisplayMode: String, CaseIterable, Sendable {
    case simple
    case fullTree

    static let defaultsKey = "ProcessDisplayMode"
    static let environmentKey = "WHO_SUDOD_DISPLAY_MODE"

    static func initial(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        defaults: UserDefaults = .standard
    ) -> ProcessDisplayMode {
        if let forced = environment[environmentKey],
           let mode = ProcessDisplayMode(rawValue: forced) {
            return mode
        }
        if let saved = defaults.string(forKey: defaultsKey),
           let mode = ProcessDisplayMode(rawValue: saved) {
            return mode
        }
        return .simple
    }
}

struct ProcessTableRow: Equatable {
    let process: ProcessRecord?
    let requestedCommand: RequestedCommand?
    let depth: Int
    let candidateIndex: Int
    let candidateIdentity: ProcessIdentity?

    init(
        process: ProcessRecord?,
        requestedCommand: RequestedCommand?,
        depth: Int,
        candidateIndex: Int,
        candidateIdentity: ProcessIdentity? = nil
    ) {
        self.process = process
        self.requestedCommand = requestedCommand
        self.depth = depth
        self.candidateIndex = candidateIndex
        self.candidateIdentity = candidateIdentity
    }
}

enum ProcessTableRowBuilder {
    static func rows(
        for snapshot: AuthenticationProcessSnapshot,
        mode: ProcessDisplayMode
    ) -> [ProcessTableRow] {
        snapshot.candidates.enumerated().flatMap { candidateIndex, chain in
            rows(for: chain, candidateIndex: candidateIndex, mode: mode)
        }
    }

    private static func rows(
        for chain: ProcessChain,
        candidateIndex: Int,
        mode: ProcessDisplayMode
    ) -> [ProcessTableRow] {
        let visibleProcesses: ArraySlice<ProcessRecord>
        switch mode {
        case .fullTree:
            visibleProcesses = chain.processes[...]
        case .simple:
            let nearestApplicationIndex = chain.processes.lastIndex { process in
                guard let path = process.executablePath else {
                    return false
                }
                return ProcessTablePresentationBuilder.enclosingApplicationPath(
                    for: path
                ) != nil
            }
            let startIndex: Int
            if let nearestApplicationIndex {
                startIndex = nearestApplicationIndex
            } else if chain.processes.count > 1,
                      chain.processes.first?.pid == 1 {
                startIndex = 1
            } else {
                startIndex = 0
            }
            visibleProcesses = chain.processes[startIndex...]
        }

        let ancestry = visibleProcesses.enumerated().map { depth, process in
            ProcessTableRow(
                process: process,
                requestedCommand: nil,
                depth: depth,
                candidateIndex: candidateIndex,
                candidateIdentity: chain.requesterProcess.identity
            )
        }
        let requesterDepth = max(0, visibleProcesses.count - 1)
        let descendants = chain.descendants.map { descendant in
            ProcessTableRow(
                process: descendant.process,
                requestedCommand: nil,
                depth: requesterDepth + descendant.depthFromRequester,
                candidateIndex: candidateIndex,
                candidateIdentity: chain.requesterProcess.identity
            )
        }
        let command: [ProcessTableRow]
        if chain.requestKind == .sudo,
           chain.descendants.isEmpty,
           let requestedCommand = chain.requesterProcess.requestedCommand {
            command = [
                ProcessTableRow(
                    process: nil,
                    requestedCommand: requestedCommand,
                    depth: requesterDepth + 1,
                    candidateIndex: candidateIndex,
                    candidateIdentity: chain.requesterProcess.identity
                )
            ]
        } else {
            command = []
        }
        return ancestry + command + descendants
    }
}

private enum ProcessTableCandidateIdentifier: Hashable {
    case requester(ProcessIdentity)
    case index(Int)
}

private enum ProcessTableRowSubjectIdentifier: Hashable {
    case process(ProcessIdentity)
    case requested(RequestedCommand)
}

private struct ProcessTableRowIdentifier: Hashable {
    let candidate: ProcessTableCandidateIdentifier
    let subject: ProcessTableRowSubjectIdentifier

    init?(_ row: ProcessTableRow) {
        candidate = row.candidateIdentity.map(ProcessTableCandidateIdentifier.requester)
            ?? .index(row.candidateIndex)
        if let process = row.process {
            subject = .process(process.identity)
        } else if let requestedCommand = row.requestedCommand {
            subject = .requested(requestedCommand)
        } else {
            return nil
        }
    }
}

struct ProcessTableRowTransition: Equatable {
    let removals: IndexSet
    let insertions: IndexSet
    let reloads: IndexSet

    init?(
        from oldRows: [ProcessTableRow],
        to newRows: [ProcessTableRow],
        reloadAllRetained: Bool = false
    ) {
        let oldIdentifiers = oldRows.compactMap(ProcessTableRowIdentifier.init)
        let newIdentifiers = newRows.compactMap(ProcessTableRowIdentifier.init)
        guard oldIdentifiers.count == oldRows.count,
              newIdentifiers.count == newRows.count,
              Set(oldIdentifiers).count == oldIdentifiers.count,
              Set(newIdentifiers).count == newIdentifiers.count else {
            return nil
        }

        let oldSet = Set(oldIdentifiers)
        let newSet = Set(newIdentifiers)
        let retainedOldOrder = oldIdentifiers.filter(newSet.contains)
        let retainedNewOrder = newIdentifiers.filter(oldSet.contains)
        guard retainedOldOrder == retainedNewOrder else {
            return nil
        }

        removals = IndexSet(
            oldIdentifiers.indices.filter { !newSet.contains(oldIdentifiers[$0]) }
        )
        insertions = IndexSet(
            newIdentifiers.indices.filter { !oldSet.contains(newIdentifiers[$0]) }
        )

        let oldIndexByIdentifier = Dictionary(
            uniqueKeysWithValues: oldIdentifiers.enumerated().map { ($0.element, $0.offset) }
        )
        reloads = IndexSet(
            newIdentifiers.indices.filter { newIndex in
                let identifier = newIdentifiers[newIndex]
                guard let oldIndex = oldIndexByIdentifier[identifier] else {
                    return false
                }
                return reloadAllRetained
                    || oldIndex != newIndex
                    || oldRows[oldIndex] != newRows[newIndex]
            }
        )
    }
}

struct ProcessTablePresentationRow: Codable, Equatable, Sendable {
    let candidateIndex: Int
    let depth: Int
    let process: String
    let pid: String
    let executableOrCommand: String
}

struct RenderedProcessTable: Equatable {
    let isComplete: Bool
    let rows: [ProcessTablePresentationRow]
}

enum ProcessTablePresentationBuilder {
    static func rows(
        for snapshot: AuthenticationProcessSnapshot,
        mode: ProcessDisplayMode
    ) -> [ProcessTablePresentationRow] {
        rows(for: ProcessTableRowBuilder.rows(for: snapshot, mode: mode), mode: mode)
    }

    static func rows(
        for rows: [ProcessTableRow],
        mode: ProcessDisplayMode
    ) -> [ProcessTablePresentationRow] {
        rows.map { row in
            let name: String
            let pid: String
            let path: String
            if let process = row.process {
                name = displayName(for: process)
                pid = String(process.pid)
                path = process.executablePath ?? "Path unavailable"
            } else {
                name = requestedCommandName(row.requestedCommand)
                pid = "—"
                path = row.requestedCommand?.displayText ?? "Command unavailable"
            }

            let safeName = DisplayTextSanitizer.sanitize(name)
            return ProcessTablePresentationRow(
                candidateIndex: row.candidateIndex,
                depth: row.depth,
                process: safeName,
                pid: mode == .simple ? "" : DisplayTextSanitizer.sanitize(pid),
                executableOrCommand: mode == .simple
                    ? ""
                    : DisplayTextSanitizer.sanitize(path)
            )
        }
    }

    static func enclosingApplicationPath(for executablePath: String) -> String? {
        var url = URL(fileURLWithPath: executablePath)
        while url.path != "/" {
            if url.pathExtension == "app",
               Bundle(url: url)?.executableURL?.resolvingSymlinksInPath().path
                == URL(fileURLWithPath: executablePath).resolvingSymlinksInPath().path {
                return url.path
            }
            url.deleteLastPathComponent()
        }
        return nil
    }

    private static func displayName(for process: ProcessRecord) -> String {
        guard let path = process.executablePath,
              let appPath = enclosingApplicationPath(for: path),
              let bundle = Bundle(url: URL(fileURLWithPath: appPath)) else {
            return process.name
        }
        return (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
            ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
            ?? process.name
    }

    private static func requestedCommandName(_ command: RequestedCommand?) -> String {
        guard let executable = command?.executable else {
            return "Command"
        }
        if executable.hasPrefix("/"),
           let appPath = enclosingApplicationPath(for: executable),
           let bundle = Bundle(url: URL(fileURLWithPath: appPath)) {
            return (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
                ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
                ?? URL(fileURLWithPath: executable).lastPathComponent
        }
        let name = URL(fileURLWithPath: executable).lastPathComponent
        return name.isEmpty ? "Command" : name
    }
}

struct ProcessTableRowContext: Equatable {
    let pid: String?
    let executablePath: String?
    let revealPath: String?
}

enum ProcessTableRowContextBuilder {
    static func context(
        for row: ProcessTableRow,
        fileExists: (String) -> Bool = FileManager.default.fileExists(atPath:)
    ) -> ProcessTableRowContext {
        let pid = row.process.map { String($0.pid) }
        let executablePath: String?
        if let process = row.process {
            executablePath = process.executablePath
        } else if let requested = row.requestedCommand?.executable,
                  requested.hasPrefix("/") {
            executablePath = requested
        } else {
            executablePath = nil
        }

        let revealCandidate = executablePath.map { path in
            ProcessTablePresentationBuilder.enclosingApplicationPath(for: path) ?? path
        }
        return ProcessTableRowContext(
            pid: pid,
            executablePath: executablePath,
            revealPath: revealCandidate.flatMap { fileExists($0) ? $0 : nil }
        )
    }
}

enum RequestedExecutableIconSource: Equatable {
    case file(String)
    case systemExecutable
}

enum RequestedExecutableResolver {
    static func iconSource(executable: String?) -> RequestedExecutableIconSource {
        guard let path = executable else {
            return .systemExecutable
        }
        guard path.hasPrefix("/"),
              FileManager.default.isExecutableFile(atPath: path) else {
            return .systemExecutable
        }
        if let applicationPath = ProcessTablePresentationBuilder.enclosingApplicationPath(
            for: path
        ) {
            return .file(applicationPath)
        }
        return .file(URL(fileURLWithPath: path).resolvingSymlinksInPath().path)
    }
}

@MainActor
final class ProcessTableView: NSView, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate {
    private enum Column {
        static let process = NSUserInterfaceItemIdentifier("process")
        static let pid = NSUserInterfaceItemIdentifier("pid")
        static let path = NSUserInterfaceItemIdentifier("path")
    }

    private let tableView: NSTableView
    private let processColumn = NSTableColumn(identifier: Column.process)
    private let pidColumn = NSTableColumn(identifier: Column.pid)
    private let pathColumn = NSTableColumn(identifier: Column.path)
    private let rowMenu = NSMenu(title: "Process")
    private var rows: [ProcessTableRow] = []
    private(set) var presentationRows: [ProcessTablePresentationRow] = []
    private(set) var displayMode: ProcessDisplayMode
    private var currentSnapshot = AuthenticationProcessSnapshot.pending
    private var iconCache: [String: NSImage] = [:]
    private let animationVisibilityOverride: Bool?
#if DEBUG
    private var lastRenderingFailure: String?
#endif

    override convenience init(frame frameRect: NSRect) {
        self.init(
            frame: frameRect,
            tableView: NSTableView(),
            displayMode: .simple
        )
    }

    convenience init(frame frameRect: NSRect, displayMode: ProcessDisplayMode) {
        self.init(
            frame: frameRect,
            tableView: NSTableView(),
            displayMode: displayMode
        )
    }

    init(
        frame frameRect: NSRect,
        tableView: NSTableView,
        displayMode: ProcessDisplayMode,
        animationVisibilityOverride: Bool? = nil
    ) {
        self.tableView = tableView
        self.displayMode = displayMode
        self.animationVisibilityOverride = animationVisibilityOverride
        super.init(frame: frameRect)
        configure()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(
        snapshot: AuthenticationProcessSnapshot,
        animated: Bool = true
    ) {
        currentSnapshot = snapshot
        rebuildRows(animated: animated)
    }

    func setDisplayMode(_ mode: ProcessDisplayMode) {
        guard mode != displayMode else {
            return
        }
        displayMode = mode
        configureColumnVisibility()
        rebuildRows(animated: true, reloadAllRetained: true)
    }

    var visibleColumnIdentifiers: [NSUserInterfaceItemIdentifier] {
        tableView.tableColumns.filter { !$0.isHidden }.map(\.identifier)
    }

    private func rebuildRows(
        animated: Bool,
        reloadAllRetained: Bool = false
    ) {
        let newRows = ProcessTableRowBuilder.rows(for: currentSnapshot, mode: displayMode)
        let newPresentationRows = ProcessTablePresentationBuilder.rows(
            for: newRows,
            mode: displayMode
        )
        let tableIsVisible = animationVisibilityOverride
            ?? (tableView.window?.isVisible == true)
        guard animated,
              tableIsVisible,
              let transition = ProcessTableRowTransition(
                from: rows,
                to: newRows,
                reloadAllRetained: reloadAllRetained
              ) else {
            rows = newRows
            presentationRows = newPresentationRows
            tableView.reloadData()
            return
        }

        let reduceMotion = NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        let removalAnimation: NSTableView.AnimationOptions = reduceMotion
            ? []
            : .effectFade
        let insertionAnimation: NSTableView.AnimationOptions = reduceMotion
            ? []
            : .effectFade

        if !transition.removals.isEmpty || !transition.insertions.isEmpty {
            tableView.beginUpdates()
        }
        if !transition.removals.isEmpty {
            for index in transition.removals.reversed() {
                rows.remove(at: index)
                presentationRows.remove(at: index)
            }
            tableView.removeRows(
                at: transition.removals,
                withAnimation: removalAnimation
            )
        }
        if !transition.insertions.isEmpty {
            for index in transition.insertions {
                rows.insert(newRows[index], at: index)
                presentationRows.insert(newPresentationRows[index], at: index)
            }
            tableView.insertRows(
                at: transition.insertions,
                withAnimation: insertionAnimation
            )
        }
        rows = newRows
        presentationRows = newPresentationRows
        if !transition.removals.isEmpty || !transition.insertions.isEmpty {
            tableView.endUpdates()
        }

        if !transition.reloads.isEmpty {
            tableView.reloadData(
                forRowIndexes: transition.reloads,
                columnIndexes: IndexSet(integersIn: 0 ..< tableView.numberOfColumns)
            )
        }
    }

    func renderedTable() -> RenderedProcessTable {
        layoutSubtreeIfNeeded()
        tableView.layoutSubtreeIfNeeded()

        guard tableView.window != nil else {
            return incompleteRendering("table is not in a window", rows: [])
        }
        guard !tableView.isHidden else {
            return incompleteRendering("table is hidden", rows: [])
        }
        guard tableView.numberOfRows == presentationRows.count else {
            return incompleteRendering("table row count does not match the presentation", rows: [])
        }
        guard tableView.accessibilityIdentifier() == "who-sudod.process-tree.table",
              tableView.accessibilityLabel() == "Authentication process tree" else {
            return incompleteRendering("table accessibility metadata does not match", rows: [])
        }

        var renderedRows: [ProcessTablePresentationRow] = []
        for rowIndex in presentationRows.indices {
            let expected = presentationRows[rowIndex]
            let processIdentifier = cellIdentifier(row: rowIndex, column: "process")
            let pidIdentifier = cellIdentifier(row: rowIndex, column: "pid")
            let commandIdentifier = cellIdentifier(row: rowIndex, column: "command")
            let rowRect = tableView.rect(ofRow: rowIndex)
            guard !rowRect.isEmpty,
                  tableView.visibleRect.minY <= rowRect.minY,
                  tableView.visibleRect.maxY >= rowRect.maxY else {
                return incompleteRendering(
                    "row \(rowIndex) is outside the visible table height",
                    rows: renderedRows
                )
            }
            guard let rowView = tableView.rowView(
                    atRow: rowIndex,
                    makeIfNecessary: false
                  ) as? ProcessTableRowView,
                  let processCell = tableView.view(
                    atColumn: 0,
                    row: rowIndex,
                    makeIfNecessary: false
                  ) as? NSTableCellView else {
                return incompleteRendering(
                    "row \(rowIndex) does not have its rendered process view",
                    rows: renderedRows
                )
            }
            let pidCell: NSTableCellView?
            let commandCell: NSTableCellView?
            if displayMode == .fullTree {
                pidCell = tableView.view(
                    atColumn: 1,
                    row: rowIndex,
                    makeIfNecessary: false
                ) as? NSTableCellView
                commandCell = tableView.view(
                    atColumn: 2,
                    row: rowIndex,
                    makeIfNecessary: false
                ) as? NSTableCellView
                guard pidCell != nil, commandCell != nil else {
                    return incompleteRendering(
                        "row \(rowIndex) does not have all rendered views",
                        rows: renderedRows
                    )
                }
            } else {
                pidCell = nil
                commandCell = nil
            }
            guard let process = processCell.textField?.stringValue else {
                return incompleteRendering(
                    "row \(rowIndex) does not have a rendered process value",
                    rows: renderedRows
                )
            }
            let pid = pidCell?.textField?.stringValue ?? ""
            let command = commandCell?.textField?.stringValue ?? ""
            guard rowView.accessibilityIdentifier() == rowIdentifier(
                    row: rowIndex,
                    candidateIndex: expected.candidateIndex
                  ),
                  rowView.accessibilityDisclosureLevel() == expected.depth,
                  processCell.accessibilityIdentifier() == processIdentifier,
                  processCell.textField?.accessibilityIdentifier() == "\(processIdentifier).value" else {
                return incompleteRendering(
                    "row \(rowIndex) accessibility metadata does not match",
                    rows: renderedRows
                )
            }
            if displayMode == .fullTree,
               (pidCell?.accessibilityIdentifier() != pidIdentifier
                   || commandCell?.accessibilityIdentifier() != commandIdentifier
                   || pidCell?.textField?.accessibilityIdentifier() != "\(pidIdentifier).value"
                   || commandCell?.textField?.accessibilityIdentifier()
                        != "\(commandIdentifier).value") {
                return incompleteRendering(
                    "row \(rowIndex) detail accessibility metadata does not match",
                    rows: renderedRows
                )
            }
            renderedRows.append(
                ProcessTablePresentationRow(
                    candidateIndex: rowView.candidateIndex,
                    depth: rowView.treeDepth,
                    process: process,
                    pid: pid,
                    executableOrCommand: command
                )
            )
        }
#if DEBUG
        lastRenderingFailure = nil
#endif
        return RenderedProcessTable(isComplete: true, rows: renderedRows)
    }

    private func incompleteRendering(
        _ reason: String,
        rows: [ProcessTablePresentationRow]
    ) -> RenderedProcessTable {
#if DEBUG
        if lastRenderingFailure != reason {
            lastRenderingFailure = reason
            FileHandle.standardError.write(
                Data("Incomplete live table rendering: \(reason)\n".utf8)
            )
        }
#endif
        return RenderedProcessTable(isComplete: false, rows: rows)
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        rows.count
    }

    func tableView(_ tableView: NSTableView, shouldSelectRow row: Int) -> Bool {
        false
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        let rowIndex = tableView.clickedRow
        guard rows.indices.contains(rowIndex) else {
            return
        }
        let context = ProcessTableRowContextBuilder.context(for: rows[rowIndex])
        addMenuItem(
            title: "Reveal in Finder",
            action: #selector(revealInFinder(_:)),
            context: context,
            enabled: context.revealPath != nil,
            to: menu
        )
        menu.addItem(.separator())
        addMenuItem(
            title: "Copy PID",
            action: #selector(copyPID(_:)),
            context: context,
            enabled: context.pid != nil,
            to: menu
        )
        addMenuItem(
            title: "Copy Path",
            action: #selector(copyPath(_:)),
            context: context,
            enabled: context.executablePath != nil,
            to: menu
        )
    }

    func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
        let rowView = ProcessTableRowView()
        let item = rows[row]
        rowView.configure(
            candidateIndex: item.candidateIndex,
            depth: item.depth,
            accessibilityIdentifier: rowIdentifier(
                row: row,
                candidateIndex: item.candidateIndex
            )
        )
        return rowView
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let tableColumn else {
            return nil
        }
        let item = rows[row]
        let presentation = presentationRows[row]

        switch tableColumn.identifier {
        case Column.process:
            let cell = ProcessNameCell()
            if let process = item.process {
                cell.configure(
                    name: presentation.process,
                    icon: icon(for: process),
                    depth: item.depth,
                    startsCandidate: item.depth == 0 && item.candidateIndex > 0,
                    accessibilityIdentifier: cellIdentifier(row: row, column: "process")
                )
            } else {
                cell.configure(
                    name: presentation.process,
                    icon: requestedCommandIcon(item.requestedCommand),
                    depth: item.depth,
                    startsCandidate: false,
                    accessibilityIdentifier: cellIdentifier(row: row, column: "process")
                )
            }
            return cell
        case Column.pid:
            return textCell(
                presentation.pid,
                monospaced: true,
                accessibilityIdentifier: cellIdentifier(row: row, column: "pid")
            )
        case Column.path:
            return textCell(
                presentation.executableOrCommand,
                monospaced: true,
                accessibilityIdentifier: cellIdentifier(row: row, column: "command")
            )
        default:
            return nil
        }
    }

    private func configure() {
        translatesAutoresizingMaskIntoConstraints = false

        processColumn.title = "Process"
        processColumn.width = 190
        processColumn.minWidth = 150
        tableView.addTableColumn(processColumn)

        pidColumn.title = "PID"
        pidColumn.width = 64
        pidColumn.minWidth = 58
        pidColumn.maxWidth = 80
        tableView.addTableColumn(pidColumn)

        pathColumn.title = "Executable / command"
        pathColumn.width = 420
        pathColumn.minWidth = 240
        tableView.addTableColumn(pathColumn)

        tableView.delegate = self
        tableView.dataSource = self
        tableView.rowHeight = 30
        tableView.intercellSpacing = NSSize(width: 8, height: 1)
        tableView.backgroundColor = .clear
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.selectionHighlightStyle = .none
        tableView.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        rowMenu.delegate = self
        rowMenu.autoenablesItems = false
        tableView.menu = rowMenu
        tableView.setAccessibilityIdentifier("who-sudod.process-tree.table")
        tableView.setAccessibilityLabel("Authentication process tree")
        configureColumnVisibility()

        let scrollView = NSScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.drawsBackground = false
        addSubview(scrollView)

        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: bottomAnchor)
        ])
    }

    private func configureColumnVisibility() {
        let showsDetails = displayMode == .fullTree
        pidColumn.isHidden = !showsDetails
        pathColumn.isHidden = !showsDetails
        processColumn.resizingMask = showsDetails ? .userResizingMask : .autoresizingMask
        pathColumn.resizingMask = showsDetails ? .autoresizingMask : .userResizingMask
        if showsDetails {
            processColumn.width = 190
            pidColumn.width = 64
        }
        tableView.sizeLastColumnToFit()
    }

    private func addMenuItem(
        title: String,
        action: Selector,
        context: ProcessTableRowContext,
        enabled: Bool,
        to menu: NSMenu
    ) {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        item.representedObject = context
        item.isEnabled = enabled
        menu.addItem(item)
    }

    @objc
    private func revealInFinder(_ sender: NSMenuItem) {
        guard let context = sender.representedObject as? ProcessTableRowContext,
              let path = context.revealPath else {
            return
        }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    @objc
    private func copyPID(_ sender: NSMenuItem) {
        guard let context = sender.representedObject as? ProcessTableRowContext,
              let pid = context.pid else {
            return
        }
        copyToPasteboard(pid)
    }

    @objc
    private func copyPath(_ sender: NSMenuItem) {
        guard let context = sender.representedObject as? ProcessTableRowContext,
              let path = context.executablePath else {
            return
        }
        copyToPasteboard(path)
    }

    private func copyToPasteboard(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    private func textCell(
        _ text: String,
        monospaced: Bool,
        accessibilityIdentifier: String
    ) -> NSTableCellView {
        let cell = NSTableCellView()
        let safeText = DisplayTextSanitizer.sanitize(text)
        let label = NSTextField(labelWithString: safeText)
        label.translatesAutoresizingMaskIntoConstraints = false
        label.lineBreakMode = .byTruncatingMiddle
        label.maximumNumberOfLines = 1
        label.font = monospaced ? .monospacedSystemFont(ofSize: 11, weight: .regular) : .systemFont(ofSize: 12)
        label.toolTip = safeText
        label.setAccessibilityIdentifier("\(accessibilityIdentifier).value")
        cell.setAccessibilityIdentifier(accessibilityIdentifier)
        cell.setAccessibilityValue(safeText)
        cell.addSubview(label)
        cell.textField = label
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 4),
            label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),
            label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }

    private func cellIdentifier(row: Int, column: String) -> String {
        "who-sudod.process-tree.row.\(row).\(column)"
    }

    private func rowIdentifier(row: Int, candidateIndex: Int) -> String {
        "who-sudod.process-tree.candidate.\(candidateIndex).row.\(row)"
    }

    private func requestedCommandIcon(_ command: RequestedCommand?) -> NSImage {
        let icon: NSImage
        switch RequestedExecutableResolver.iconSource(executable: command?.executable) {
        case let .file(path):
            icon = NSWorkspace.shared.icon(
                forFile: ProcessTablePresentationBuilder.enclosingApplicationPath(for: path) ?? path
            )
        case .systemExecutable:
            icon = NSWorkspace.shared.icon(for: .unixExecutable)
        }
        icon.size = NSSize(width: 22, height: 22)
        return icon
    }

    private func icon(for process: ProcessRecord) -> NSImage {
        let cacheKey = process.executablePath ?? "pid:\(process.pid)"
        if let cached = iconCache[cacheKey] {
            return cached
        }

        let icon: NSImage
        if let runningIcon = NSRunningApplication(processIdentifier: process.pid)?.icon {
            icon = runningIcon
        } else if let path = process.executablePath {
            let appPath = ProcessTablePresentationBuilder.enclosingApplicationPath(for: path)
            icon = NSWorkspace.shared.icon(forFile: appPath ?? path)
        } else {
            icon = NSImage(systemSymbolName: "terminal", accessibilityDescription: nil) ?? NSImage()
        }
        icon.size = NSSize(width: 22, height: 22)
        iconCache[cacheKey] = icon
        return icon
    }
}

@MainActor
private final class ProcessTableRowView: NSTableRowView {
    private(set) var candidateIndex = 0
    private(set) var treeDepth = 0

    func configure(
        candidateIndex: Int,
        depth: Int,
        accessibilityIdentifier: String
    ) {
        self.candidateIndex = candidateIndex
        treeDepth = depth
        setAccessibilityIdentifier(accessibilityIdentifier)
        setAccessibilityDisclosureLevel(depth)
    }
}

@MainActor
private final class ProcessNameCell: NSTableCellView {
    private let iconView = NSImageView()
    private let nameLabel = NSTextField(labelWithString: "")
    private let separator = NSView()
    private var iconLeadingConstraint: NSLayoutConstraint?
    private var nameLeadingWithIconConstraint: NSLayoutConstraint?
    private var nameLeadingWithoutIconConstraint: NSLayoutConstraint?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)

        iconView.translatesAutoresizingMaskIntoConstraints = false
        iconView.imageScaling = .scaleProportionallyUpOrDown
        iconView.setAccessibilityElement(false)
        addSubview(iconView)
        imageView = iconView

        nameLabel.translatesAutoresizingMaskIntoConstraints = false
        nameLabel.lineBreakMode = .byTruncatingTail
        nameLabel.maximumNumberOfLines = 1
        addSubview(nameLabel)
        textField = nameLabel

        separator.translatesAutoresizingMaskIntoConstraints = false
        separator.wantsLayer = true
        separator.setAccessibilityElement(false)
        addSubview(separator)

        iconLeadingConstraint = iconView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4)
        iconLeadingConstraint?.isActive = true
        nameLeadingWithIconConstraint = nameLabel.leadingAnchor.constraint(
            equalTo: iconView.trailingAnchor,
            constant: 7
        )
        nameLeadingWithIconConstraint?.isActive = true
        nameLeadingWithoutIconConstraint = nameLabel.leadingAnchor.constraint(
            equalTo: leadingAnchor,
            constant: 4
        )
        NSLayoutConstraint.activate([
            iconView.widthAnchor.constraint(equalToConstant: 22),
            iconView.heightAnchor.constraint(equalToConstant: 22),
            iconView.centerYAnchor.constraint(equalTo: centerYAnchor),
            nameLabel.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            nameLabel.centerYAnchor.constraint(equalTo: centerYAnchor),
            separator.leadingAnchor.constraint(equalTo: leadingAnchor),
            separator.trailingAnchor.constraint(equalTo: trailingAnchor),
            separator.topAnchor.constraint(equalTo: topAnchor),
            separator.heightAnchor.constraint(equalToConstant: 1)
        ])
        updateAppearanceColors()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        updateAppearanceColors()
    }

    func configure(
        name: String,
        icon: NSImage?,
        depth: Int,
        startsCandidate: Bool,
        accessibilityIdentifier: String
    ) {
        nameLabel.stringValue = DisplayTextSanitizer.sanitize(name)
        nameLabel.setAccessibilityIdentifier("\(accessibilityIdentifier).value")
        setAccessibilityIdentifier(accessibilityIdentifier)
        setAccessibilityValue(nameLabel.stringValue)
        iconView.image = icon
        iconView.isHidden = icon == nil
        iconLeadingConstraint?.constant = 4 + CGFloat(depth) * 12
        nameLeadingWithoutIconConstraint?.constant = 4 + CGFloat(depth) * 12
        nameLeadingWithIconConstraint?.isActive = false
        nameLeadingWithoutIconConstraint?.isActive = false
        if icon == nil {
            nameLeadingWithoutIconConstraint?.isActive = true
        } else {
            nameLeadingWithIconConstraint?.isActive = true
        }
        separator.isHidden = !startsCandidate
    }

    private func updateAppearanceColors() {
        effectiveAppearance.performAsCurrentDrawingAppearance { [separator] in
            separator.layer?.backgroundColor = NSColor.separatorColor
                .withAlphaComponent(0.55)
                .cgColor
        }
    }
}

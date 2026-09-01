import AppKit

struct ProcessTableRow: Equatable {
    let process: ProcessRecord?
    let requestedCommand: String?
    let depth: Int
    let candidateIndex: Int
}

enum ProcessTableRowBuilder {
    static func rows(for snapshot: AuthenticationProcessSnapshot) -> [ProcessTableRow] {
        snapshot.candidates.enumerated().flatMap { candidateIndex, chain in
            let ancestry = chain.processes.enumerated().map { depth, process in
                ProcessTableRow(
                    process: process,
                    requestedCommand: nil,
                    depth: depth,
                    candidateIndex: candidateIndex
                )
            }
            let requesterDepth = max(0, chain.processes.count - 1)
            let descendants = chain.descendants.map { descendant in
                ProcessTableRow(
                    process: descendant.process,
                    requestedCommand: nil,
                    depth: requesterDepth + descendant.depthFromRequester,
                    candidateIndex: candidateIndex
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
                        candidateIndex: candidateIndex
                    )
                ]
            } else {
                command = []
            }
            return ancestry + command + descendants
        }
    }
}

@MainActor
final class ProcessTableView: NSView, NSTableViewDataSource, NSTableViewDelegate {
    private enum Column {
        static let process = NSUserInterfaceItemIdentifier("process")
        static let pid = NSUserInterfaceItemIdentifier("pid")
        static let path = NSUserInterfaceItemIdentifier("path")
    }

    private let tableView = NSTableView()
    private var rows: [ProcessTableRow] = []
    private var iconCache: [String: NSImage] = [:]

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        configure()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func update(snapshot: AuthenticationProcessSnapshot) {
        rows = ProcessTableRowBuilder.rows(for: snapshot)
        tableView.reloadData()
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        rows.count
    }

    func tableView(_ tableView: NSTableView, shouldSelectRow row: Int) -> Bool {
        false
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let tableColumn else {
            return nil
        }
        let item = rows[row]

        switch tableColumn.identifier {
        case Column.process:
            let cell = ProcessNameCell()
            if let process = item.process {
                cell.configure(
                    name: displayName(for: process),
                    icon: icon(for: process),
                    depth: item.depth,
                    startsCandidate: item.depth == 0 && item.candidateIndex > 0
                )
            } else {
                cell.configure(
                    name: requestedCommandName(item.requestedCommand),
                    icon: requestedCommandIcon(item.requestedCommand),
                    depth: item.depth,
                    startsCandidate: false
                )
            }
            return cell
        case Column.pid:
            return textCell(item.process.map { String($0.pid) } ?? "—", monospaced: true)
        case Column.path:
            return textCell(pathText(for: item), monospaced: true)
        default:
            return nil
        }
    }

    private func configure() {
        translatesAutoresizingMaskIntoConstraints = false

        let processColumn = NSTableColumn(identifier: Column.process)
        processColumn.title = "Process"
        processColumn.width = 190
        processColumn.minWidth = 150
        tableView.addTableColumn(processColumn)

        let pidColumn = NSTableColumn(identifier: Column.pid)
        pidColumn.title = "PID"
        pidColumn.width = 64
        pidColumn.minWidth = 58
        pidColumn.maxWidth = 80
        tableView.addTableColumn(pidColumn)

        let pathColumn = NSTableColumn(identifier: Column.path)
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

    private func textCell(_ text: String, monospaced: Bool) -> NSTableCellView {
        let cell = NSTableCellView()
        let safeText = DisplayTextSanitizer.sanitize(text)
        let label = NSTextField(labelWithString: safeText)
        label.translatesAutoresizingMaskIntoConstraints = false
        label.lineBreakMode = .byTruncatingMiddle
        label.maximumNumberOfLines = 1
        label.font = monospaced ? .monospacedSystemFont(ofSize: 11, weight: .regular) : .systemFont(ofSize: 12)
        label.toolTip = safeText
        cell.addSubview(label)
        cell.textField = label
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 4),
            label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -4),
            label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
        ])
        return cell
    }

    private func pathText(for row: ProcessTableRow) -> String {
        if let process = row.process {
            return process.executablePath ?? "Path unavailable"
        }
        return row.requestedCommand ?? "Command unavailable"
    }

    private func requestedCommandName(_ command: String?) -> String {
        guard let firstWord = command?.split(whereSeparator: { $0.isWhitespace }).first else {
            return "Command"
        }
        let executable = String(firstWord)
        if executable.hasPrefix("/"),
           let appPath = enclosingApplicationPath(for: executable),
           let appName = applicationName(at: appPath) {
            return appName
        }
        let name = URL(fileURLWithPath: executable).lastPathComponent
        return name.isEmpty ? "Command" : name
    }

    private func requestedCommandIcon(_ command: String?) -> NSImage {
        if let path = requestedExecutablePath(command) {
            let icon = NSWorkspace.shared.icon(
                forFile: enclosingApplicationPath(for: path) ?? path
            )
            icon.size = NSSize(width: 22, height: 22)
            return icon
        }
        let icon = NSImage(systemSymbolName: "terminal", accessibilityDescription: "Command")
            ?? NSImage()
        icon.size = NSSize(width: 22, height: 22)
        return icon
    }

    private func requestedExecutablePath(_ command: String?) -> String? {
        guard let firstWord = command?.split(whereSeparator: { $0.isWhitespace }).first else {
            return nil
        }
        let path = String(firstWord)
        guard path.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: path) else {
            return nil
        }
        return path
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
            let appPath = enclosingApplicationPath(for: path)
            icon = NSWorkspace.shared.icon(forFile: appPath ?? path)
        } else {
            icon = NSImage(systemSymbolName: "terminal", accessibilityDescription: nil) ?? NSImage()
        }
        icon.size = NSSize(width: 22, height: 22)
        iconCache[cacheKey] = icon
        return icon
    }

    private func displayName(for process: ProcessRecord) -> String {
        guard let path = process.executablePath,
              let appPath = enclosingApplicationPath(for: path),
              let appName = applicationName(at: appPath) else {
            return process.name
        }
        return appName
    }

    private func applicationName(at appPath: String) -> String? {
        guard let bundle = Bundle(url: URL(fileURLWithPath: appPath)) else {
            return nil
        }
        return (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
            ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
    }

    private func enclosingApplicationPath(for executablePath: String) -> String? {
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
}

@MainActor
private final class ProcessNameCell: NSTableCellView {
    private let iconView = NSImageView()
    private let nameLabel = NSTextField(labelWithString: "")
    private let separator = NSView()
    private var leadingConstraint: NSLayoutConstraint?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)

        iconView.translatesAutoresizingMaskIntoConstraints = false
        iconView.imageScaling = .scaleProportionallyUpOrDown
        addSubview(iconView)
        imageView = iconView

        nameLabel.translatesAutoresizingMaskIntoConstraints = false
        nameLabel.lineBreakMode = .byTruncatingTail
        nameLabel.maximumNumberOfLines = 1
        addSubview(nameLabel)
        textField = nameLabel

        separator.translatesAutoresizingMaskIntoConstraints = false
        separator.wantsLayer = true
        separator.layer?.backgroundColor = NSColor.separatorColor.withAlphaComponent(0.55).cgColor
        addSubview(separator)

        leadingConstraint = iconView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 4)
        leadingConstraint?.isActive = true
        NSLayoutConstraint.activate([
            iconView.widthAnchor.constraint(equalToConstant: 22),
            iconView.heightAnchor.constraint(equalToConstant: 22),
            iconView.centerYAnchor.constraint(equalTo: centerYAnchor),
            nameLabel.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 7),
            nameLabel.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -4),
            nameLabel.centerYAnchor.constraint(equalTo: centerYAnchor),
            separator.leadingAnchor.constraint(equalTo: leadingAnchor),
            separator.trailingAnchor.constraint(equalTo: trailingAnchor),
            separator.topAnchor.constraint(equalTo: topAnchor),
            separator.heightAnchor.constraint(equalToConstant: 1)
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func configure(name: String, icon: NSImage, depth: Int, startsCandidate: Bool) {
        let safeName = DisplayTextSanitizer.sanitize(name)
        nameLabel.stringValue = depth == 0 ? safeName : "└ \(safeName)"
        iconView.image = icon
        leadingConstraint?.constant = 4 + CGFloat(depth) * 12
        separator.isHidden = !startsCandidate
    }
}

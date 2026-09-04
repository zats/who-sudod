import AppKit
import Darwin
import XCTest
@testable import WhoSudod

final class ProcessTableRowBuilderTests: XCTestCase {
    func testValidationOnlySudoHasNoCommandRow() throws {
        let snapshot = sudoSnapshot(processArguments: ["sudo", "-v"])

        let rows = ProcessTableRowBuilder.rows(for: snapshot)

        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(try XCTUnwrap(rows.first).process?.name, "sudo")
        XCTAssertNil(rows.first?.requestedCommand)
    }

    func testSudoCommandHasPendingCommandRow() throws {
        let snapshot = sudoSnapshot(
            processArguments: ["sudo", "-k", "/bin/echo", "who-sudod-child-check"]
        )

        let rows = ProcessTableRowBuilder.rows(for: snapshot)

        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows[0].process?.name, "sudo")
        XCTAssertNil(rows[1].process)
        XCTAssertEqual(
            rows[1].requestedCommand,
            RequestedCommand(executable: "/bin/echo", arguments: ["who-sudod-child-check"])
        )
        XCTAssertEqual(rows[1].depth, 1)
    }

    func testRowTransitionAnimatesAnInsertedDescendant() throws {
        let requester = process(
            pid: 300,
            parentPID: 200,
            name: "sudo",
            path: "/usr/bin/sudo"
        )
        let child = process(
            pid: 301,
            parentPID: 300,
            name: "echo",
            path: "/bin/echo"
        )
        let oldRows = [
            row(process: requester, depth: 0, requester: requester)
        ]
        let newRows = oldRows + [
            row(process: child, depth: 1, requester: requester)
        ]

        let transition = try XCTUnwrap(
            ProcessTableRowTransition(from: oldRows, to: newRows)
        )

        XCTAssertEqual(transition.removals, IndexSet())
        XCTAssertEqual(transition.insertions, IndexSet(integer: 1))
        XCTAssertEqual(transition.reloads, IndexSet())
    }

    func testRowTransitionReplacesPendingCommandWithLiveChild() throws {
        let requester = process(
            pid: 300,
            parentPID: 200,
            name: "sudo",
            path: "/usr/bin/sudo"
        )
        let child = process(
            pid: 301,
            parentPID: 300,
            name: "echo",
            path: "/bin/echo"
        )
        let command = RequestedCommand(executable: "/bin/echo", arguments: ["hello"])
        let oldRows = [
            row(process: requester, depth: 0, requester: requester),
            row(command: command, depth: 1, requester: requester)
        ]
        let newRows = [
            row(process: requester, depth: 0, requester: requester),
            row(process: child, depth: 1, requester: requester)
        ]

        let transition = try XCTUnwrap(
            ProcessTableRowTransition(from: oldRows, to: newRows)
        )

        XCTAssertEqual(transition.removals, IndexSet(integer: 1))
        XCTAssertEqual(transition.insertions, IndexSet(integer: 1))
        XCTAssertEqual(transition.reloads, IndexSet())
    }

    func testRowTransitionReloadsRetainedRowsAfterLeadingInsertion() throws {
        let requester = process(
            pid: 300,
            parentPID: 1,
            name: "sudo",
            path: "/usr/bin/sudo"
        )
        let launchd = process(
            pid: 1,
            parentPID: 0,
            name: "launchd",
            path: "/sbin/launchd"
        )
        let command = RequestedCommand(executable: "/bin/echo", arguments: [])
        let oldRows = [
            row(process: requester, depth: 0, requester: requester),
            row(command: command, depth: 1, requester: requester)
        ]
        let newRows = [
            row(process: launchd, depth: 0, requester: requester),
            row(process: requester, depth: 1, requester: requester),
            row(command: command, depth: 2, requester: requester)
        ]

        let transition = try XCTUnwrap(
            ProcessTableRowTransition(from: oldRows, to: newRows)
        )

        XCTAssertEqual(transition.removals, IndexSet())
        XCTAssertEqual(transition.insertions, IndexSet(integer: 0))
        XCTAssertEqual(transition.reloads, IndexSet(integersIn: 1 ..< 3))
    }

    func testRowTransitionRejectsRetainedRowReorderingAndDuplicateIdentity() {
        let requester = process(
            pid: 300,
            parentPID: 200,
            name: "sudo",
            path: "/usr/bin/sudo"
        )
        let parent = process(
            pid: 200,
            parentPID: 1,
            name: "shell",
            path: "/bin/zsh"
        )
        let first = row(process: parent, depth: 0, requester: requester)
        let second = row(process: requester, depth: 1, requester: requester)

        XCTAssertNil(ProcessTableRowTransition(from: [first, second], to: [second, first]))
        XCTAssertNil(ProcessTableRowTransition(from: [first, first], to: [first]))
    }

    func testPromptAnimationPolicyUsesOnlyTheSameVisiblePrompt() {
        XCTAssertFalse(
            ProcessTableAnimationPolicy.animatesContentChange(
                panelIsPresented: false,
                currentPromptSequence: 1,
                nextPromptSequence: 1
            )
        )
        XCTAssertTrue(
            ProcessTableAnimationPolicy.animatesContentChange(
                panelIsPresented: true,
                currentPromptSequence: 1,
                nextPromptSequence: 1
            )
        )
        XCTAssertFalse(
            ProcessTableAnimationPolicy.animatesContentChange(
                panelIsPresented: true,
                currentPromptSequence: 1,
                nextPromptSequence: 2
            )
        )
    }

    @MainActor
    func testVisibleSamePromptUpdateUsesNativeRowInsertion() {
        let requester = process(
            pid: 300,
            parentPID: 0,
            name: "sudo",
            path: "/usr/bin/sudo"
        )
        let child = process(
            pid: 301,
            parentPID: 300,
            name: "echo",
            path: "/bin/echo"
        )
        let initial = snapshot(
            records: [requester],
            requester: requester,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )
        let updated = snapshot(
            records: [requester, child],
            requester: requester,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )
        let recordingTable = RecordingTableView()
        let table = ProcessTableView(
            frame: NSRect(x: 0, y: 0, width: 760, height: 240),
            tableView: recordingTable,
            displayMode: .fullTree,
            animationVisibilityOverride: true
        )

        table.update(snapshot: initial, animated: false)
        recordingTable.resetRecordedUpdates()

        table.update(snapshot: updated, animated: true)

        XCTAssertEqual(recordingTable.reloadDataCallCount, 0)
        XCTAssertEqual(recordingTable.insertedRows, [IndexSet(integer: 1)])
        XCTAssertTrue(recordingTable.removedRows.isEmpty)
        XCTAssertEqual(table.presentationRows.map(\.process), ["sudo", "echo"])
    }

    @MainActor
    func testVisibleNewPromptUpdateReloadsImmediately() {
        let firstRequester = process(
            pid: 300,
            parentPID: 0,
            name: "sudo",
            path: "/usr/bin/sudo"
        )
        let secondRequester = process(
            pid: 400,
            parentPID: 0,
            name: "security",
            path: "/usr/bin/security"
        )
        let first = snapshot(
            records: [firstRequester],
            requester: firstRequester,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )
        let second = snapshot(
            records: [secondRequester],
            requester: secondRequester,
            requestKind: .authorization,
            attribution: .authorizationLog
        )
        let recordingTable = RecordingTableView()
        let table = ProcessTableView(
            frame: NSRect(x: 0, y: 0, width: 760, height: 240),
            tableView: recordingTable,
            displayMode: .fullTree,
            animationVisibilityOverride: true
        )

        table.update(snapshot: first, animated: false)
        recordingTable.resetRecordedUpdates()

        table.update(snapshot: second, animated: false)

        XCTAssertEqual(recordingTable.reloadDataCallCount, 1)
        XCTAssertTrue(recordingTable.insertedRows.isEmpty)
        XCTAssertTrue(recordingTable.removedRows.isEmpty)
        XCTAssertEqual(table.presentationRows.map(\.process), ["security"])
    }

    func testPresentationRowsMatchVisibleTableStrings() {
        let snapshot = sudoSnapshot(
            processArguments: ["sudo", "-k", "/bin/echo", "who-sudod-child-check"]
        )

        XCTAssertEqual(
            ProcessTablePresentationBuilder.rows(for: snapshot, mode: .fullTree),
            [
                ProcessTablePresentationRow(
                    candidateIndex: 0,
                    depth: 0,
                    process: "sudo",
                    pid: "300",
                    executableOrCommand: "/usr/bin/sudo"
                ),
                ProcessTablePresentationRow(
                    candidateIndex: 0,
                    depth: 1,
                    process: "echo",
                    pid: "—",
                    executableOrCommand: "/bin/echo who-sudod-child-check"
                )
            ]
        )
    }

    func testRequestedExecutableResolverUsesTheRealAbsoluteBinary() {
        XCTAssertEqual(
            RequestedExecutableResolver.iconSource(executable: "/bin/echo"),
            .file(URL(fileURLWithPath: "/bin/echo").resolvingSymlinksInPath().path)
        )
    }

    func testRequestedExecutableResolverUsesSystemExecutableForUnresolvedCommands() {
        XCTAssertEqual(
            RequestedExecutableResolver.iconSource(executable: "ls"),
            .systemExecutable
        )
        XCTAssertEqual(
            RequestedExecutableResolver.iconSource(executable: "/not/a/real/binary"),
            .systemExecutable
        )
        XCTAssertEqual(
            RequestedExecutableResolver.iconSource(executable: nil),
            .systemExecutable
        )
    }

    func testRequestedAppWithSpacesUsesItsBundleNameAndExactExecutable() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "who-sudod-requested-app-\(UUID().uuidString)",
            isDirectory: true
        )
        let bundleURL = root.appendingPathComponent("Example App.app", isDirectory: true)
        let contentsURL = bundleURL.appendingPathComponent("Contents", isDirectory: true)
        let executableDirectory = contentsURL.appendingPathComponent("MacOS", isDirectory: true)
        let executableURL = executableDirectory.appendingPathComponent("Example Tool")
        try FileManager.default.createDirectory(
            at: executableDirectory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let propertyList: [String: Any] = [
            "CFBundleDisplayName": "Example Display",
            "CFBundleExecutable": "Example Tool",
            "CFBundleIdentifier": "com.zats.WhoSudodRequestedAppFixture",
            "CFBundlePackageType": "APPL"
        ]
        let propertyListData = try PropertyListSerialization.data(
            fromPropertyList: propertyList,
            format: .xml,
            options: 0
        )
        try propertyListData.write(to: contentsURL.appendingPathComponent("Info.plist"))
        try Data("#!/bin/sh\n".utf8).write(to: executableURL)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: executableURL.path
        )

        let snapshot = sudoSnapshot(
            processArguments: ["sudo", executableURL.path, "argument with spaces"]
        )
        let commandRow = try XCTUnwrap(
            ProcessTablePresentationBuilder.rows(for: snapshot, mode: .fullTree).last
        )

        XCTAssertEqual(commandRow.process, "Example Display")
        XCTAssertEqual(
            commandRow.executableOrCommand,
            "'\(executableURL.path)' 'argument with spaces'"
        )
        XCTAssertEqual(
            RequestedExecutableResolver.iconSource(executable: executableURL.path),
            .file(bundleURL.path)
        )
    }

    func testRequestedAppWithSymlinkedExecutableUsesItsBundleIcon() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "who-sudod-requested-symlink-app-\(UUID().uuidString)",
            isDirectory: true
        )
        let bundleURL = root.appendingPathComponent("Symlink App.app", isDirectory: true)
        let contentsURL = bundleURL.appendingPathComponent("Contents", isDirectory: true)
        let executableDirectory = contentsURL.appendingPathComponent("MacOS", isDirectory: true)
        let executableURL = executableDirectory.appendingPathComponent("Symlink Tool")
        try FileManager.default.createDirectory(
            at: executableDirectory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let propertyList: [String: Any] = [
            "CFBundleDisplayName": "Symlink Display",
            "CFBundleExecutable": "Symlink Tool",
            "CFBundleIdentifier": "com.zats.WhoSudodRequestedSymlinkAppFixture",
            "CFBundlePackageType": "APPL"
        ]
        let propertyListData = try PropertyListSerialization.data(
            fromPropertyList: propertyList,
            format: .xml,
            options: 0
        )
        try propertyListData.write(to: contentsURL.appendingPathComponent("Info.plist"))
        try FileManager.default.createSymbolicLink(
            at: executableURL,
            withDestinationURL: URL(fileURLWithPath: "/bin/echo")
        )

        XCTAssertEqual(
            RequestedExecutableResolver.iconSource(executable: executableURL.path),
            .file(bundleURL.path)
        )
    }

    func testSimpleModeKeepsEntireTreeAndRequestedCommand() throws {
        let fixture = try applicationFixture(name: "Caller App")
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let launchd = process(pid: 1, parentPID: 0, name: "launchd", path: "/sbin/launchd")
        let app = process(
            pid: 100,
            parentPID: 1,
            name: "Caller",
            path: fixture.executable.path
        )
        let helper = process(pid: 200, parentPID: 100, name: "helper", path: "/bin/sh")
        let sudo = process(
            pid: 300,
            parentPID: 200,
            name: "sudo",
            path: "/usr/bin/sudo",
            arguments: ["sudo", "/bin/echo", "hello"]
        )
        let snapshot = snapshot(
            records: [launchd, app, helper, sudo],
            requester: sudo,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )

        let rows = ProcessTableRowBuilder.rows(for: snapshot)

        XCTAssertEqual(rows.compactMap(\.process?.pid), [1, 100, 200, 300])
        XCTAssertEqual(rows.map(\.depth), [0, 1, 2, 3, 4])
        XCTAssertEqual(rows.last?.requestedCommand?.executable, "/bin/echo")
        XCTAssertEqual(
            ProcessTablePresentationBuilder.rows(for: rows, mode: .simple).map(\.process),
            ["launchd", "Caller App", "helper", "sudo", "echo"]
        )
    }

    func testSimpleModeKeepsAllApplicationAncestors() throws {
        let outer = try applicationFixture(name: "Outer App")
        let inner = try applicationFixture(name: "Inner App")
        defer {
            try? FileManager.default.removeItem(at: outer.root)
            try? FileManager.default.removeItem(at: inner.root)
        }
        let launchd = process(pid: 1, parentPID: 0, name: "launchd", path: "/sbin/launchd")
        let outerApp = process(
            pid: 100,
            parentPID: 1,
            name: "outer",
            path: outer.executable.path
        )
        let innerApp = process(
            pid: 200,
            parentPID: 100,
            name: "inner",
            path: inner.executable.path
        )
        let sudo = process(
            pid: 300,
            parentPID: 200,
            name: "sudo",
            path: "/usr/bin/sudo",
            arguments: ["sudo", "/bin/echo"]
        )
        let snapshot = snapshot(
            records: [launchd, outerApp, innerApp, sudo],
            requester: sudo,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )

        let rows = ProcessTableRowBuilder.rows(for: snapshot)

        XCTAssertEqual(rows.compactMap(\.process?.pid), [1, 100, 200, 300])
        XCTAssertEqual(rows.map(\.depth), [0, 1, 2, 3, 4])
    }

    func testSimpleModeKeepsLeadingPIDOne() {
        let launchd = process(pid: 1, parentPID: 0, name: "launchd", path: "/sbin/launchd")
        let shell = process(pid: 200, parentPID: 1, name: "zsh", path: "/bin/zsh")
        let sudo = process(
            pid: 300,
            parentPID: 200,
            name: "sudo",
            path: "/usr/bin/sudo",
            arguments: ["sudo", "/bin/echo"]
        )
        let snapshot = snapshot(
            records: [launchd, shell, sudo],
            requester: sudo,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )

        let rows = ProcessTableRowBuilder.rows(for: snapshot)

        XCTAssertEqual(rows.compactMap(\.process?.pid), [1, 200, 300])
        XCTAssertEqual(rows.map(\.depth), [0, 1, 2, 3])
    }

    func testSimpleModeKeepsIncompleteAncestryThatDoesNotStartAtPIDOne() {
        let shell = process(pid: 200, parentPID: 99, name: "zsh", path: "/bin/zsh")
        let sudo = process(
            pid: 300,
            parentPID: 200,
            name: "sudo",
            path: "/usr/bin/sudo",
            arguments: ["sudo", "/bin/echo"]
        )
        let snapshot = snapshot(
            records: [shell, sudo],
            requester: sudo,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )

        let rows = ProcessTableRowBuilder.rows(for: snapshot)

        XCTAssertEqual(rows.compactMap(\.process?.pid), [200, 300])
        XCTAssertEqual(rows.map(\.depth), [0, 1, 2])
    }

    func testSimpleModeKeepsAncestryRegardlessOfBundleResolution() {
        let launchd = process(pid: 1, parentPID: 0, name: "launchd", path: "/sbin/launchd")
        let shell = process(pid: 100, parentPID: 1, name: "zsh", path: "/bin/zsh")
        let falseApp = process(
            pid: 200,
            parentPID: 100,
            name: "helper",
            path: "/tmp/Not-A-Bundle.app/Contents/MacOS/helper"
        )
        let sudo = process(
            pid: 300,
            parentPID: 200,
            name: "sudo",
            path: "/usr/bin/sudo",
            arguments: ["sudo", "/bin/echo"]
        )
        let snapshot = snapshot(
            records: [launchd, shell, falseApp, sudo],
            requester: sudo,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )

        let rows = ProcessTableRowBuilder.rows(for: snapshot)

        XCTAssertEqual(rows.compactMap(\.process?.pid), [1, 100, 200, 300])
        XCTAssertEqual(rows.map(\.depth), [0, 1, 2, 3, 4])
    }

    func testSimpleModePreservesEachCandidateTree() throws {
        let fixture = try applicationFixture(name: "Caller App")
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let launchd = process(pid: 1, parentPID: 0, name: "launchd", path: "/sbin/launchd")
        let app = process(pid: 100, parentPID: 1, name: "Caller", path: fixture.executable.path)
        let firstRequester = process(pid: 300, parentPID: 100, name: "first", path: "/bin/sh")
        let shell = process(pid: 400, parentPID: 1, name: "zsh", path: "/bin/zsh")
        let secondRequester = process(pid: 500, parentPID: 400, name: "second", path: "/bin/sh")
        let snapshot = AuthenticationProcessSnapshot(
            candidates: [
                ProcessChain(
                    processes: [launchd, app, firstRequester],
                    descendants: [],
                    isComplete: true,
                    requestKind: .authorization,
                    attribution: .authorizationLog
                ),
                ProcessChain(
                    processes: [launchd, shell, secondRequester],
                    descendants: [],
                    isComplete: true,
                    requestKind: .authorization,
                    attribution: .authorizationLog
                )
            ]
        )

        let rows = ProcessTableRowBuilder.rows(for: snapshot)

        XCTAssertEqual(
            rows.map { "\($0.candidateIndex):\($0.process?.pid ?? -1):\($0.depth)" },
            ["0:1:0", "0:100:1", "0:300:2", "1:1:0", "1:400:1", "1:500:2"]
        )
    }

    func testSimpleModeRetainsPIDOneWhenItIsTheOnlyProcess() {
        let launchd = process(pid: 1, parentPID: 0, name: "launchd", path: "/sbin/launchd")
        let snapshot = snapshot(
            records: [launchd],
            requester: launchd,
            requestKind: .authorization,
            attribution: .authorizationLog
        )

        XCTAssertEqual(
            ProcessTableRowBuilder.rows(for: snapshot).compactMap(\.process?.pid),
            [1]
        )
    }

    func testSimpleModeKeepsObservedDescendants() throws {
        let fixture = try applicationFixture(name: "Requester App")
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let app = process(
            pid: 100,
            parentPID: 1,
            name: "Requester",
            path: fixture.executable.path
        )
        let sudo = process(
            pid: 300,
            parentPID: 100,
            name: "sudo",
            path: "/usr/bin/sudo",
            arguments: ["sudo", "/bin/echo"]
        )
        let child = process(pid: 400, parentPID: 300, name: "echo", path: "/bin/echo")
        let snapshot = snapshot(
            records: [app, sudo, child],
            requester: sudo,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )

        let rows = ProcessTableRowBuilder.rows(for: snapshot)

        XCTAssertEqual(rows.compactMap(\.process?.pid), [100, 300, 400])
        XCTAssertTrue(rows.allSatisfy { $0.requestedCommand == nil })
        XCTAssertEqual(rows.map(\.depth), [0, 1, 2])
    }

    func testSimplePresentationHidesDetailValuesWithoutLosingRowContext() {
        let sudo = process(
            pid: 300,
            parentPID: 0,
            name: "sudo",
            path: "/usr/bin/sudo",
            arguments: ["sudo", "/bin/echo", "hello"]
        )
        let snapshot = snapshot(
            records: [sudo],
            requester: sudo,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )
        let rows = ProcessTableRowBuilder.rows(for: snapshot)
        let presentation = ProcessTablePresentationBuilder.rows(for: rows, mode: .simple)

        XCTAssertEqual(presentation.map(\.process), ["sudo", "echo"])
        XCTAssertEqual(presentation.map(\.pid), ["", ""])
        XCTAssertEqual(presentation.map(\.executableOrCommand), ["", ""])
        XCTAssertEqual(ProcessTableRowContextBuilder.context(for: rows[0]).pid, "300")
        XCTAssertEqual(
            ProcessTableRowContextBuilder.context(for: rows[0]).executablePath,
            "/usr/bin/sudo"
        )
        XCTAssertEqual(
            ProcessTableRowContextBuilder.context(for: rows[1]).executablePath,
            "/bin/echo"
        )
    }

    func testRowContextUsesOnlyHonestAvailableValues() {
        let processWithoutPath = process(
            pid: 300,
            parentPID: 0,
            name: "requester",
            path: nil
        )
        let missingProcessPath = process(
            pid: 301,
            parentPID: 0,
            name: "missing",
            path: "/not/a/live/file"
        )
        let relativeCommand = ProcessTableRow(
            process: nil,
            requestedCommand: RequestedCommand(executable: "ls", arguments: ["-l"]),
            depth: 0,
            candidateIndex: 0
        )

        XCTAssertEqual(
            ProcessTableRowContextBuilder.context(
                for: ProcessTableRow(
                    process: processWithoutPath,
                    requestedCommand: nil,
                    depth: 0,
                    candidateIndex: 0
                )
            ),
            ProcessTableRowContext(pid: "300", executablePath: nil, revealPath: nil)
        )
        XCTAssertEqual(
            ProcessTableRowContextBuilder.context(
                for: ProcessTableRow(
                    process: missingProcessPath,
                    requestedCommand: nil,
                    depth: 0,
                    candidateIndex: 0
                ),
                fileExists: { _ in false }
            ),
            ProcessTableRowContext(
                pid: "301",
                executablePath: "/not/a/live/file",
                revealPath: nil
            )
        )
        XCTAssertEqual(
            ProcessTableRowContextBuilder.context(for: relativeCommand),
            ProcessTableRowContext(pid: nil, executablePath: nil, revealPath: nil)
        )
    }

    func testRowContextRevealsApplicationBundleButCopiesExecutablePath() throws {
        let fixture = try applicationFixture(name: "Reveal App")
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let app = process(
            pid: 100,
            parentPID: 1,
            name: "Reveal",
            path: fixture.executable.path
        )
        let context = ProcessTableRowContextBuilder.context(
            for: ProcessTableRow(
                process: app,
                requestedCommand: nil,
                depth: 0,
                candidateIndex: 0
            )
        )

        XCTAssertEqual(context.pid, "100")
        XCTAssertEqual(context.executablePath, fixture.executable.path)
        XCTAssertEqual(context.revealPath, fixture.bundle.path)
    }

    @MainActor
    func testRowMenuUsesTheClickedRowAndDisablesUnavailableActions() throws {
        let snapshot = sudoSnapshot(
            processArguments: ["sudo", "--", "/bin/echo", "hello"]
        )
        let backingTable = ClickedRowTableView()
        let table = ProcessTableView(
            frame: NSRect(x: 0, y: 0, width: 760, height: 240),
            tableView: backingTable,
            displayMode: .simple
        )
        table.update(snapshot: snapshot)
        let menu = try XCTUnwrap(backingTable.menu)

        backingTable.testClickedRow = 0
        table.menuNeedsUpdate(menu)
        XCTAssertEqual(
            menu.items.filter { !$0.isSeparatorItem }.map(\.title),
            ["Reveal in Finder", "Copy PID", "Copy Path"]
        )
        XCTAssertTrue(try XCTUnwrap(menu.item(withTitle: "Copy PID")).isEnabled)
        XCTAssertEqual(
            try XCTUnwrap(
                menu.item(withTitle: "Copy PID")?.representedObject as? ProcessTableRowContext
            ).pid,
            "300"
        )

        backingTable.testClickedRow = 1
        table.menuNeedsUpdate(menu)
        XCTAssertFalse(try XCTUnwrap(menu.item(withTitle: "Copy PID")).isEnabled)
        XCTAssertTrue(try XCTUnwrap(menu.item(withTitle: "Copy Path")).isEnabled)
        XCTAssertEqual(
            try XCTUnwrap(
                menu.item(withTitle: "Copy Path")?.representedObject as? ProcessTableRowContext
            ).executablePath,
            "/bin/echo"
        )

        backingTable.testClickedRow = -1
        table.menuNeedsUpdate(menu)
        XCTAssertTrue(menu.items.isEmpty)
    }

    func testDisplayModeUsesSimpleByDefaultAndHonorsSavedAndForcedValues() throws {
        let suiteName = "WhoSudodTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        XCTAssertEqual(ProcessDisplayMode.initial(environment: [:], defaults: defaults), .simple)
        defaults.set(ProcessDisplayMode.fullTree.rawValue, forKey: ProcessDisplayMode.defaultsKey)
        XCTAssertEqual(ProcessDisplayMode.initial(environment: [:], defaults: defaults), .fullTree)
        XCTAssertEqual(
            ProcessDisplayMode.initial(
                environment: [ProcessDisplayMode.environmentKey: "simple"],
                defaults: defaults
            ),
            .simple
        )
    }

    @MainActor
    func testChangingDisplayModeReusesSnapshotAndChangesVisibleColumns() {
        let launchd = process(
            pid: 1,
            parentPID: 0,
            name: "launchd",
            path: "/sbin/launchd"
        )
        let shell = process(
            pid: 200,
            parentPID: 1,
            name: "zsh",
            path: "/bin/zsh"
        )
        let sudo = process(
            pid: 300,
            parentPID: 200,
            name: "sudo",
            path: "/usr/bin/sudo",
            arguments: ["sudo", "-k", "/bin/echo", "who-sudod-child-check"]
        )
        let snapshot = snapshot(
            records: [launchd, shell, sudo],
            requester: sudo,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )
        let table = ProcessTableView(
            frame: NSRect(x: 0, y: 0, width: 760, height: 240),
            displayMode: .simple
        )
        table.translatesAutoresizingMaskIntoConstraints = true
        let window = NSWindow(
            contentRect: table.frame,
            styleMask: .borderless,
            backing: .buffered,
            defer: false
        )
        window.contentView = table
        table.update(snapshot: snapshot)
        window.layoutIfNeeded()
        window.displayIfNeeded()

        XCTAssertEqual(table.visibleColumnIdentifiers.map(\.rawValue), ["process"])
        let simpleRows = table.renderedTable().rows
        XCTAssertEqual(
            simpleRows,
            ProcessTablePresentationBuilder.rows(for: snapshot, mode: .simple)
        )
        let simpleIconOffsets = processIconOffsets(in: table)
        XCTAssertEqual(simpleIconOffsets.count, simpleRows.count)
        for offset in simpleIconOffsets {
            XCTAssertEqual(offset, 4, accuracy: 0.5)
        }
        let simpleCellIdentities = processCellIdentities(in: table)

        table.setDisplayMode(.fullTree)
        window.layoutIfNeeded()
        window.displayIfNeeded()

        XCTAssertEqual(
            table.visibleColumnIdentifiers.map(\.rawValue),
            ["process", "pid", "path"]
        )
        let fullTreeRows = table.renderedTable().rows
        XCTAssertEqual(
            fullTreeRows,
            ProcessTablePresentationBuilder.rows(for: snapshot, mode: .fullTree)
        )
        XCTAssertEqual(simpleRows.map(\.process), fullTreeRows.map(\.process))
        XCTAssertEqual(simpleRows.map(\.depth), fullTreeRows.map(\.depth))
        XCTAssertEqual(simpleRows.map(\.candidateIndex), fullTreeRows.map(\.candidateIndex))
        let fullTreeIconOffsets = processIconOffsets(in: table)
        XCTAssertEqual(fullTreeIconOffsets.count, fullTreeRows.count)
        for (offset, row) in zip(fullTreeIconOffsets, fullTreeRows) {
            XCTAssertEqual(offset, 4 + CGFloat(row.depth) * 12, accuracy: 0.5)
        }
        XCTAssertEqual(processCellIdentities(in: table), simpleCellIdentities)

        table.setDisplayMode(.simple)
        window.layoutIfNeeded()
        window.displayIfNeeded()

        XCTAssertEqual(table.renderedTable().rows, simpleRows)
        XCTAssertEqual(processCellIdentities(in: table), simpleCellIdentities)
        for offset in processIconOffsets(in: table) {
            XCTAssertEqual(offset, 4, accuracy: 0.5)
        }
    }

    @MainActor
    func testModeToggleUsesTheCorrectVisibilityDirectionAndRequestedMode() throws {
        let diameter = ProcessPanelMetrics.modeControlDiameter
        let control = ProcessModeToggleControl(
            frame: NSRect(x: 0, y: 0, width: diameter, height: diameter)
        )
        var requestedModes: [ProcessDisplayMode] = []
        control.onModeRequest = { requestedModes.append($0) }

        XCTAssertFalse(control.isHidden)
        XCTAssertEqual(control.alphaValue, 0)
        control.setHovered(true)

        XCTAssertFalse(control.isHidden)
        XCTAssertEqual(control.alphaValue, 1)
        XCTAssertFalse(control.isBordered)
        XCTAssertEqual(control.frame.width, control.frame.height)
        XCTAssertEqual(
            control.layer?.cornerRadius,
            ProcessPanelMetrics.modeControlDiameter / 2
        )
        XCTAssertEqual(control.layer?.backgroundColor?.alpha, 1)
        XCTAssertEqual(control.layer?.borderWidth, 0)
        XCTAssertEqual(control.toolTip, "Advanced")
        XCTAssertEqual(control.accessibilityLabel(), "Advanced")
        XCTAssertEqual(control.direction, .right)
        XCTAssertNotNil(control.symbolImage)
        XCTAssertEqual(
            control.symbolDrawingRect.midX,
            control.bounds.midX + ProcessPanelMetrics.modeControlSymbolOpticalOffset,
            accuracy: 0.001
        )
        XCTAssertEqual(control.symbolDrawingRect.midY, control.bounds.midY, accuracy: 0.001)
        XCTAssertEqual(control.outerStrokeAngles.lowerBound, -90)
        XCTAssertEqual(control.outerStrokeAngles.upperBound, 90)
        XCTAssertTrue(control.acceptsFirstMouse(for: nil))

        control.performClick(nil)
        XCTAssertEqual(requestedModes, [.fullTree])

        control.setDisplayMode(.fullTree)
        control.setHovered(false)

        XCTAssertFalse(control.isHidden)
        XCTAssertEqual(control.toolTip, "Collapse")
        XCTAssertEqual(control.accessibilityLabel(), "Collapse")
        XCTAssertEqual(control.direction, .left)
        XCTAssertEqual(
            control.symbolDrawingRect.midX,
            control.bounds.midX - ProcessPanelMetrics.modeControlSymbolOpticalOffset,
            accuracy: 0.001
        )
        XCTAssertEqual(control.symbolDrawingRect.midY, control.bounds.midY, accuracy: 0.001)
        XCTAssertEqual(control.outerStrokeAngles.lowerBound, -90)
        XCTAssertEqual(control.outerStrokeAngles.upperBound, 90)

        control.performClick(nil)
        XCTAssertEqual(requestedModes, [.fullTree, .simple])

        control.setAttachmentSide(.left)
        XCTAssertEqual(control.direction, .right)
        XCTAssertEqual(
            control.symbolDrawingRect.midX,
            control.bounds.midX + ProcessPanelMetrics.modeControlSymbolOpticalOffset,
            accuracy: 0.001
        )
        XCTAssertEqual(control.outerStrokeAngles.lowerBound, 90)
        XCTAssertEqual(control.outerStrokeAngles.upperBound, 270)

        control.setDisplayMode(.simple)
        XCTAssertEqual(control.direction, .left)
        XCTAssertEqual(
            control.symbolDrawingRect.midX,
            control.bounds.midX - ProcessPanelMetrics.modeControlSymbolOpticalOffset,
            accuracy: 0.001
        )
        XCTAssertEqual(control.outerStrokeAngles.lowerBound, 90)
        XCTAssertEqual(control.outerStrokeAngles.upperBound, 270)
        XCTAssertFalse(control.isHidden)
        XCTAssertEqual(control.alphaValue, 0)
    }

    @MainActor
    func testHoverTrackingViewReportsEntryAndExit() throws {
        let view = HoverTrackingView(frame: NSRect(x: 0, y: 0, width: 100, height: 100))
        var states: [Bool] = []
        view.onHoverChange = { states.append($0) }
        let event = try XCTUnwrap(
            NSEvent.mouseEvent(
                with: .mouseMoved,
                location: .zero,
                modifierFlags: [],
                timestamp: 0,
                windowNumber: 0,
                context: nil,
                eventNumber: 0,
                clickCount: 0,
                pressure: 0
            )
        )

        view.mouseEntered(with: event)
        view.mouseExited(with: event)

        XCTAssertEqual(states, [true, false])
    }

    @MainActor
    func testPanelModeToggleLayoutAndBehaviorForBothAttachmentSides() throws {
        let contentWidth = ProcessPanelMetrics.contentWidth(
            for: .simple,
            availableAdvancedContentWidth: ProcessPanelMetrics.advancedContentWidth
        )
        for side in [SidecarSide.right, .left] {
            var requestedModes: [ProcessDisplayMode] = []
            let content = CompanionContentView(
                frame: NSRect(
                    x: 0,
                    y: 0,
                    width: 300
                        + contentWidth
                        + ProcessPanelMetrics.modeControlWindowMargin,
                    height: 297
                ),
                displayMode: .simple,
                displayModeRequestHandler: { requestedModes.append($0) }
            )
            content.setAttachmentSide(side, reservedDialogWidth: 300)
            let window = NSWindow(
                contentRect: content.frame,
                styleMask: .borderless,
                backing: .buffered,
                defer: false
            )
            window.contentView = content
            window.layoutIfNeeded()

            let hoverView = try XCTUnwrap(firstSubview(of: HoverTrackingView.self, in: content))
            let control = try XCTUnwrap(
                firstSubview(of: ProcessModeToggleControl.self, in: content)
            )
            let material = try XCTUnwrap(
                firstSubview(of: NSVisualEffectView.self, in: content)
            )
            let table = try XCTUnwrap(firstSubview(of: ProcessTableView.self, in: content))
            let event = try XCTUnwrap(
                NSEvent.mouseEvent(
                    with: .mouseMoved,
                    location: .zero,
                    modifierFlags: [],
                    timestamp: 0,
                    windowNumber: window.windowNumber,
                    context: nil,
                    eventNumber: 0,
                    clickCount: 0,
                    pressure: 0
                )
            )

            XCTAssertFalse(control.isHidden)
            XCTAssertEqual(control.alphaValue, 0)
            let hiddenControlCenter = control.convert(
                NSPoint(x: control.bounds.midX, y: control.bounds.midY),
                to: content
            )
            XCTAssertTrue(
                hoverView.hitTest(hiddenControlCenter) === control,
                "body=\(hoverView.bounds) control=\(control.frame) point=\(hiddenControlCenter)"
            )
            hoverView.mouseEntered(with: event)
            window.layoutIfNeeded()

            let controlFrame = control.convert(control.bounds, to: content)
            XCTAssertFalse(control.isHidden)
            XCTAssertEqual(control.alphaValue, 1)
            XCTAssertEqual(control.toolTip, "Advanced")
            XCTAssertTrue(table.isDescendant(of: material))
            XCTAssertTrue(material.layer?.masksToBounds == true)
            XCTAssertEqual(controlFrame.width, ProcessPanelMetrics.modeControlDiameter)
            XCTAssertEqual(controlFrame.height, ProcessPanelMetrics.modeControlDiameter)
            let controlCenter = control.convert(
                NSPoint(x: control.bounds.midX, y: control.bounds.midY),
                to: content
            )
            XCTAssertTrue(
                hoverView.hitTest(controlCenter) === control,
                "body=\(hoverView.bounds) control=\(control.frame) point=\(controlCenter)"
            )
            let emptyBodyPoint = hoverView.convert(
                NSPoint(x: hoverView.bounds.midX, y: 12),
                to: content
            )
            XCTAssertNil(hoverView.hitTest(emptyBodyPoint))
            if side == .right {
                XCTAssertEqual(control.direction, .right)
                XCTAssertEqual(controlFrame.midX, material.frame.maxX, accuracy: 0.5)
                XCTAssertEqual(controlFrame.maxX, content.bounds.maxX, accuracy: 0.5)
                XCTAssertEqual(control.outerStrokeAngles.lowerBound, -90)
                XCTAssertEqual(control.outerStrokeAngles.upperBound, 90)
            } else {
                XCTAssertEqual(control.direction, .left)
                XCTAssertEqual(controlFrame.midX, material.frame.minX, accuracy: 0.5)
                XCTAssertEqual(controlFrame.minX, content.bounds.minX, accuracy: 0.5)
                XCTAssertEqual(control.outerStrokeAngles.lowerBound, 90)
                XCTAssertEqual(control.outerStrokeAngles.upperBound, 270)
            }

            control.performClick(nil)
            XCTAssertEqual(requestedModes, [.fullTree])

            content.setDisplayMode(.fullTree)
            hoverView.mouseExited(with: event)

            XCTAssertFalse(control.isHidden)
            XCTAssertEqual(control.alphaValue, 1)
            XCTAssertEqual(control.toolTip, "Collapse")
            XCTAssertEqual(control.direction, side == .right ? .left : .right)
            XCTAssertEqual(
                control.outerStrokeAngles.lowerBound,
                side == .right ? -90 : 90
            )
            XCTAssertEqual(
                control.outerStrokeAngles.upperBound,
                side == .right ? 90 : 270
            )

            control.performClick(nil)
            XCTAssertEqual(requestedModes, [.fullTree, .simple])
        }
    }

    @MainActor
    func testPanelTintUpdatesForTheEffectiveAppearance() throws {
        let tint = PanelTintView(frame: NSRect(x: 0, y: 0, width: 100, height: 100))
        tint.appearance = try XCTUnwrap(NSAppearance(named: .aqua))
        tint.updateLayer()
        let lightBrightness = try brightness(of: tint.layer?.backgroundColor)

        tint.appearance = try XCTUnwrap(NSAppearance(named: .darkAqua))
        tint.updateLayer()
        let darkBrightness = try brightness(of: tint.layer?.backgroundColor)

        XCTAssertGreaterThan(lightBrightness, darkBrightness)
    }

    @MainActor
    func testRenderedTableReadsConfiguredCellsAndAccessibilityValues() {
        let snapshot = sudoSnapshot(
            processArguments: ["sudo", "-k", "/bin/echo", "who-sudod-child-check"]
        )
        let table = ProcessTableView(
            frame: NSRect(x: 0, y: 0, width: 760, height: 240),
            displayMode: .fullTree
        )
        table.translatesAutoresizingMaskIntoConstraints = true
        let window = NSWindow(
            contentRect: table.frame,
            styleMask: .borderless,
            backing: .buffered,
            defer: false
        )
        window.contentView = table

        table.update(snapshot: snapshot)
        window.layoutIfNeeded()
        window.displayIfNeeded()

        XCTAssertEqual(
            table.renderedTable(),
            RenderedProcessTable(
                isComplete: true,
                rows: ProcessTablePresentationBuilder.rows(for: snapshot, mode: .fullTree)
            )
        )
    }

    @MainActor
    func testRenderedTableRejectsRowsOutsideVisibleViewport() {
        let snapshot = sudoSnapshot(
            processArguments: ["sudo", "-k", "/bin/echo", "who-sudod-child-check"]
        )
        let table = ProcessTableView(
            frame: NSRect(x: 0, y: 0, width: 760, height: 52),
            displayMode: .fullTree
        )
        table.translatesAutoresizingMaskIntoConstraints = true
        let window = NSWindow(
            contentRect: table.frame,
            styleMask: .borderless,
            backing: .buffered,
            defer: false
        )
        window.contentView = table

        table.update(snapshot: snapshot)
        window.layoutIfNeeded()
        window.displayIfNeeded()

        let rendered = table.renderedTable()
        XCTAssertFalse(rendered.isComplete)
        XCTAssertLessThan(
            rendered.rows.count,
            ProcessTablePresentationBuilder.rows(for: snapshot, mode: .fullTree).count
        )
    }

    @MainActor
    func testRenderedTableRejectsUnrealizedRows() {
        let snapshot = sudoSnapshot(
            processArguments: ["sudo", "-k", "/bin/echo", "who-sudod-child-check"]
        )
        let backingTable = MissingRealizedViewTableView()
        let table = ProcessTableView(
            frame: NSRect(x: 0, y: 0, width: 760, height: 240),
            tableView: backingTable,
            displayMode: .fullTree
        )
        table.translatesAutoresizingMaskIntoConstraints = true
        let window = NSWindow(
            contentRect: table.frame,
            styleMask: .borderless,
            backing: .buffered,
            defer: false
        )
        window.contentView = table

        table.update(snapshot: snapshot)
        window.layoutIfNeeded()
        window.displayIfNeeded()
        backingTable.returnMissingRealizedView = true

        let rendered = table.renderedTable()
        XCTAssertFalse(rendered.isComplete)
        XCTAssertTrue(rendered.rows.isEmpty)
    }

#if DEBUG
    func testLiveTreeDiagnosticsWritesOnlyStateChanges() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
            "who-sudod-live-tree-\(UUID().uuidString)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let stateURL = directory.appendingPathComponent("state.json")
        var diagnostics = try XCTUnwrap(
            LiveTreeDiagnostics(runID: "test-run", stateURL: stateURL)
        )
        let snapshot = sudoSnapshot(processArguments: ["sudo", "-v"])
        let rows = ProcessTablePresentationBuilder.rows(for: snapshot, mode: .fullTree)

        try diagnostics.recordVisible(
            promptSequence: 1,
            surfaceKind: .securityAgent,
            snapshot: snapshot,
            renderedTable: RenderedProcessTable(isComplete: true, rows: rows)
        )
        let first = try JSONDecoder().decode(
            LiveTreeDiagnosticState.self,
            from: Data(contentsOf: stateURL)
        )
        XCTAssertEqual(first.schemaVersion, 3)
        XCTAssertEqual(first.runID, "test-run")
        XCTAssertEqual(first.writeSequence, 1)
        XCTAssertEqual(first.promptSequence, 1)
        XCTAssertTrue(first.accessibilityTrusted)
        XCTAssertEqual(first.visibility, .visible)
        XCTAssertTrue(first.promptPresent)
        XCTAssertGreaterThan(first.writtenAtUptime, 0)
        XCTAssertTrue(first.renderingComplete)
        XCTAssertEqual(first.surfaceKind, "securityAgent")
        XCTAssertEqual(first.inspectionState, "complete")
        XCTAssertEqual(first.requestKind, "sudo")
        XCTAssertEqual(first.attribution, "heuristicSudo")
        XCTAssertEqual(first.candidateCount, 1)
        XCTAssertEqual(first.rows, rows)

        try diagnostics.recordVisible(
            promptSequence: 1,
            surfaceKind: .securityAgent,
            snapshot: snapshot,
            renderedTable: RenderedProcessTable(isComplete: true, rows: rows)
        )
        let unchanged = try JSONDecoder().decode(
            LiveTreeDiagnosticState.self,
            from: Data(contentsOf: stateURL)
        )
        XCTAssertEqual(unchanged.writeSequence, 1)

        try diagnostics.recordHidden(
            accessibilityTrusted: true,
            promptSequence: 1,
            promptPresent: false
        )
        let hidden = try JSONDecoder().decode(
            LiveTreeDiagnosticState.self,
            from: Data(contentsOf: stateURL)
        )
        XCTAssertEqual(hidden.writeSequence, 2)
        XCTAssertEqual(hidden.visibility, .hidden)
        XCTAssertFalse(hidden.promptPresent)
        XCTAssertTrue(hidden.rows.isEmpty)
    }
#endif

    private struct ApplicationFixture {
        let root: URL
        let bundle: URL
        let executable: URL
    }

    private func applicationFixture(name: String) throws -> ApplicationFixture {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "who-sudod-simple-app-\(UUID().uuidString)",
            isDirectory: true
        )
        let bundle = root.appendingPathComponent("\(name).app", isDirectory: true)
        let contents = bundle.appendingPathComponent("Contents", isDirectory: true)
        let executableDirectory = contents.appendingPathComponent("MacOS", isDirectory: true)
        let executable = executableDirectory.appendingPathComponent(name)
        try FileManager.default.createDirectory(
            at: executableDirectory,
            withIntermediateDirectories: true
        )
        let propertyList: [String: Any] = [
            "CFBundleDisplayName": name,
            "CFBundleExecutable": name,
            "CFBundleIdentifier": "com.zats.WhoSudod.\(UUID().uuidString)",
            "CFBundlePackageType": "APPL"
        ]
        let propertyListData = try PropertyListSerialization.data(
            fromPropertyList: propertyList,
            format: .xml,
            options: 0
        )
        try propertyListData.write(to: contents.appendingPathComponent("Info.plist"))
        try Data("#!/bin/sh\n".utf8).write(to: executable)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: executable.path
        )
        return ApplicationFixture(root: root, bundle: bundle, executable: executable)
    }

    private func process(
        pid: pid_t,
        parentPID: pid_t,
        name: String,
        path: String?,
        arguments: [String]? = nil
    ) -> ProcessRecord {
        ProcessRecord(
            pid: pid,
            parentPID: parentPID,
            realUserID: 502,
            name: name,
            executablePath: path,
            startTime: ProcessStartTime(seconds: UInt64(pid), microseconds: 0),
            processArguments: arguments
        )
    }

    private func row(
        process: ProcessRecord,
        depth: Int,
        requester: ProcessRecord
    ) -> ProcessTableRow {
        ProcessTableRow(
            process: process,
            requestedCommand: nil,
            depth: depth,
            candidateIndex: 0,
            candidateIdentity: requester.identity
        )
    }

    private func row(
        command: RequestedCommand,
        depth: Int,
        requester: ProcessRecord
    ) -> ProcessTableRow {
        ProcessTableRow(
            process: nil,
            requestedCommand: command,
            depth: depth,
            candidateIndex: 0,
            candidateIdentity: requester.identity
        )
    }

    private func snapshot(
        records: [ProcessRecord],
        requester: ProcessRecord,
        requestKind: AuthenticationRequestKind,
        attribution: AuthenticationAttribution
    ) -> AuthenticationProcessSnapshot {
        ProcessTreeBuilder.build(
            records: records,
            requesterIdentities: [requester.identity],
            requestKind: requestKind,
            attribution: attribution
        )
    }

    private func sudoSnapshot(processArguments: [String]) -> AuthenticationProcessSnapshot {
        let sudo = ProcessRecord(
            pid: 300,
            parentPID: 0,
    @MainActor
    private func processIconOffsets(in processTable: ProcessTableView) -> [CGFloat] {
        guard let tableView = firstSubview(of: NSTableView.self, in: processTable) else {
            return []
        }
        return (0 ..< tableView.numberOfRows).compactMap { row in
            guard let cell = tableView.view(
                atColumn: 0,
                row: row,
                makeIfNecessary: true
            ) as? NSTableCellView,
            let icon = cell.imageView else {
                return nil
            }
            cell.layoutSubtreeIfNeeded()
            return icon.frame.minX
        }
    }

    @MainActor
    private func processCellIdentities(
        in processTable: ProcessTableView
    ) -> [ObjectIdentifier] {
        guard let tableView = firstSubview(of: NSTableView.self, in: processTable) else {
            return []
        }
        return (0 ..< tableView.numberOfRows).compactMap { row in
            tableView.view(
                atColumn: 0,
                row: row,
                makeIfNecessary: true
            ).map(ObjectIdentifier.init)
        }
    }

            realUserID: 502,
            name: "sudo",
            executablePath: "/usr/bin/sudo",
            startTime: ProcessStartTime(seconds: 3, microseconds: 0),
            processArguments: processArguments
        )
        return ProcessTreeBuilder.build(
            records: [sudo],
            requesterIdentities: [sudo.identity],
            requestKind: .sudo,
            attribution: .heuristicSudo
        )
    }

    private func brightness(of color: CGColor?) throws -> CGFloat {
        let color = try XCTUnwrap(color)
        let converted = try XCTUnwrap(NSColor(cgColor: color)?.usingColorSpace(.deviceRGB))
        return converted.brightnessComponent
    }

    @MainActor
    private func firstSubview<View: NSView>(of type: View.Type, in root: NSView) -> View? {
        for subview in root.subviews {
            if let match = subview as? View {
                return match
            }
            if let nestedMatch = firstSubview(of: type, in: subview) {
                return nestedMatch
            }
        }
        return nil
    }
}

private final class MissingRealizedViewTableView: NSTableView {
    var returnMissingRealizedView = false

    override func view(
        atColumn column: Int,
        row: Int,
        makeIfNecessary: Bool
    ) -> NSView? {
        if returnMissingRealizedView,
           row == 0,
           column == 0,
           !makeIfNecessary {
            return nil
        }
        return super.view(
            atColumn: column,
            row: row,
            makeIfNecessary: makeIfNecessary
        )
    }
}

private final class ClickedRowTableView: NSTableView {
    var testClickedRow = -1

    override var clickedRow: Int {
        testClickedRow
    }
}

private final class RecordingTableView: NSTableView {
    private(set) var reloadDataCallCount = 0
    private(set) var insertedRows: [IndexSet] = []
    private(set) var removedRows: [IndexSet] = []

    override func reloadData() {
        reloadDataCallCount += 1
        super.reloadData()
    }

    override func insertRows(
        at indexes: IndexSet,
        withAnimation animationOptions: NSTableView.AnimationOptions = []
    ) {
        insertedRows.append(indexes)
        super.insertRows(at: indexes, withAnimation: animationOptions)
    }

    override func removeRows(
        at indexes: IndexSet,
        withAnimation animationOptions: NSTableView.AnimationOptions = []
    ) {
        removedRows.append(indexes)
        super.removeRows(at: indexes, withAnimation: animationOptions)
    }

    func resetRecordedUpdates() {
        reloadDataCallCount = 0
        insertedRows = []
        removedRows = []
    }
}

import AppKit
import XCTest
@testable import WhoSudod

final class IgnoredApplicationsTests: XCTestCase {
    func testDialogSummaryListsOnlyDialogsThatRemainVisible() {
        XCTAssertEqual(
            IgnoredApplicationRuleSorter.summary(Set(AuthenticationRequestKind.allCases)),
            "None"
        )
        XCTAssertEqual(
            IgnoredApplicationRuleSorter.summary([.authorization]),
            "Sudo, Local Authentication"
        )
        XCTAssertEqual(
            IgnoredApplicationRuleSorter.summary([]),
            "Sudo, Administrator access, Local Authentication"
        )
    }

    func testDialogSortUsesApplicationNameAsSecondarySort() {
        let alpha = ignoredRule(name: "Alpha", requestKinds: [.sudo])
        let beta = ignoredRule(name: "Beta", requestKinds: [.sudo])
        let gamma = ignoredRule(name: "Gamma", requestKinds: [.authorization])

        XCTAssertEqual(
            IgnoredApplicationRuleSorter.sorted(
                [beta, gamma, alpha],
                by: .dialogs,
                ascending: true
            ).map(\.displayName),
            ["Alpha", "Beta", "Gamma"]
        )
        XCTAssertEqual(
            IgnoredApplicationRuleSorter.sorted(
                [beta, gamma, alpha],
                by: .dialogs,
                ascending: false
            ).map(\.displayName),
            ["Gamma", "Alpha", "Beta"]
        )
    }

    @MainActor
    func testDeleteKeysRequestSelectedRuleRemoval() throws {
        let tableView = IgnoredApplicationsTableView()
        var deletionCount = 0
        tableView.deleteSelection = {
            deletionCount += 1
        }

        for keyCode: UInt16 in [51, 117] {
            let event = try XCTUnwrap(
                NSEvent.keyEvent(
                    with: .keyDown,
                    location: .zero,
                    modifierFlags: [],
                    timestamp: 0,
                    windowNumber: 0,
                    context: nil,
                    characters: "\u{7f}",
                    charactersIgnoringModifiers: "\u{7f}",
                    isARepeat: false,
                    keyCode: keyCode
                )
            )
            tableView.keyDown(with: event)
        }

        XCTAssertEqual(deletionCount, 2)
    }

    @MainActor
    func testStorePersistsSelectedRequestKinds() throws {
        let suiteName = "IgnoredApplicationsTests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let application = try makeApplication(
            name: "Example",
            bundleIdentifier: "com.example.ignored"
        )
        defer { try? FileManager.default.removeItem(at: application.root) }

        let store = IgnoredApplicationsStore(defaults: defaults, defaultApplicationURLs: [])
        let rule = try XCTUnwrap(store.addApplication(at: application.bundle))
        store.setRequestKinds([.sudo, .localAuthentication], for: rule.identifier)

        let restored = IgnoredApplicationsStore(defaults: defaults, defaultApplicationURLs: [])
        XCTAssertEqual(restored.rules.count, 1)
        XCTAssertEqual(restored.rules[0].bundleIdentifier, "com.example.ignored")
        XCTAssertEqual(restored.rules[0].requestKinds, [.sudo, .localAuthentication])
    }

    @MainActor
    func testStoreKeepsApplicationWhenEveryDialogTypeIsShown() throws {
        let suiteName = "IgnoredApplicationsVisibleTypesTests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let application = try makeApplication(
            name: "Visible",
            bundleIdentifier: "com.example.visible"
        )
        defer { try? FileManager.default.removeItem(at: application.root) }

        let store = IgnoredApplicationsStore(defaults: defaults, defaultApplicationURLs: [])
        let rule = try XCTUnwrap(store.addApplication(at: application.bundle))
        store.setRequestKinds([], for: rule.identifier)

        let restored = IgnoredApplicationsStore(defaults: defaults, defaultApplicationURLs: [])
        XCTAssertEqual(restored.rules.count, 1)
        XCTAssertEqual(restored.rules[0].requestKinds, [])
    }

    @MainActor
    func testStoreRestoresDefaultApplicationWhenItIsMissing() throws {
        let suiteName = "IgnoredApplicationsDefaultsTests-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let application = try makeApplication(
            name: "Default",
            bundleIdentifier: "com.example.default-ignored"
        )
        defer { try? FileManager.default.removeItem(at: application.root) }

        let store = IgnoredApplicationsStore(
            defaults: defaults,
            defaultApplicationURLs: [application.bundle]
        )
        XCTAssertEqual(store.rules.count, 1)
        XCTAssertEqual(
            store.rules[0].requestKinds,
            Set(AuthenticationRequestKind.allCases)
        )

        store.removeRule(identifier: store.rules[0].identifier)
        let relaunched = IgnoredApplicationsStore(
            defaults: defaults,
            defaultApplicationURLs: [application.bundle]
        )
        XCTAssertEqual(relaunched.rules.count, 1)
        XCTAssertEqual(
            relaunched.rules[0].bundleIdentifier,
            "com.example.default-ignored"
        )
    }

    func testRuleMatchesMovedCopyByBundleIdentifier() throws {
        let first = try makeApplication(
            name: "First Copy",
            bundleIdentifier: "com.example.same-application"
        )
        let second = try makeApplication(
            name: "Second Copy",
            bundleIdentifier: "com.example.same-application"
        )
        defer {
            try? FileManager.default.removeItem(at: first.root)
            try? FileManager.default.removeItem(at: second.root)
        }
        let application = try XCTUnwrap(RequestingApplicationResolver.application(at: first.bundle))
        let rule = IgnoredApplicationRule(
            bundleIdentifier: application.bundleIdentifier,
            applicationPath: application.applicationPath,
            displayName: application.displayName,
            requestKinds: [.authorization]
        )
        let chain = makeChain(executablePath: second.executable.path, requestKind: .authorization)

        XCTAssertTrue(IgnoredApplicationsPolicy.isIgnored(chain, by: [rule]))
    }

    func testPolicyFiltersOnlySelectedRequestKinds() throws {
        let application = try makeApplication(
            name: "Selective",
            bundleIdentifier: "com.example.selective"
        )
        defer { try? FileManager.default.removeItem(at: application.root) }
        let descriptor = try XCTUnwrap(
            RequestingApplicationResolver.application(at: application.bundle)
        )
        let rule = IgnoredApplicationRule(
            bundleIdentifier: descriptor.bundleIdentifier,
            applicationPath: descriptor.applicationPath,
            displayName: descriptor.displayName,
            requestKinds: [.sudo]
        )
        let sudo = makeChain(executablePath: application.executable.path, requestKind: .sudo)
        let localAuthentication = makeChain(
            executablePath: application.executable.path,
            requestKind: .localAuthentication,
            pid: 202
        )
        let snapshot = AuthenticationProcessSnapshot(
            candidates: [sudo, localAuthentication]
        )

        let filtered = IgnoredApplicationsPolicy.filtering(snapshot, by: [rule])

        XCTAssertEqual(filtered.candidates, [localAuthentication])
        XCTAssertEqual(filtered.inspectionState, snapshot.inspectionState)
    }

    func testPolicyUsesNearestApplicationInRequesterChain() throws {
        let outer = try makeApplication(
            name: "Outer",
            bundleIdentifier: "com.example.outer"
        )
        let nearest = try makeApplication(
            name: "Nearest",
            bundleIdentifier: "com.example.nearest"
        )
        defer {
            try? FileManager.default.removeItem(at: outer.root)
            try? FileManager.default.removeItem(at: nearest.root)
        }
        let descriptor = try XCTUnwrap(
            RequestingApplicationResolver.application(at: outer.bundle)
        )
        let outerRule = IgnoredApplicationRule(
            bundleIdentifier: descriptor.bundleIdentifier,
            applicationPath: descriptor.applicationPath,
            displayName: descriptor.displayName,
            requestKinds: [.sudo]
        )
        let chain = ProcessChain(
            processes: [
                process(pid: 1, parentPID: 0, name: "launchd", executablePath: "/sbin/launchd"),
                process(
                    pid: 100,
                    parentPID: 1,
                    name: "Outer",
                    executablePath: outer.executable.path
                ),
                process(
                    pid: 101,
                    parentPID: 100,
                    name: "Nearest",
                    executablePath: nearest.executable.path
                ),
                process(
                    pid: 102,
                    parentPID: 101,
                    name: "sudo",
                    executablePath: "/usr/bin/sudo"
                )
            ],
            descendants: [],
            isComplete: true,
            requestKind: .sudo,
            attribution: .heuristicSudo
        )

        XCTAssertEqual(
            RequestingApplicationResolver.application(for: chain)?.bundleIdentifier,
            "com.example.nearest"
        )
        XCTAssertFalse(IgnoredApplicationsPolicy.isIgnored(chain, by: [outerRule]))
    }

    func testPolicyDoesNotIgnoreCommandWithoutApplicationAncestor() {
        let rule = IgnoredApplicationRule(
            bundleIdentifier: "com.example.ignored",
            applicationPath: "/Applications/Ignored.app",
            displayName: "Ignored",
            requestKinds: Set(AuthenticationRequestKind.allCases)
        )
        let chain = makeChain(executablePath: "/usr/bin/sudo", requestKind: .sudo)

        XCTAssertFalse(IgnoredApplicationsPolicy.isIgnored(chain, by: [rule]))
    }

    private func makeChain(
        executablePath: String,
        requestKind: AuthenticationRequestKind,
        pid: pid_t = 201
    ) -> ProcessChain {
        ProcessChain(
            processes: [
                process(pid: 1, parentPID: 0, name: "launchd", executablePath: "/sbin/launchd"),
                process(
                    pid: pid,
                    parentPID: 1,
                    name: "Example",
                    executablePath: executablePath
                )
            ],
            descendants: [],
            isComplete: true,
            requestKind: requestKind,
            attribution: requestKind == .sudo ? .heuristicSudo : .authorizationLog
        )
    }

    private func ignoredRule(
        name: String,
        requestKinds: Set<AuthenticationRequestKind>
    ) -> IgnoredApplicationRule {
        IgnoredApplicationRule(
            bundleIdentifier: "com.example.\(name.lowercased())",
            applicationPath: "/Applications/\(name).app",
            displayName: name,
            requestKinds: requestKinds
        )
    }

    private func process(
        pid: pid_t,
        parentPID: pid_t,
        name: String,
        executablePath: String
    ) -> ProcessRecord {
        ProcessRecord(
            pid: pid,
            parentPID: parentPID,
            realUserID: getuid(),
            name: name,
            executablePath: executablePath,
            startTime: ProcessStartTime(seconds: UInt64(pid), microseconds: 0)
        )
    }

    private func makeApplication(
        name: String,
        bundleIdentifier: String
    ) throws -> (root: URL, bundle: URL, executable: URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "who-sudod-ignored-app-\(UUID().uuidString)",
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
        try Data().write(to: executable)
        let info: [String: Any] = [
            "CFBundleIdentifier": bundleIdentifier,
            "CFBundleExecutable": name,
            "CFBundleDisplayName": name,
            "CFBundlePackageType": "APPL"
        ]
        let infoData = try PropertyListSerialization.data(
            fromPropertyList: info,
            format: .xml,
            options: 0
        )
        try infoData.write(to: contents.appendingPathComponent("Info.plist"))
        return (root, bundle, executable)
    }
}

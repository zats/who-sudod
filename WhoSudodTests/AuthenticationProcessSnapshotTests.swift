import Darwin
import XCTest
@testable import WhoSudod

final class AuthenticationProcessSnapshotTests: XCTestCase {
    func testHeuristicPreferredAnchorAllowsNewLogEvidenceToTakePriority() {
        let anchor = AuthenticationRequestAnchor(
            identity: ProcessIdentity(
                pid: 300,
                startTime: ProcessStartTime(seconds: 3, microseconds: 0)
            ),
            requestKind: .sudo,
            attribution: .heuristicSudo
        )

        XCTAssertFalse(AuthenticationAnchorPriority.isAuthoritative(anchor))
    }

    func testLogAttributedPreferredAnchorsRemainAuthoritative() {
        for attribution in [
            AuthenticationAttribution.authorizationLog,
            .localAuthenticationLog
        ] {
            let anchor = AuthenticationRequestAnchor(
                identity: ProcessIdentity(
                    pid: 300,
                    startTime: ProcessStartTime(seconds: 3, microseconds: 0)
                ),
                requestKind: .authorization,
                attribution: attribution
            )

            XCTAssertTrue(AuthenticationAnchorPriority.isAuthoritative(anchor))
        }
    }

    func testEvidencePathMatcherAcceptsExactExecutablePath() {
        XCTAssertTrue(
            AuthenticationEvidencePathMatcher.matches(
                reportedPath: "/bin/echo",
                liveExecutablePath: "/bin/echo"
            )
        )
    }

    func testEvidencePathMatcherAcceptsBundleDeclaredExecutable() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(
            "who-sudod-path-matcher-\(UUID().uuidString)",
            isDirectory: true
        )
        let bundleURL = root.appendingPathComponent("Requester.app", isDirectory: true)
        let contentsURL = bundleURL.appendingPathComponent("Contents", isDirectory: true)
        let executableDirectory = contentsURL.appendingPathComponent("MacOS", isDirectory: true)
        try FileManager.default.createDirectory(
            at: executableDirectory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: root) }

        let propertyList: [String: Any] = [
            "CFBundleExecutable": "Requester",
            "CFBundleIdentifier": "com.zats.WhoSudodPathMatcherFixture",
            "CFBundlePackageType": "APPL"
        ]
        let propertyListData = try PropertyListSerialization.data(
            fromPropertyList: propertyList,
            format: .xml,
            options: 0
        )
        try propertyListData.write(to: contentsURL.appendingPathComponent("Info.plist"))
        try FileManager.default.createSymbolicLink(
            at: executableDirectory.appendingPathComponent("Requester"),
            withDestinationURL: URL(fileURLWithPath: "/bin/echo")
        )

        XCTAssertTrue(
            AuthenticationEvidencePathMatcher.matches(
                reportedPath: bundleURL.path,
                liveExecutablePath: "/bin/echo"
            )
        )
        XCTAssertFalse(
            AuthenticationEvidencePathMatcher.matches(
                reportedPath: bundleURL.path,
                liveExecutablePath: "/bin/cat"
            )
        )
    }

    func testEvidencePathMatcherRejectsUnrelatedPaths() {
        XCTAssertFalse(
            AuthenticationEvidencePathMatcher.matches(
                reportedPath: "/bin/echo",
                liveExecutablePath: "/bin/cat"
            )
        )
    }

    func testRequesterUserPolicyAllowsRootAuthorizationLogRequester() {
        XCTAssertTrue(
            AuthenticationRequesterUserPolicy.allows(
                realUserID: 0,
                signedInUserID: 501,
                attribution: .authorizationLog
            )
        )
    }

    func testRequesterUserPolicyRejectsRootForOtherAttribution() {
        XCTAssertFalse(
            AuthenticationRequesterUserPolicy.allows(
                realUserID: 0,
                signedInUserID: 501,
                attribution: .localAuthenticationLog
            )
        )
        XCTAssertFalse(
            AuthenticationRequesterUserPolicy.allows(
                realUserID: 0,
                signedInUserID: 501,
                attribution: .heuristicSudo
            )
        )
    }

    func testRequesterUserPolicyAllowsSignedInUserForEveryAttribution() {
        for attribution in [
            AuthenticationAttribution.authorizationLog,
            .localAuthenticationLog,
            .heuristicSudo
        ] {
            XCTAssertTrue(
                AuthenticationRequesterUserPolicy.allows(
                    realUserID: 501,
                    signedInUserID: 501,
                    attribution: attribution
                )
            )
        }
    }

    func testRequesterUserPolicyRejectsDifferentNonRootUser() {
        XCTAssertFalse(
            AuthenticationRequesterUserPolicy.allows(
                realUserID: 502,
                signedInUserID: 501,
                attribution: .authorizationLog
            )
        )
    }

    func testBuildsObservedLocalAuthenticationAncestry() throws {
        let helper = record(
            pid: 300,
            parent: 200,
            name: "LocalAuthenticationTest",
            path: "/tmp/LocalAuthenticationTest",
            start: 3
        )
        let snapshot = ProcessTreeBuilder.build(
            records: [
                record(pid: 1, parent: 0, name: "launchd", path: "/sbin/launchd", start: 1),
                record(pid: 200, parent: 1, name: "zsh", path: "/bin/zsh", start: 2),
                helper
            ],
            requesterIdentities: [helper.identity],
            requestKind: .localAuthentication,
            attribution: .localAuthenticationLog
        )

        let chain = try XCTUnwrap(snapshot.candidates.first)
        XCTAssertEqual(chain.processes.map(\.pid), [1, 200, 300])
        XCTAssertEqual(chain.requesterProcess, helper)
        XCTAssertEqual(chain.requestKind, .localAuthentication)
        XCTAssertEqual(chain.attribution, .localAuthenticationLog)
        XCTAssertTrue(chain.isComplete)
    }

    func testRejectsReusedRequesterPIDWithDifferentStartTime() {
        let oldIdentity = ProcessIdentity(
            pid: 300,
            startTime: ProcessStartTime(seconds: 3, microseconds: 0)
        )
        let snapshot = ProcessTreeBuilder.build(
            records: [
                record(
                    pid: 300,
                    parent: 1,
                    name: "DifferentProcess",
                    path: "/tmp/DifferentProcess",
                    start: 9
                )
            ],
            requesterIdentities: [oldIdentity],
            requestKind: .localAuthentication,
            attribution: .localAuthenticationLog
        )

        XCTAssertTrue(snapshot.candidates.isEmpty)
    }

    func testRetainsObservedAuthorizationRequesterAsExited() {
        let requester = record(
            pid: 300,
            parent: 0,
            name: "osascript",
            path: "/usr/bin/osascript",
            start: 3
        )
        let captured = ProcessTreeBuilder.build(
            records: [requester],
            requesterIdentities: [requester.identity],
            requestKind: .authorization,
            attribution: .authorizationLog
        )

        let result = ProcessSnapshotSelection.refreshingLive(
            current: captured,
            observed: .empty
        )

        XCTAssertEqual(result.candidates, captured.candidates)
        XCTAssertEqual(result.inspectionState, .requesterExited)
    }

    func testDropsExitedHeuristicSudoRequester() {
        let sudo = record(
            pid: 300,
            parent: 0,
            name: "sudo",
            path: "/usr/bin/sudo",
            start: 3
        )
        let captured = ProcessTreeBuilder.build(
            records: [sudo],
            requesterIdentities: [sudo.identity],
            requestKind: .sudo,
            attribution: .heuristicSudo
        )

        let result = ProcessSnapshotSelection.refreshingLive(
            current: captured,
            observed: .empty
        )

        XCTAssertTrue(result.candidates.isEmpty)
        XCTAssertEqual(result.inspectionState, .complete)
    }

    func testKeepsPinnedRequesterWhenAnotherObservedCandidateAppears() throws {
        let first = record(
            pid: 300,
            parent: 0,
            name: "FirstClient",
            path: "/tmp/FirstClient",
            start: 3
        )
        let second = record(
            pid: 400,
            parent: 0,
            name: "SecondClient",
            path: "/tmp/SecondClient",
            start: 4
        )
        let current = ProcessTreeBuilder.build(
            records: [first],
            requesterIdentities: [first.identity],
            requestKind: .localAuthentication,
            attribution: .localAuthenticationLog
        )
        let observed = ProcessTreeBuilder.build(
            records: [first, second],
            requesterIdentities: [second.identity, first.identity],
            requestKind: .localAuthentication,
            attribution: .localAuthenticationLog
        )

        let result = ProcessSnapshotSelection.refreshingLive(
            current: current,
            observed: observed
        )

        XCTAssertEqual(try XCTUnwrap(result.candidates.first).requesterProcess.pid, 300)
    }

    func testRefreshesPinnedRequesterWithCurrentDescendants() throws {
        let requester = record(
            pid: 300,
            parent: 0,
            name: "Client",
            path: "/tmp/Client",
            start: 3
        )
        let child = record(
            pid: 400,
            parent: 300,
            name: "Helper",
            path: "/tmp/Helper",
            start: 4
        )
        let current = ProcessTreeBuilder.build(
            records: [requester, child],
            requesterIdentities: [requester.identity],
            requestKind: .localAuthentication,
            attribution: .localAuthenticationLog
        )
        let observed = ProcessTreeBuilder.build(
            records: [requester],
            requesterIdentities: [requester.identity],
            requestKind: .localAuthentication,
            attribution: .localAuthenticationLog
        )

        let result = ProcessSnapshotSelection.refreshingLive(
            current: current,
            observed: observed
        )

        XCTAssertTrue(try XCTUnwrap(result.candidates.first).descendants.isEmpty)
    }

    func testReportsDepthFromRequesterForActualDescendants() throws {
        let requester = record(
            pid: 300,
            parent: 200,
            name: "Client",
            path: "/tmp/Client",
            start: 3
        )
        let snapshot = ProcessTreeBuilder.build(
            records: [
                record(pid: 1, parent: 0, name: "launchd", path: "/sbin/launchd", start: 1),
                record(pid: 200, parent: 1, name: "zsh", path: "/bin/zsh", start: 2),
                requester,
                record(pid: 400, parent: 300, name: "first", path: "/tmp/first", start: 4),
                record(pid: 500, parent: 400, name: "nested", path: "/tmp/nested", start: 5),
                record(pid: 410, parent: 300, name: "second", path: "/tmp/second", start: 6)
            ],
            requesterIdentities: [requester.identity],
            requestKind: .authorization,
            attribution: .authorizationLog
        )

        let chain = try XCTUnwrap(snapshot.candidates.first)
        XCTAssertEqual(chain.descendants.map { $0.process.pid }, [400, 500, 410])
        XCTAssertEqual(chain.descendants.map(\.depthFromRequester), [1, 2, 1])
        XCTAssertEqual(snapshot.processCount, 6)
    }

    func testStopsIncompleteAncestryAtMissingParent() throws {
        let requester = record(
            pid: 300,
            parent: 999,
            name: "Client",
            path: "/tmp/Client",
            start: 3
        )
        let snapshot = ProcessTreeBuilder.build(
            records: [requester],
            requesterIdentities: [requester.identity],
            requestKind: .authorization,
            attribution: .authorizationLog
        )

        let chain = try XCTUnwrap(snapshot.candidates.first)
        XCTAssertEqual(chain.processes.map(\.pid), [300])
        XCTAssertFalse(chain.isComplete)
    }

    func testExtractsRequestedCommandOnlyFromSudo() {
        let sudo = record(
            pid: 300,
            parent: 0,
            name: "sudo",
            path: "/usr/bin/sudo",
            start: 3,
            processArguments: ["sudo", "/bin/cat", "/etc/hosts"]
        )
        let other = record(
            pid: 400,
            parent: 0,
            name: "tool",
            path: "/usr/bin/tool",
            start: 4,
            processArguments: ["tool", "/bin/cat", "/etc/hosts"]
        )

        XCTAssertEqual(
            sudo.requestedCommand,
            RequestedCommand(executable: "/bin/cat", arguments: ["/etc/hosts"])
        )
        XCTAssertNil(other.requestedCommand)
    }

    func testDoesNotTreatSudoValidationModeAsARequestedCommand() {
        let shortForm = record(
            pid: 300,
            parent: 0,
            name: "sudo",
            path: "/usr/bin/sudo",
            start: 3,
            processArguments: ["sudo", "-v"]
        )
        let longForm = record(
            pid: 301,
            parent: 0,
            name: "sudo",
            path: "/usr/bin/sudo",
            start: 4,
            processArguments: ["/usr/bin/sudo", "--validate", "--user", "root"]
        )

        XCTAssertNil(shortForm.requestedCommand)
        XCTAssertNil(longForm.requestedCommand)
    }

    func testDoesNotProjectShortShellModeAsADirectCommand() {
        XCTAssertNil(
            SudoInvocationParser.command(
                from: ["sudo", "-s", "echo", "hello"]
            )
        )
    }

    func testDoesNotProjectClusteredShellModeAsADirectCommand() {
        XCTAssertNil(
            SudoInvocationParser.command(
                from: ["sudo", "-ns", "echo", "hello"]
            )
        )
        XCTAssertNil(
            SudoInvocationParser.command(
                from: ["sudo", "-ni", "echo", "hello"]
            )
        )
    }

    func testDoesNotProjectLongShellModesAsDirectCommands() {
        XCTAssertNil(
            SudoInvocationParser.command(
                from: ["sudo", "--shell", "echo", "hello"]
            )
        )
        XCTAssertNil(
            SudoInvocationParser.command(
                from: ["sudo", "--login", "echo", "hello"]
            )
        )
    }

    func testDoesNotTreatSudoeditInvocationAsARequestedCommand() {
        let sudo = record(
            pid: 300,
            parent: 0,
            name: "sudo",
            path: "/usr/bin/sudo",
            start: 3,
            processArguments: ["/usr/bin/sudoedit", "/etc/hosts"]
        )

        XCTAssertNil(sudo.requestedCommand)
    }

    func testSkipsSudoOptionsAndEnvironmentBeforeRequestedCommand() {
        let sudo = record(
            pid: 300,
            parent: 0,
            name: "sudo",
            path: "/usr/bin/sudo",
            start: 3,
            processArguments: [
                "sudo", "-k", "-u", "root", "SAMPLE=value", "--", "/bin/echo", "hello"
            ]
        )

        XCTAssertEqual(
            sudo.requestedCommand,
            RequestedCommand(executable: "/bin/echo", arguments: ["hello"])
        )
    }

    func testAttachedShortOptionValuesAreNotParsedAsFlags() {
        for arguments in [
            ["sudo", "-udeveloper", "/bin/echo", "ok"],
            ["sudo", "-nudeveloper", "/bin/echo", "ok"],
            ["sudo", "-pPassword: ", "/bin/echo", "ok"],
            ["sudo", "-D/tmp", "/bin/echo", "ok"]
        ] {
            XCTAssertEqual(
                SudoInvocationParser.command(from: arguments),
                RequestedCommand(executable: "/bin/echo", arguments: ["ok"])
            )
        }
    }

    func testSeparateShortOptionValuePreservesSpaces() {
        XCTAssertEqual(
            SudoInvocationParser.command(
                from: ["sudo", "-p", "Password for this request: ", "/bin/echo", "hello world"]
            ),
            RequestedCommand(executable: "/bin/echo", arguments: ["hello world"])
        )
    }

    func testRequestedCommandDisplayPreservesArgumentBoundaries() {
        let command = RequestedCommand(
            executable: "/Applications/Example App.app/Contents/MacOS/Example Tool",
            arguments: ["argument with spaces", "plain", "can't"]
        )

        XCTAssertEqual(
            command.displayText,
            "'/Applications/Example App.app/Contents/MacOS/Example Tool' "
                + "'argument with spaces' plain 'can'\\''t'"
        )
    }

    func testDoesNotTreatSudoListTargetAsAChildCommand() {
        let sudo = record(
            pid: 300,
            parent: 0,
            name: "sudo",
            path: "/usr/bin/sudo",
            start: 3,
            processArguments: ["sudo", "-l", "/bin/cat", "/etc/hosts"]
        )

        XCTAssertNil(sudo.requestedCommand)
    }

    func testProcessCommandLineParserReadsPSOutput() {
        let output = Data("/usr/bin/sudo -- /bin/echo hello\n".utf8)

        XCTAssertEqual(
            ProcessCommandLineParser.arguments(fromPSOutput: output),
            ["/usr/bin/sudo", "--", "/bin/echo", "hello"]
        )
    }

    func testProcessCommandLineParserRejectsEmptyAndOversizedOutput() {
        XCTAssertNil(ProcessCommandLineParser.arguments(fromPSOutput: Data()))
        XCTAssertNil(
            ProcessCommandLineParser.arguments(
                fromPSOutput: Data(repeating: 0x61, count: 1_048_577)
            )
        )
    }

    func testSanitizesControlAndBidirectionalCharactersInDisplayText() {
        let value = "/bin/echo safe\nspoof\u{202E}txt"

        XCTAssertEqual(
            DisplayTextSanitizer.sanitize(value),
            "/bin/echo safe�spoof�txt"
        )
    }

    private func record(
        pid: pid_t,
        parent: pid_t,
        user: uid_t = 502,
        name: String,
        path: String,
        start: UInt64,
        processArguments: [String]? = nil
    ) -> ProcessRecord {
        ProcessRecord(
            pid: pid,
            parentPID: parent,
            realUserID: user,
            name: name,
            executablePath: path,
            startTime: ProcessStartTime(seconds: start, microseconds: 0),
            processArguments: processArguments
        )
    }

}

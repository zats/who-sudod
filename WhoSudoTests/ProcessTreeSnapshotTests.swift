import Darwin
import XCTest
@testable import WhoSudo

final class ProcessTreeSnapshotTests: XCTestCase {
    func testBuildsOldestToSudoChainForCurrentUser() {
        let records = [
            record(pid: 1, parent: 0, name: "launchd", path: "/sbin/launchd", start: 1),
            record(pid: 100, parent: 1, name: "Terminal", path: "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", start: 2),
            record(pid: 200, parent: 100, name: "zsh", path: "/bin/zsh", start: 3),
            record(pid: 300, parent: 200, name: "sudo", path: "/usr/bin/sudo", start: 4),
            record(pid: 400, parent: 200, user: 501, name: "sudo", path: "/usr/bin/sudo", start: 5)
        ]

        let snapshot = ProcessTreeBuilder.build(records: records, realUserID: 502)

        XCTAssertEqual(snapshot.candidates.count, 1)
        XCTAssertEqual(snapshot.candidates[0].processes.map(\.pid), [1, 100, 200, 300])
        XCTAssertTrue(snapshot.candidates[0].isComplete)
    }

    func testMarksMissingParentAsIncomplete() {
        let snapshot = ProcessTreeBuilder.build(
            records: [record(pid: 300, parent: 999, name: "sudo", path: "/usr/bin/sudo", start: 4)],
            realUserID: 502
        )

        XCTAssertEqual(snapshot.candidates[0].processes.map(\.pid), [300])
        XCTAssertFalse(snapshot.candidates[0].isComplete)
    }

    func testStopsAtCycle() {
        let records = [
            record(pid: 200, parent: 300, name: "zsh", path: "/bin/zsh", start: 3),
            record(pid: 300, parent: 200, name: "sudo", path: "/usr/bin/sudo", start: 4)
        ]

        let snapshot = ProcessTreeBuilder.build(records: records, realUserID: 502)

        XCTAssertEqual(snapshot.candidates[0].processes.map(\.pid), [200, 300])
        XCTAssertFalse(snapshot.candidates[0].isComplete)
    }

    func testOrdersNewestSudoCandidateFirst() {
        let records = [
            record(pid: 300, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 4),
            record(pid: 400, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 8)
        ]

        let snapshot = ProcessTreeBuilder.build(records: records, realUserID: 502)

        XCTAssertEqual(snapshot.candidates.map { $0.sudoProcess.pid }, [400, 300])
    }

    func testDropsCapturedSnapshotAfterSudoExits() {
        let captured = ProcessTreeBuilder.build(
            records: [record(pid: 300, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 4)],
            realUserID: 502
        )

        let result = ProcessSnapshotSelection.refreshingLive(
            current: captured,
            observed: .empty
        )

        XCTAssertTrue(result.candidates.isEmpty)
    }

    func testSwitchesToTheOnlyLiveCandidate() {
        let captured = ProcessTreeBuilder.build(
            records: [record(pid: 300, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 4)],
            realUserID: 502
        )
        let observed = ProcessTreeBuilder.build(
            records: [record(pid: 400, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 8)],
            realUserID: 502
        )

        let result = ProcessSnapshotSelection.refreshingLive(
            current: captured,
            observed: observed
        )

        XCTAssertEqual(result.candidates.map { $0.sudoProcess.pid }, [400])
    }

    func testReplacesCapturedCandidateWithMoreCompleteChain() {
        let captured = ProcessTreeBuilder.build(
            records: [record(pid: 300, parent: 200, name: "sudo", path: "/usr/bin/sudo", start: 4)],
            realUserID: 502
        )
        let observed = ProcessTreeBuilder.build(
            records: [
                record(pid: 1, parent: 0, name: "launchd", path: "/sbin/launchd", start: 1),
                record(pid: 200, parent: 1, name: "zsh", path: "/bin/zsh", start: 3),
                record(pid: 300, parent: 200, name: "sudo", path: "/usr/bin/sudo", start: 4)
            ],
            realUserID: 502
        )

        let result = ProcessSnapshotSelection.refreshingLive(
            current: captured,
            observed: observed
        )

        XCTAssertEqual(result.candidates[0].processes.map(\.pid), [1, 200, 300])
        XCTAssertTrue(result.candidates[0].isComplete)
    }

    func testSelectsNewestWhenPromptHasNoPinnedRequest() {
        let observed = ProcessTreeBuilder.build(
            records: [
                record(pid: 300, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 4),
                record(pid: 400, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 8)
            ],
            realUserID: 502
        )

        let result = ProcessSnapshotSelection.refreshingLive(current: .empty, observed: observed)

        XCTAssertEqual(result.candidates.map { $0.sudoProcess.pid }, [400])
    }

    func testKeepsPinnedRequestWhenAnotherSudoStarts() {
        let current = ProcessTreeBuilder.build(
            records: [record(pid: 300, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 4)],
            realUserID: 502
        )
        let observed = ProcessTreeBuilder.build(
            records: [
                record(pid: 300, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 4),
                record(pid: 400, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 8)
            ],
            realUserID: 502
        )

        let result = ProcessSnapshotSelection.refreshingLive(current: current, observed: observed)

        XCTAssertEqual(result.candidates.map { $0.sudoProcess.pid }, [300])
    }

    func testRemovesExitedDescendantsFromPinnedRequest() {
        let current = ProcessTreeBuilder.build(
            records: [
                record(pid: 300, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 4),
                record(pid: 400, parent: 300, name: "tool", path: "/usr/bin/tool", start: 5)
            ],
            realUserID: 502
        )
        let observed = ProcessTreeBuilder.build(
            records: [record(pid: 300, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 4)],
            realUserID: 502
        )

        let result = ProcessSnapshotSelection.refreshingLive(current: current, observed: observed)

        XCTAssertTrue(result.candidates[0].descendants.isEmpty)
    }

    func testKeepsPinnedRequestDuringUnavailableScan() {
        let current = ProcessTreeBuilder.build(
            records: [record(pid: 300, parent: 0, name: "sudo", path: "/usr/bin/sudo", start: 4)],
            realUserID: 502
        )

        let result = ProcessSnapshotSelection.refreshingLive(
            current: current,
            observed: .unavailable
        )

        XCTAssertEqual(result.candidates.map { $0.sudoProcess.pid }, [300])
        XCTAssertEqual(result.inspectionState, .unavailable)
    }

    func testExtractsRequestedCommandFromSudoCommandLine() {
        let sudo = record(
            pid: 300,
            parent: 0,
            name: "sudo",
            path: "/usr/bin/sudo",
            start: 4,
            commandLine: "sudo /bin/cat /etc/hosts"
        )

        XCTAssertEqual(sudo.requestedCommand, "/bin/cat /etc/hosts")
    }

    func testSanitizesControlAndBidirectionalCharactersInCommandDisplay() {
        let value = "/bin/echo safe\nspoof\u{202E}txt"

        XCTAssertEqual(
            CommandDisplaySanitizer.sanitize(value),
            "/bin/echo safe�spoof�txt"
        )
    }

    func testAddsActualDescendantsBelowSudo() {
        let snapshot = ProcessTreeBuilder.build(
            records: [
                record(pid: 1, parent: 0, name: "launchd", path: "/sbin/launchd", start: 1),
                record(pid: 200, parent: 1, name: "zsh", path: "/bin/zsh", start: 2),
                record(pid: 300, parent: 200, name: "sudo", path: "/usr/bin/sudo", start: 3),
                record(pid: 400, parent: 300, name: "tool", path: "/usr/local/bin/tool", start: 4),
                record(pid: 500, parent: 400, name: "helper", path: "/usr/local/bin/helper", start: 5),
                record(pid: 410, parent: 300, name: "logger", path: "/usr/bin/logger", start: 6)
            ],
            realUserID: 502
        )

        XCTAssertEqual(snapshot.candidates[0].processes.map(\.pid), [1, 200, 300])
        XCTAssertEqual(snapshot.candidates[0].descendants.map { $0.process.pid }, [400, 500, 410])
        XCTAssertEqual(snapshot.candidates[0].descendants.map(\.depthFromSudo), [1, 2, 1])
        XCTAssertEqual(snapshot.processCount, 6)
    }

    private func record(
        pid: pid_t,
        parent: pid_t,
        user: uid_t = 502,
        name: String,
        path: String,
        start: UInt64,
        commandLine: String? = nil
    ) -> ProcessRecord {
        ProcessRecord(
            pid: pid,
            parentPID: parent,
            realUserID: user,
            name: name,
            executablePath: path,
            startTime: ProcessStartTime(seconds: start, microseconds: 0),
            commandLine: commandLine
        )
    }
}

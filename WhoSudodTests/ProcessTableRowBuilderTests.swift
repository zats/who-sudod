import Darwin
import XCTest
@testable import WhoSudod

final class ProcessTableRowBuilderTests: XCTestCase {
    func testValidationOnlySudoHasNoCommandRow() throws {
        let snapshot = sudoSnapshot(commandLine: "sudo -v")

        let rows = ProcessTableRowBuilder.rows(for: snapshot)

        XCTAssertEqual(rows.count, 1)
        XCTAssertEqual(try XCTUnwrap(rows.first).process?.name, "sudo")
        XCTAssertNil(rows.first?.requestedCommand)
    }

    func testSudoCommandHasPendingCommandRow() throws {
        let snapshot = sudoSnapshot(
            commandLine: "sudo -k /bin/echo who-sudod-child-check"
        )

        let rows = ProcessTableRowBuilder.rows(for: snapshot)

        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows[0].process?.name, "sudo")
        XCTAssertNil(rows[1].process)
        XCTAssertEqual(
            rows[1].requestedCommand,
            "/bin/echo who-sudod-child-check"
        )
        XCTAssertEqual(rows[1].depth, 1)
    }

    private func sudoSnapshot(commandLine: String) -> AuthenticationProcessSnapshot {
        let sudo = ProcessRecord(
            pid: 300,
            parentPID: 0,
            realUserID: 502,
            name: "sudo",
            executablePath: "/usr/bin/sudo",
            startTime: ProcessStartTime(seconds: 3, microseconds: 0),
            commandLine: commandLine
        )
        return ProcessTreeBuilder.build(
            records: [sudo],
            requesterIdentities: [sudo.identity],
            requestKind: .sudo,
            attribution: .heuristicSudo
        )
    }
}

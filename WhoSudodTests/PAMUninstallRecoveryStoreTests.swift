import Foundation
import XCTest
@testable import WhoSudod

final class PAMUninstallRecoveryStoreTests: XCTestCase {
    func testMissingFileLoadsNone() throws {
        let values = try temporaryStore()

        XCTAssertEqual(try values.store.load(), .none)
    }

    func testSaveReplacesTheSinglePhaseValue() throws {
        let values = try temporaryStore()

        for phase in [
            PAMUninstallRecoveryPhase.uninstallPending,
            .helperCleanupRequired,
            .installOutcomeUnknown,
            .uninstallOutcomeUnknown,
            .none,
        ] {
            try values.store.save(phase)

            XCTAssertEqual(try values.store.load(), phase)
            XCTAssertEqual(
                try String(contentsOf: values.fileURL, encoding: .utf8),
                phase.rawValue
            )
            let temporaryFiles = try FileManager.default.contentsOfDirectory(
                atPath: values.directoryURL.path
            ).filter { $0.hasSuffix(".tmp") }
            XCTAssertTrue(temporaryFiles.isEmpty)
        }

        let attributes = try FileManager.default.attributesOfItem(
            atPath: values.fileURL.path
        )
        let permissions = try XCTUnwrap(
            attributes[.posixPermissions] as? NSNumber
        ).intValue
        XCTAssertEqual(permissions & 0o777, 0o600)
    }

    func testInvalidPhaseValueIsRejected() throws {
        let values = try temporaryStore()
        try Data("unknown".utf8).write(to: values.fileURL)

        XCTAssertThrowsError(try values.store.load()) { error in
            XCTAssertEqual(
                error.localizedDescription,
                "The PAM change recovery file contains an invalid value."
            )
        }
    }

    private func temporaryStore() throws -> (
        store: FilePAMUninstallRecoveryStore,
        fileURL: URL,
        directoryURL: URL
    ) {
        let directoryURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "PAMUninstallRecoveryStoreTests.\(UUID().uuidString)",
                isDirectory: true
            )
        try FileManager.default.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: false
        )
        addTeardownBlock {
            try? FileManager.default.removeItem(at: directoryURL)
        }
        let fileURL = directoryURL.appendingPathComponent("phase")
        return (
            FilePAMUninstallRecoveryStore(fileURL: fileURL),
            fileURL,
            directoryURL
        )
    }
}

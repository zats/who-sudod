import Foundation
import XCTest
@testable import WhoSudod

final class PAMConfigurationEditorTests: XCTestCase {
    private let offerLine = PAMIntegrationConstants.ownedOfferConfigurationLine
    private let restoreLine = PAMIntegrationConstants.ownedRestoreConfigurationLine

    func testDetectsOnlyExactOwnedPayloadReferences() {
        XCTAssertTrue(
            PAMConfigurationEditor.hasOwnedPayloadReference(
                in: Data("auth include sudo_local\n\(offerLine)\n".utf8)
            )
        )
        XCTAssertTrue(
            PAMConfigurationEditor.hasOwnedPayloadReference(
                in: Data("\(restoreLine)\r\nauth required pam_opendirectory.so\r\n".utf8)
            )
        )
        XCTAssertFalse(
            PAMConfigurationEditor.hasOwnedPayloadReference(
                in: Data("# \(offerLine)\nauth required pam_opendirectory.so\n".utf8)
            )
        )
        XCTAssertFalse(
            PAMConfigurationEditor.hasOwnedPayloadReference(
                in: Data("auth optional \(PAMIntegrationConstants.installedModulePath) foreign\n".utf8)
            )
        )
    }

    func testInstallsBeforePasswordModuleWithoutChangingCustomEntries() throws {
        let original = """
        # sudo: auth account password session
        auth       include        sudo_local
        auth       sufficient     pam_yubico.so mode=challenge-response
        auth       sufficient     pam_smartcard.so
        auth       required       pam_opendirectory.so
        account    required       pam_permit.so

        """

        let updated = try PAMConfigurationEditor.installing(in: Data(original.utf8))
        let expected = original.replacingOccurrences(
            of: "auth       required       pam_opendirectory.so",
            with: "\(offerLine)\nauth       required       pam_opendirectory.so\n\(restoreLine)"
        )
        XCTAssertEqual(updated, Data(expected.utf8))
    }

    func testInstallationRepairsDuplicateOwnedEntries() throws {
        let original = """
        \(restoreLine)
        auth sufficient pam_smartcard.so
        \(offerLine)
        \(offerLine)
        auth required pam_opendirectory.so
        \(restoreLine)
        """

        let updated = try PAMConfigurationEditor.installing(in: Data(original.utf8))
        let text = try XCTUnwrap(String(data: updated, encoding: .utf8))
        XCTAssertEqual(text.components(separatedBy: offerLine).count - 1, 1)
        XCTAssertEqual(text.components(separatedBy: restoreLine).count - 1, 1)
        XCTAssertTrue(
            text.contains(
                "auth sufficient pam_smartcard.so\n\(offerLine)\nauth required pam_opendirectory.so\n\(restoreLine)"
            )
        )
    }

    func testUninstallRemovesOnlyOwnedEntries() throws {
        let original = """
        auth include sudo_local
        auth optional /Library/Security/WhoSudod/another_module.so
        \(offerLine)
        auth required pam_opendirectory.so
        \(restoreLine)
        """

        let updated = try PAMConfigurationEditor.uninstalling(from: Data(original.utf8))
        let text = try XCTUnwrap(String(data: updated, encoding: .utf8))
        XCTAssertFalse(text.contains(offerLine))
        XCTAssertFalse(text.contains(restoreLine))
        XCTAssertTrue(text.contains("auth optional /Library/Security/WhoSudod/another_module.so"))
        XCTAssertTrue(text.contains("auth required pam_opendirectory.so"))
    }

    func testPreservesWindowsLineEndings() throws {
        let original = "auth include sudo_local\r\nauth required pam_opendirectory.so\r\n"
        let updated = try PAMConfigurationEditor.installing(in: Data(original.utf8))
        let expected = "auth include sudo_local\r\n\(offerLine)\r\nauth required pam_opendirectory.so\r\n\(restoreLine)\r\n"
        XCTAssertEqual(updated, Data(expected.utf8))
    }

    func testPreservesMissingFinalLineTerminator() throws {
        let original = "auth include sudo_local\nauth required pam_opendirectory.so"
        let updated = try PAMConfigurationEditor.installing(in: Data(original.utf8))
        let expected = "auth include sudo_local\n\(offerLine)\nauth required pam_opendirectory.so\n\(restoreLine)"

        XCTAssertEqual(updated, Data(expected.utf8))
    }

    func testIgnoresCommentedModuleReference() throws {
        let original = """
        # auth optional /Library/Security/WhoSudod/pam_whosudod.so foreign
        auth required pam_opendirectory.so
        """

        XCTAssertNoThrow(
            try PAMConfigurationEditor.installing(in: Data(original.utf8))
        )
    }

    func testRefusesMissingOrAmbiguousPasswordAnchor() {
        XCTAssertThrowsError(
            try PAMConfigurationEditor.installing(in: Data("auth include sudo_local\n".utf8))
        ) { error in
            XCTAssertEqual(error as? PAMConfigurationError, .missingPasswordAnchor)
        }
        XCTAssertThrowsError(
            try PAMConfigurationEditor.installing(
                in: Data("auth required pam_opendirectory.so\nauth required pam_opendirectory.so\n".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? PAMConfigurationError, .ambiguousPasswordAnchor)
        }
    }

    func testRefusesOptionsOnPasswordAnchor() {
        for option in ["try_first_pass", "use_first_pass", "nullok"] {
            let configuration = Data(
                "auth required pam_opendirectory.so \(option)\n".utf8
            )
            XCTAssertThrowsError(
                try PAMConfigurationEditor.installing(in: configuration)
            ) { error in
                XCTAssertEqual(
                    error as? PAMConfigurationError,
                    .unsupportedPasswordAnchorOptions
                )
            }
        }
    }

    func testRefusesAnUnownedReferenceToTheInstallPath() {
        let configuration = """
        auth optional /Library/Security/WhoSudod/pam_whosudod.so different_argument
        auth required pam_opendirectory.so
        """
        XCTAssertThrowsError(
            try PAMConfigurationEditor.installing(in: Data(configuration.utf8))
        ) { error in
            XCTAssertEqual(error as? PAMConfigurationError, .foreignModuleReference)
        }

        XCTAssertThrowsError(
            try PAMConfigurationEditor.uninstalling(from: Data(configuration.utf8))
        ) { error in
            XCTAssertEqual(error as? PAMConfigurationError, .foreignModuleReference)
        }
    }

    func testReportsInstalledOnlyForExactCompleteInstallation() {
        let configuration = Data(
            "\(offerLine)\nauth required pam_opendirectory.so\n\(restoreLine)\n".utf8
        )
        XCTAssertEqual(
            PAMConfigurationEditor.inspect(
                configuration: configuration,
                moduleExists: true,
                moduleMatchesPayload: true,
                terminalReaderExists: true,
                terminalReaderMatchesPayload: true
            ).state,
            .installed
        )
        XCTAssertEqual(
            PAMConfigurationEditor.inspect(
                configuration: configuration,
                moduleExists: true,
                moduleMatchesPayload: false,
                terminalReaderExists: true,
                terminalReaderMatchesPayload: true
            ).state,
            .needsRepair
        )
        XCTAssertEqual(
            PAMConfigurationEditor.inspect(
                configuration: configuration,
                moduleExists: false,
                moduleMatchesPayload: false,
                terminalReaderExists: true,
                terminalReaderMatchesPayload: true
            ).state,
            .needsRepair
        )

        let noOwnedLine = Data("auth required pam_opendirectory.so\n".utf8)
        XCTAssertEqual(
            PAMConfigurationEditor.inspect(
                configuration: noOwnedLine,
                moduleExists: true,
                moduleMatchesPayload: true,
                terminalReaderExists: true,
                terminalReaderMatchesPayload: true
            ).state,
            .needsRepair
        )

        XCTAssertEqual(
            PAMConfigurationEditor.inspect(
                configuration: configuration,
                moduleExists: true,
                moduleMatchesPayload: true,
                terminalReaderExists: false,
                terminalReaderMatchesPayload: false
            ).state,
            .needsRepair
        )
    }

    func testUninstallCanRecoverAfterPasswordAnchorWasRemoved() throws {
        let configuration = Data(
            "auth include sudo_local\n\(offerLine)\n\(restoreLine)\n".utf8
        )
        let updated = try PAMConfigurationEditor.uninstalling(from: configuration)
        XCTAssertEqual(updated, Data("auth include sudo_local\n".utf8))
    }

    func testInspectionOffersRemovalWhenUnsupportedConfigurationContainsOwnedLines() {
        let configurations = [
            "auth include sudo_local\n\(offerLine)\n\(restoreLine)\n",
            "\(offerLine)\nauth required pam_opendirectory.so\nauth required pam_opendirectory.so\n\(restoreLine)\n",
            "\(offerLine)\nauth required pam_opendirectory.so try_first_pass\n\(restoreLine)\n",
        ]

        for configuration in configurations {
            XCTAssertEqual(
                PAMConfigurationEditor.inspect(
                    configuration: Data(configuration.utf8),
                    moduleExists: false,
                    moduleMatchesPayload: false,
                    terminalReaderExists: false,
                    terminalReaderMatchesPayload: false
                ).state,
                .removalOnly
            )
        }
    }

    func testInspectionOffersRemovalWhenUnsupportedConfigurationHasOwnedPayload() {
        let inspection = PAMConfigurationEditor.inspect(
            configuration: Data("auth required pam_opendirectory.so nullok\n".utf8),
            moduleExists: true,
            moduleMatchesPayload: true,
            terminalReaderExists: false,
            terminalReaderMatchesPayload: false
        )

        XCTAssertEqual(inspection.state, .removalOnly)
    }

    func testInspectionDoesNotOfferRemovalWithoutOwnedArtifacts() {
        let inspection = PAMConfigurationEditor.inspect(
            configuration: Data("auth include sudo_local\n".utf8),
            moduleExists: false,
            moduleMatchesPayload: false,
            terminalReaderExists: false,
            terminalReaderMatchesPayload: false
        )

        XCTAssertEqual(inspection.state, .unsupported)
    }

    func testInspectionDoesNotOfferRemovalForForeignModuleReference() {
        let configuration = """
        \(offerLine)
        auth optional /Library/Security/WhoSudod/pam_whosudod.so foreign_argument
        """
        let inspection = PAMConfigurationEditor.inspect(
            configuration: Data(configuration.utf8),
            moduleExists: true,
            moduleMatchesPayload: true,
            terminalReaderExists: false,
            terminalReaderMatchesPayload: false
        )

        XCTAssertEqual(inspection.state, .unsupported)
    }
}

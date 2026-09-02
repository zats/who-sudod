import AppKit
import XCTest
@testable import WhoSudod

final class ApplicationLaunchContextTests: XCTestCase {
    func testStartsMonitorForNormalLaunch() {
        XCTAssertTrue(ApplicationLaunchContext.shouldStartMonitor(environment: [:]))
    }

    func testDoesNotStartMonitorInsideXCTestHost() {
        XCTAssertFalse(
            ApplicationLaunchContext.shouldStartMonitor(
                environment: ["XCTestConfigurationFilePath": "/tmp/test.xctestconfiguration"]
            )
        )
    }

    func testSettingsCloseShortcutRequiresOnlyCommandQ() throws {
        XCTAssertTrue(
            SettingsKeyboardShortcut.closesSettings(
                for: try keyEvent(character: "q", modifiers: .command)
            )
        )
        XCTAssertFalse(
            SettingsKeyboardShortcut.closesSettings(
                for: try keyEvent(character: "w", modifiers: .command)
            )
        )
        XCTAssertFalse(
            SettingsKeyboardShortcut.closesSettings(
                for: try keyEvent(character: "q", modifiers: [])
            )
        )
        XCTAssertFalse(
            SettingsKeyboardShortcut.closesSettings(
                for: try keyEvent(character: "q", modifiers: [.command, .option])
            )
        )
    }

    @MainActor
    func testStatusFingerprintIsATemplateImage() throws {
        let image = try XCTUnwrap(NSImage(named: "StatusFingerprint"))

        XCTAssertTrue(image.isTemplate)
        XCTAssertFalse(image.representations.isEmpty)
    }

    private func keyEvent(
        character: String,
        modifiers: NSEvent.ModifierFlags
    ) throws -> NSEvent {
        try XCTUnwrap(
            NSEvent.keyEvent(
                with: .keyDown,
                location: .zero,
                modifierFlags: modifiers,
                timestamp: 0,
                windowNumber: 0,
                context: nil,
                characters: character,
                charactersIgnoringModifiers: character,
                isARepeat: false,
                keyCode: 0
            )
        )
    }
}

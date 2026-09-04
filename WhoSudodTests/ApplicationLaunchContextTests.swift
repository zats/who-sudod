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

    func testDoesNotStartMonitorInsideXcodePreviewHost() {
        XCTAssertFalse(
            ApplicationLaunchContext.shouldStartMonitor(
                environment: ["XCODE_RUNNING_FOR_PREVIEWS": "1"]
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

    @MainActor
    func testStatusMenuContainsOnlySettingsAndQuit() {
        let delegate = AppDelegate()
        let menu = delegate.makeStatusMenu()
        let actionTitles = menu.items
            .filter { !$0.isSeparatorItem }
            .map(\.title)

        XCTAssertEqual(
            actionTitles,
            [
                "Settings…",
                "Quit Who Sudo'd"
            ]
        )
        XCTAssertFalse(
            actionTitles.contains { $0.localizedCaseInsensitiveContains("Accessibility") }
        )
        XCTAssertFalse(actionTitles.contains { $0.localizedCaseInsensitiveContains("PAM") })
        XCTAssertFalse(delegate.dependenciesAreLoaded)
    }

    @MainActor
    func testTestHostLaunchDoesNotLoadProductionDependencies() {
        let delegate = AppDelegate(
            environment: ["XCTestConfigurationFilePath": "/tmp/tests.xctestconfiguration"]
        )

        delegate.applicationDidFinishLaunching(
            Notification(name: NSApplication.didFinishLaunchingNotification)
        )

        XCTAssertFalse(delegate.dependenciesAreLoaded)
    }

    @MainActor
    func testTestHostReopenDoesNotLoadProductionDependencies() {
        let delegate = AppDelegate(
            environment: ["XCTestConfigurationFilePath": "/tmp/tests.xctestconfiguration"]
        )

        let shouldHandleReopen = delegate.applicationShouldHandleReopen(
            NSApplication.shared,
            hasVisibleWindows: false
        )

        XCTAssertFalse(shouldHandleReopen)
        XCTAssertFalse(delegate.dependenciesAreLoaded)
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

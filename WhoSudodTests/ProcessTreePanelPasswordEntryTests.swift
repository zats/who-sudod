import AppKit
import XCTest
@testable import WhoSudod

final class ProcessTreePanelPasswordEntryTests: XCTestCase {
    @MainActor
    func testVerifiedRequestEnablesInputAndSubmitEndsPresentation() throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        let controller = ProcessTreePanelController()
        defer { controller.hide(promptPresent: false, accessibilityTrusted: true) }
        let request = VerifiedPAMPasswordRequest(id: UUID())
        var submittedRequestID: UUID?
        var submittedPassword: String?

        controller.presentVerifiedPAMPasswordRequest(
            request,
            onPassword: { requestID, password in
                submittedRequestID = requestID
                submittedPassword = password
            }
        )
        controller.showNotch(
            snapshot: .pending,
            promptSequence: -1,
            anchorFrame: screen.visibleFrame,
            visibleFrame: screen.visibleFrame
        )

        XCTAssertTrue(controller.isPresentingVerifiedPAMPasswordRequest)
        XCTAssertTrue(try XCTUnwrap(controller.notchWindow).canBecomeKey)
        XCTAssertFalse(try XCTUnwrap(controller.window).canBecomeKey)

        let contentView = try XCTUnwrap(controller.notchWindow?.contentView)
        let passwordField = try XCTUnwrap(firstSubview(of: NSSecureTextField.self, in: contentView))
        let submitButton = try XCTUnwrap(
            firstSubview(
                of: NSButton.self,
                in: contentView,
                where: { $0.title == "Submit" }
            )
        )
        contentView.layoutSubtreeIfNeeded()
        XCTAssertTrue(passwordField.frame.contains(submitButton.frame))
        passwordField.stringValue = "test-password"
        submitButton.performClick(nil)

        XCTAssertEqual(submittedRequestID, request.id)
        XCTAssertEqual(submittedPassword, "test-password")
        XCTAssertEqual(passwordField.stringValue, "")
        XCTAssertFalse(controller.isPresentingVerifiedPAMPasswordRequest)
        XCTAssertFalse(try XCTUnwrap(controller.notchWindow).canBecomeKey)
    }

    @MainActor
    func testInvalidPasswordDoesNotDismissInputOrSubmit() throws {
        let controller = ProcessTreePanelController()
        let request = VerifiedPAMPasswordRequest(id: UUID())
        var submissionCount = 0

        controller.presentVerifiedPAMPasswordRequest(
            request,
            onPassword: { _, _ in submissionCount += 1 }
        )

        let contentView = try XCTUnwrap(controller.notchWindow?.contentView)
        let passwordField = try XCTUnwrap(firstSubview(of: NSSecureTextField.self, in: contentView))
        let submitButton = try XCTUnwrap(
            firstSubview(of: NSButton.self, in: contentView, where: { $0.title == "Submit" })
        )
        passwordField.stringValue = ""
        submitButton.performClick(nil)

        XCTAssertEqual(submissionCount, 0)
        XCTAssertTrue(controller.isPresentingVerifiedPAMPasswordRequest)
    }

    @MainActor
    func testRepeatedNotchPresentationPreservesPasswordInput() throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        let controller = ProcessTreePanelController()
        defer { controller.hide(promptPresent: false, accessibilityTrusted: true) }
        let request = VerifiedPAMPasswordRequest(id: UUID())
        controller.presentVerifiedPAMPasswordRequest(request, onPassword: { _, _ in })
        controller.showNotch(
            snapshot: .pending,
            promptSequence: -1,
            anchorFrame: screen.visibleFrame,
            visibleFrame: screen.visibleFrame
        )
        let content = try XCTUnwrap(controller.notchWindow?.contentView)
        let passwordField = try XCTUnwrap(
            firstSubview(of: NSSecureTextField.self, in: content)
        )
        passwordField.stringValue = "partially entered"

        controller.showNotch(
            snapshot: .pending,
            promptSequence: -1,
            anchorFrame: screen.visibleFrame,
            visibleFrame: screen.visibleFrame
        )

        XCTAssertTrue(controller.isPresentingVerifiedPAMPasswordRequest)
        XCTAssertEqual(passwordField.stringValue, "partially entered")
        XCTAssertTrue(controller.notchWindow?.isVisible == true)
    }

    @MainActor
    func testHideClearsPresentationWithoutRespondingToPAM() {
        let controller = ProcessTreePanelController()
        let request = VerifiedPAMPasswordRequest(id: UUID())
        var responseCount = 0

        controller.presentVerifiedPAMPasswordRequest(
            request,
            onPassword: { _, _ in responseCount += 1 }
        )
        controller.hide(promptPresent: false, accessibilityTrusted: false)

        XCTAssertEqual(responseCount, 0)
        XCTAssertFalse(controller.isPresentingVerifiedPAMPasswordRequest)
        XCTAssertFalse(controller.notchWindow?.canBecomeKey ?? true)
    }

    @MainActor
    func testEscapeFromSecureFieldRequestsNotchDismissalWithoutSubmitting() throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        let controller = ProcessTreePanelController()
        defer { controller.hide(promptPresent: false, accessibilityTrusted: true) }
        var dismissalCount = 0
        var submissionCount = 0
        controller.onNotchDismissRequest = { dismissalCount += 1 }
        controller.presentVerifiedPAMPasswordRequest(
            VerifiedPAMPasswordRequest(id: UUID()),
            onPassword: { _, _ in submissionCount += 1 }
        )
        controller.showNotch(
            snapshot: .pending,
            promptSequence: -1,
            anchorFrame: screen.visibleFrame,
            visibleFrame: screen.visibleFrame
        )

        let window = try XCTUnwrap(controller.notchWindow)
        let content = try XCTUnwrap(window.contentView)
        let passwordField = try XCTUnwrap(
            firstSubview(of: NSSecureTextField.self, in: content)
        )
        window.makeKey()
        XCTAssertTrue(window.makeFirstResponder(passwordField))
        let editor = try XCTUnwrap(passwordField.currentEditor() as? NSTextView)
        XCTAssertTrue(window.firstResponder === editor)
        let escape = try XCTUnwrap(
            NSEvent.keyEvent(
                with: .keyDown,
                location: .zero,
                modifierFlags: [],
                timestamp: ProcessInfo.processInfo.systemUptime,
                windowNumber: window.windowNumber,
                context: nil,
                characters: "\u{1B}",
                charactersIgnoringModifiers: "\u{1B}",
                isARepeat: false,
                keyCode: 53
            )
        )

        window.sendEvent(escape)

        XCTAssertEqual(dismissalCount, 1)
        XCTAssertEqual(submissionCount, 0)
        XCTAssertTrue(controller.isPresentingVerifiedPAMPasswordRequest)
    }

    @MainActor
    func testEscapeDismissesReadOnlyNonKeyNotch() throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        let controller = ProcessNotchController(
            displayMode: .simple,
            displayModeRequestHandler: { _ in }
        )
        defer { controller.hide() }
        var dismissalCount = 0
        controller.onDismissRequest = { dismissalCount += 1 }
        controller.show(snapshot: .pending, screen: screen, animated: false)
        let escape = try XCTUnwrap(
            NSEvent.keyEvent(
                with: .keyDown,
                location: .zero,
                modifierFlags: [],
                timestamp: ProcessInfo.processInfo.systemUptime,
                windowNumber: 0,
                context: nil,
                characters: "\u{1B}",
                charactersIgnoringModifiers: "\u{1B}",
                isARepeat: false,
                keyCode: 53
            )
        )

        XCTAssertFalse(controller.window?.isKeyWindow ?? true)
        XCTAssertFalse(controller.passwordInputVisible)
        XCTAssertTrue(controller.handleEscapeKeyDown(escape))
        XCTAssertEqual(dismissalCount, 1)
    }

    @MainActor
    func testTerminalOnlyPresentationUsesNotchWithoutPasswordInput() throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        let controller = ProcessTreePanelController()
        defer { controller.hide(promptPresent: false, accessibilityTrusted: true) }
        controller.showNotch(
            snapshot: .pending, promptSequence: -1,
            anchorFrame: screen.visibleFrame, visibleFrame: screen.visibleFrame
        )

        XCTAssertTrue(controller.isPresented)
        XCTAssertTrue(controller.notchWindow?.isVisible == true)
        XCTAssertFalse(controller.window?.isVisible == true)
        XCTAssertFalse(controller.notchWindow?.canBecomeKey ?? true)
        XCTAssertFalse(controller.isPresentingVerifiedPAMPasswordRequest)
        let content = try XCTUnwrap(controller.notchWindow?.contentView)
        XCTAssertTrue(try XCTUnwrap(firstSubview(of: PAMPasswordEntryView.self, in: content)).isHidden)
    }

    @MainActor
    func testSystemDialogImmediatelyReplacesNotchAndRemovesPasswordInput() throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        let controller = ProcessTreePanelController()
        defer { controller.hide(promptPresent: false, accessibilityTrusted: true) }
        controller.presentVerifiedPAMPasswordRequest(
            VerifiedPAMPasswordRequest(id: UUID()),
            onPassword: { _, _ in XCTFail("Switching surfaces must not submit") }
        )
        controller.showNotch(
            snapshot: .pending, promptSequence: -1,
            anchorFrame: screen.visibleFrame, visibleFrame: screen.visibleFrame
        )
        controller.show(
            snapshot: .pending, promptSequence: 1, surfaceKind: .securityAgent,
            authenticationFrame: CGRect(x: screen.frame.midX, y: screen.frame.midY, width: 260, height: 300),
            visibleFrame: screen.visibleFrame
        )

        XCTAssertTrue(controller.window?.isVisible == true)
        XCTAssertFalse(controller.notchWindow?.isVisible == true)
        XCTAssertFalse(controller.isPresentingVerifiedPAMPasswordRequest)
        XCTAssertFalse(controller.window?.canBecomeKey ?? true)
    }

    @MainActor
    func testPasswordInputCanReturnAfterTemporarySystemDialogWithoutSubmitting() throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        let controller = ProcessTreePanelController()
        defer { controller.hide(promptPresent: false, accessibilityTrusted: true) }
        let request = VerifiedPAMPasswordRequest(id: UUID())
        var submissionCount = 0
        let presentPasswordInput = {
            controller.presentVerifiedPAMPasswordRequest(
                request,
                onPassword: { _, _ in submissionCount += 1 }
            )
            controller.showNotch(
                snapshot: .pending,
                promptSequence: -1,
                anchorFrame: screen.visibleFrame,
                visibleFrame: screen.visibleFrame,
                allowsPAMSetupAction: false
            )
        }

        presentPasswordInput()
        controller.show(
            snapshot: .pending,
            promptSequence: 1,
            surfaceKind: .securityAgent,
            authenticationFrame: CGRect(
                x: screen.frame.midX,
                y: screen.frame.midY,
                width: 260,
                height: 300
            ),
            visibleFrame: screen.visibleFrame
        )
        XCTAssertFalse(controller.isPresentingVerifiedPAMPasswordRequest)

        presentPasswordInput()

        XCTAssertEqual(submissionCount, 0)
        XCTAssertTrue(controller.notchWindow?.isVisible == true)
        XCTAssertFalse(controller.window?.isVisible == true)
        XCTAssertTrue(controller.isPresentingVerifiedPAMPasswordRequest)
        let content = try XCTUnwrap(controller.notchWindow?.contentView)
        XCTAssertFalse(
            try XCTUnwrap(firstSubview(of: PAMPasswordEntryView.self, in: content)).isHidden
        )
    }

    @MainActor
    func testPasswordInputCanReturnAfterPanelWasHiddenWithoutSubmitting() throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        let controller = ProcessTreePanelController()
        defer { controller.hide(promptPresent: false, accessibilityTrusted: true) }
        let request = VerifiedPAMPasswordRequest(id: UUID())
        var submissionCount = 0

        controller.presentVerifiedPAMPasswordRequest(
            request,
            onPassword: { _, _ in submissionCount += 1 }
        )
        controller.showNotch(
            snapshot: .pending,
            promptSequence: -1,
            anchorFrame: screen.visibleFrame,
            visibleFrame: screen.visibleFrame,
            allowsPAMSetupAction: false
        )
        controller.hide(promptPresent: true, accessibilityTrusted: true)
        XCTAssertFalse(controller.isPresentingVerifiedPAMPasswordRequest)

        controller.presentVerifiedPAMPasswordRequest(
            request,
            onPassword: { _, _ in submissionCount += 1 }
        )
        controller.showNotch(
            snapshot: .pending,
            promptSequence: -1,
            anchorFrame: screen.visibleFrame,
            visibleFrame: screen.visibleFrame,
            allowsPAMSetupAction: false
        )

        XCTAssertEqual(submissionCount, 0)
        XCTAssertTrue(controller.isPresentingVerifiedPAMPasswordRequest)
        XCTAssertTrue(controller.notchWindow?.isVisible == true)
    }

    @MainActor
    func testPAMSetupActionAppearsInsteadOfPasswordInputAndReportsExactAction() throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        var selectedAction: PAMSettingsAction?
        let controller = ProcessTreePanelController(
            pamSetupActionProvider: {
                PAMNotchAction(action: .repair, title: "Repair…")
            },
            pamSetupActionHandler: { selectedAction = $0 }
        )
        defer { controller.hide(promptPresent: false, accessibilityTrusted: true) }

        controller.showNotch(
            snapshot: .pending,
            promptSequence: -1,
            anchorFrame: screen.visibleFrame,
            visibleFrame: screen.visibleFrame
        )

        let content = try XCTUnwrap(controller.notchWindow?.contentView)
        let actionButton = try XCTUnwrap(
            firstSubview(of: NSButton.self, in: content, where: { $0.title == "Repair…" })
        )
        XCTAssertFalse(actionButton.isHidden)
        XCTAssertTrue(try XCTUnwrap(firstSubview(of: PAMPasswordEntryView.self, in: content)).isHidden)

        actionButton.performClick(nil)
        XCTAssertEqual(selectedAction, .repair)
    }

    @MainActor
    func testVerifiedPasswordInputHidesSetupActionAndDismissDoesNotRevealIt() throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        let request = VerifiedPAMPasswordRequest(id: UUID())
        let controller = ProcessTreePanelController(
            pamSetupActionProvider: {
                PAMNotchAction(action: .install, title: "Install…")
            }
        )
        defer { controller.hide(promptPresent: false, accessibilityTrusted: true) }

        controller.showNotch(
            snapshot: .pending,
            promptSequence: -1,
            anchorFrame: screen.visibleFrame,
            visibleFrame: screen.visibleFrame
        )
        controller.presentVerifiedPAMPasswordRequest(request, onPassword: { _, _ in })

        let content = try XCTUnwrap(controller.notchWindow?.contentView)
        let actionButton = try XCTUnwrap(
            firstSubview(
                of: NSButton.self,
                in: content,
                where: { $0.accessibilityIdentifier() == "who-sudod.notch.pam-action" }
            )
        )
        XCTAssertTrue(actionButton.isHidden)
        XCTAssertFalse(try XCTUnwrap(firstSubview(of: PAMPasswordEntryView.self, in: content)).isHidden)

        controller.dismissVerifiedPAMPasswordRequest(request.id)
        controller.showNotch(
            snapshot: .pending,
            promptSequence: -1,
            anchorFrame: screen.visibleFrame,
            visibleFrame: screen.visibleFrame,
            allowsPAMSetupAction: false
        )

        XCTAssertTrue(actionButton.isHidden)
        XCTAssertTrue(try XCTUnwrap(firstSubview(of: PAMPasswordEntryView.self, in: content)).isHidden)
    }

    @MainActor
    func testNotchHeaderControlsAreAboveTheTableAndDismisses() throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        let controller = ProcessNotchController(
            displayMode: .simple,
            displayModeRequestHandler: { _ in }
        )
        var dismissalCount = 0
        controller.onDismissRequest = { dismissalCount += 1 }
        defer { controller.hide() }

        controller.show(snapshot: .pending, screen: screen, animated: false)
        let content = try XCTUnwrap(controller.window?.contentView)
        content.layoutSubtreeIfNeeded()
        let modeButton = try XCTUnwrap(
            firstSubview(
                of: NSButton.self,
                in: content,
                where: {
                    $0.accessibilityIdentifier() == "who-sudod.notch.display-mode"
                }
            )
        )
        let table = try XCTUnwrap(firstSubview(of: ProcessTableView.self, in: content))
        let dismissButton = try XCTUnwrap(
            firstSubview(
                of: NSButton.self,
                in: content,
                where: {
                    $0.accessibilityIdentifier() == "who-sudod.notch.dismiss"
                }
            )
        )
        let modeFrame = modeButton.convert(modeButton.bounds, to: content)
        let dismissFrame = dismissButton.convert(dismissButton.bounds, to: content)
        let tableFrame = table.convert(table.bounds, to: content)

        XCTAssertLessThanOrEqual(modeFrame.maxY, tableFrame.minY)
        XCTAssertLessThanOrEqual(dismissFrame.maxY, tableFrame.minY)
        XCTAssertEqual(content.bounds.maxX - modeFrame.maxX, 20, accuracy: 1)
        XCTAssertEqual(dismissFrame.minX, 20, accuracy: 1)
        XCTAssertEqual(dismissFrame.minY, modeFrame.minY, accuracy: 1)
        XCTAssertEqual(modeFrame.size, CGSize(width: 28, height: 28))
        XCTAssertEqual(dismissFrame.size, CGSize(width: 28, height: 28))
        XCTAssertEqual(modeButton.title, "")
        XCTAssertNotNil(modeButton.image)
        XCTAssertEqual(modeButton.toolTip, "Advanced")
        XCTAssertEqual(modeButton.accessibilityLabel(), "Advanced")
        XCTAssertEqual(dismissButton.title, "")
        XCTAssertNotNil(dismissButton.image)
        XCTAssertEqual(dismissButton.toolTip, "Close")
        XCTAssertEqual(dismissButton.accessibilityLabel(), "Close")
        XCTAssertTrue(dismissButton.acceptsFirstMouse(for: nil))

        dismissButton.performClick(nil)
        XCTAssertEqual(dismissalCount, 1)
    }

    @MainActor
    func testNotchRendersEveryProcessAndCommandRow() throws {
        try assertNotchRendersTree(passwordInputVisible: false)
    }

    @MainActor
    func testNotchRendersEveryRowAbovePasswordInput() throws {
        try assertNotchRendersTree(passwordInputVisible: true)
    }

    @MainActor
    private func assertNotchRendersTree(passwordInputVisible: Bool) throws {
        let screen = try XCTUnwrap(NSScreen.screens.first)
        let controller = ProcessNotchController(
            displayMode: .fullTree, displayModeRequestHandler: { _ in }
        )
        defer { controller.hide() }
        var records: [ProcessRecord] = []
        for index in 1...6 {
            let arguments: [String]? = index == 6
                ? ["sudo", "--", "/usr/bin/stat", "/var/root"] : nil
            records.append(ProcessRecord(
                pid: pid_t(index), parentPID: pid_t(index - 1), realUserID: 502,
                name: index == 6 ? "sudo" : "process-\(index)",
                executablePath: index == 6 ? "/usr/bin/sudo" : "/bin/sh",
                startTime: ProcessStartTime(seconds: UInt64(index), microseconds: 0),
                processArguments: arguments
            ))
        }
        let snapshot = ProcessTreeBuilder.build(
            records: records, requesterIdentities: [try XCTUnwrap(records.last).identity],
            requestKind: .sudo, attribution: .heuristicSudo
        )
        if passwordInputVisible {
            controller.presentPasswordEntry(clearExistingInput: true)
        }
        controller.show(snapshot: snapshot, screen: screen, animated: false)
        controller.window?.contentView?.layoutSubtreeIfNeeded()
        controller.window?.displayIfNeeded()

        let rendered = controller.renderedTable
        XCTAssertTrue(rendered.isComplete)
        XCTAssertEqual(rendered.rows, ProcessTablePresentationBuilder.rows(for: snapshot, mode: .fullTree))
        XCTAssertEqual(rendered.rows.count, 7)
        XCTAssertEqual(controller.passwordInputVisible, passwordInputVisible)
    }

    @MainActor
    private func firstSubview<View: NSView>(
        of type: View.Type,
        in root: NSView,
        where predicate: (View) -> Bool = { _ in true }
    ) -> View? {
        if let matchingRoot = root as? View, predicate(matchingRoot) {
            return matchingRoot
        }
        for child in root.subviews {
            if let match = firstSubview(of: type, in: child, where: predicate) {
                return match
            }
        }
        return nil
    }
}

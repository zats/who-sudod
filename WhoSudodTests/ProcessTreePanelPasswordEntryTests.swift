import AppKit
import XCTest
@testable import WhoSudod

final class ProcessTreePanelPasswordEntryTests: XCTestCase {
    @MainActor
    func testVerifiedRequestEnablesInputAndSubmitEndsPresentation() throws {
        let controller = ProcessTreePanelController()
        let request = VerifiedPAMPasswordRequest(id: UUID())
        var submittedRequestID: UUID?
        var submittedPassword: String?

        controller.presentVerifiedPAMPasswordRequest(
            request,
            onPassword: { requestID, password in
                submittedRequestID = requestID
                submittedPassword = password
            },
            onUseTerminal: { _ in
                XCTFail("Submit must not select terminal input")
            }
        )

        XCTAssertTrue(controller.isPresentingVerifiedPAMPasswordRequest)
        XCTAssertTrue(try XCTUnwrap(controller.window).canBecomeKey)

        let contentView = try XCTUnwrap(controller.window?.contentView)
        let passwordField = try XCTUnwrap(firstSubview(of: NSSecureTextField.self, in: contentView))
        let submitButton = try XCTUnwrap(
            firstSubview(
                of: NSButton.self,
                in: contentView,
                where: { $0.title == "Submit" }
            )
        )
        passwordField.stringValue = "test-password"
        submitButton.performClick(nil)

        XCTAssertEqual(submittedRequestID, request.id)
        XCTAssertEqual(submittedPassword, "test-password")
        XCTAssertEqual(passwordField.stringValue, "")
        XCTAssertFalse(controller.isPresentingVerifiedPAMPasswordRequest)
        XCTAssertFalse(try XCTUnwrap(controller.window).canBecomeKey)
    }

    @MainActor
    func testUseTerminalIsDistinctFromPasswordSubmission() throws {
        let controller = ProcessTreePanelController()
        let request = VerifiedPAMPasswordRequest(id: UUID())
        var usedTerminalRequestID: UUID?

        controller.presentVerifiedPAMPasswordRequest(
            request,
            onPassword: { _, _ in
                XCTFail("Terminal selection must not submit a password")
            },
            onUseTerminal: { requestID in
                usedTerminalRequestID = requestID
            }
        )

        let contentView = try XCTUnwrap(controller.window?.contentView)
        let useTerminalButton = try XCTUnwrap(
            firstSubview(
                of: NSButton.self,
                in: contentView,
                where: { $0.title == "Use Terminal" }
            )
        )
        useTerminalButton.performClick(nil)

        XCTAssertEqual(usedTerminalRequestID, request.id)
        XCTAssertFalse(controller.isPresentingVerifiedPAMPasswordRequest)
    }

    @MainActor
    func testInvalidPasswordDoesNotDismissInputOrSubmit() throws {
        let controller = ProcessTreePanelController()
        let request = VerifiedPAMPasswordRequest(id: UUID())
        var submissionCount = 0

        controller.presentVerifiedPAMPasswordRequest(
            request,
            onPassword: { _, _ in submissionCount += 1 },
            onUseTerminal: { _ in XCTFail("Invalid input must keep both options available") }
        )

        let contentView = try XCTUnwrap(controller.window?.contentView)
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
    func testHideClearsPresentationWithoutRespondingToPAM() {
        let controller = ProcessTreePanelController()
        let request = VerifiedPAMPasswordRequest(id: UUID())
        var responseCount = 0

        controller.presentVerifiedPAMPasswordRequest(
            request,
            onPassword: { _, _ in responseCount += 1 },
            onUseTerminal: { _ in responseCount += 1 }
        )
        controller.hide(promptPresent: false, accessibilityTrusted: false)

        XCTAssertEqual(responseCount, 0)
        XCTAssertFalse(controller.isPresentingVerifiedPAMPasswordRequest)
        XCTAssertFalse(controller.window?.canBecomeKey ?? true)
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

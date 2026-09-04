import AppKit
import XCTest
@testable import WhoSudod

final class PAMPasswordEntryViewTests: XCTestCase {
    @MainActor
    func testShowsOnlySecureFieldWithSubmitButtonInsideTrailingEdge() throws {
        let view = PAMPasswordEntryView(
            frame: NSRect(x: 0, y: 0, width: 320, height: 40)
        )
        view.layoutSubtreeIfNeeded()

        let passwordField = try XCTUnwrap(
            firstSubview(of: NSSecureTextField.self, in: view)
        )
        let buttons = subviews(of: NSButton.self, in: view)
        let submitButton = try XCTUnwrap(buttons.first)
        XCTAssertEqual(buttons.map(\.title), ["Submit"])
        XCTAssertEqual(passwordField.layer?.cornerRadius, 0)
        XCTAssertEqual(passwordField.layer?.borderWidth, 0)
        XCTAssertNil(passwordField.layer?.borderColor)
        XCTAssertEqual(passwordField.focusRingType, .none)
        XCTAssertFalse(passwordField.isBezeled)
        XCTAssertFalse(passwordField.isBordered)
        XCTAssertFalse(passwordField.drawsBackground)
        XCTAssertTrue(passwordField.isEditable)
        XCTAssertTrue(passwordField.isSelectable)
        XCTAssertTrue(passwordField.acceptsFirstResponder)
        XCTAssertTrue(passwordField.acceptsFirstMouse(for: nil))
        XCTAssertTrue(passwordField.needsPanelToBecomeKey)

        let submitFrameInField = passwordField.convert(
            submitButton.bounds,
            from: submitButton
        )
        XCTAssertTrue(passwordField.bounds.contains(submitFrameInField))
        let trailingInset = passwordField.bounds.maxX - submitFrameInField.maxX
        XCTAssertGreaterThanOrEqual(trailingInset, 0)
        XCTAssertLessThanOrEqual(trailingInset, 8)

        let textDrawingRect = try XCTUnwrap(passwordField.cell).drawingRect(
            forBounds: passwordField.bounds
        )
        XCTAssertLessThanOrEqual(textDrawingRect.maxX, submitFrameInField.minX)
        XCTAssertGreaterThan(textDrawingRect.minX, passwordField.bounds.minX)
        XCTAssertEqual(
            textDrawingRect.midY,
            passwordField.bounds.midY,
            accuracy: 0.5
        )
        XCTAssertLessThan(textDrawingRect.height, passwordField.bounds.height)

        let textTitleRect = try XCTUnwrap(passwordField.cell).titleRect(
            forBounds: passwordField.bounds
        )
        XCTAssertEqual(
            textTitleRect.midY,
            passwordField.bounds.midY,
            accuracy: 0.5
        )
    }

    @MainActor
    func testSubmitButtonSubmitsAndClearsPassword() throws {
        let view = PAMPasswordEntryView(
            frame: NSRect(x: 0, y: 0, width: 320, height: 40)
        )
        let passwordField = try XCTUnwrap(
            firstSubview(of: NSSecureTextField.self, in: view)
        )
        let submitButton = try XCTUnwrap(firstSubview(of: NSButton.self, in: view))
        var submittedPassword: String?
        view.onSubmit = { submittedPassword = $0 }

        passwordField.stringValue = "button-password"
        submitButton.performClick(nil)

        XCTAssertEqual(submittedPassword, "button-password")
        XCTAssertEqual(passwordField.stringValue, "")
    }

    @MainActor
    func testReturnActionSubmitsAndClearsPassword() throws {
        let view = PAMPasswordEntryView(
            frame: NSRect(x: 0, y: 0, width: 320, height: 40)
        )
        let passwordField = try XCTUnwrap(
            firstSubview(of: NSSecureTextField.self, in: view)
        )
        let submitButton = try XCTUnwrap(firstSubview(of: NSButton.self, in: view))
        var submittedPassword: String?
        view.onSubmit = { submittedPassword = $0 }

        XCTAssertEqual(submitButton.keyEquivalent, "\r")
        passwordField.stringValue = "return-password"
        let action = try XCTUnwrap(passwordField.action)
        let target = try XCTUnwrap(passwordField.target)
        XCTAssertTrue(NSApplication.shared.sendAction(action, to: target, from: passwordField))

        XCTAssertEqual(submittedPassword, "return-password")
        XCTAssertEqual(passwordField.stringValue, "")
    }

    @MainActor
    private func firstSubview<View: NSView>(
        of type: View.Type,
        in root: NSView
    ) -> View? {
        subviews(of: type, in: root).first
    }

    @MainActor
    private func subviews<View: NSView>(
        of type: View.Type,
        in root: NSView
    ) -> [View] {
        var matches = root.subviews.compactMap { $0 as? View }
        for child in root.subviews {
            matches.append(contentsOf: subviews(of: type, in: child))
        }
        return matches
    }
}

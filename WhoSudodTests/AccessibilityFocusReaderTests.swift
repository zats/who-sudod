import XCTest
@testable import WhoSudod

final class AccessibilityFocusReaderTests: XCTestCase {
    func testMainAuthenticationWindowIsActiveWhenAXFocusedIsFalse() {
        XCTAssertEqual(
            AccessibilityWindowFocusResolver.resolve(
                frameMatches: true,
                focused: false,
                main: true,
                frontmost: true
            ),
            true
        )
    }

    func testWindowIsInactiveWhenBothKnownStatesAreFalse() {
        XCTAssertEqual(
            AccessibilityWindowFocusResolver.resolve(
                frameMatches: true,
                focused: false,
                main: false,
                frontmost: true
            ),
            false
        )
    }

    func testUnknownStatesRequireFrontmostFallback() {
        XCTAssertEqual(
            AccessibilityWindowFocusResolver.resolve(
                frameMatches: true,
                focused: nil,
                main: nil,
                frontmost: true
            ),
            true
        )
    }

    func testStaleFrameDuringMoveStaysActiveWhenPresenterIsFrontmost() {
        XCTAssertEqual(
            AccessibilityWindowFocusResolver.resolve(
                frameMatches: false,
                focused: false,
                main: true,
                frontmost: true
            ),
            true
        )
    }

    func testUnknownWindowStateUsesFrontmostPresenterWhenFramesDiffer() {
        XCTAssertEqual(
            AccessibilityWindowFocusResolver.resolve(
                frameMatches: false,
                focused: nil,
                main: nil,
                frontmost: true
            ),
            true
        )
    }

    func testMatchingMainSecureWindowStaysActiveWhenPresenterReportsNotFrontmost() {
        XCTAssertEqual(
            AccessibilityWindowFocusResolver.resolve(
                frameMatches: true,
                focused: true,
                main: true,
                frontmost: false
            ),
            true
        )
    }

    func testMismatchedWindowIsInactiveWhenPresenterIsNotFrontmost() {
        XCTAssertEqual(
            AccessibilityWindowFocusResolver.resolve(
                frameMatches: false,
                focused: true,
                main: true,
                frontmost: false
            ),
            false
        )
    }
}

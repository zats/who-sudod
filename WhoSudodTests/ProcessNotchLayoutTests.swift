import CoreGraphics
import XCTest
@testable import WhoSudod

final class ProcessNotchLayoutTests: XCTestCase {
    func testContentStartsBelowHardwareNotch() {
        let layout = ProcessNotchLayout(
            screenSize: CGSize(width: 1512, height: 982),
            notchSize: CGSize(width: 180, height: 32),
            displayMode: .simple,
            rowCount: 3,
            passwordInputVisible: false
        )

        XCTAssertTrue(layout.hasNotch)
        XCTAssertEqual(layout.topInset, 44)
        XCTAssertEqual(layout.size, CGSize(width: 360, height: 179))
    }

    func testNonNotchedScreenKeepsHeaderControlsAboveContent() {
        let layout = ProcessNotchLayout(
            screenSize: CGSize(width: 1920, height: 1080),
            notchSize: nil,
            displayMode: .simple,
            rowCount: 3,
            passwordInputVisible: false
        )

        XCTAssertFalse(layout.hasNotch)
        XCTAssertEqual(layout.topInset, 44)
        XCTAssertEqual(layout.size, CGSize(width: 360, height: 179))
    }

    func testExpandedModeAddsWidthWithoutChangingHeight() {
        let compact = ProcessNotchLayout(
            screenSize: CGSize(width: 1512, height: 982),
            notchSize: CGSize(width: 180, height: 32),
            displayMode: .simple,
            rowCount: 4,
            passwordInputVisible: false
        )
        let expanded = ProcessNotchLayout(
            screenSize: CGSize(width: 1512, height: 982),
            notchSize: CGSize(width: 180, height: 32),
            displayMode: .fullTree,
            rowCount: 4,
            passwordInputVisible: false
        )

        XCTAssertEqual(compact.size.width, 360)
        XCTAssertEqual(expanded.size.width, 680)
        XCTAssertEqual(compact.size.height, expanded.size.height)
    }

    func testPasswordInputAddsHeightAndMinimumCompactWidth() {
        let withoutPassword = ProcessNotchLayout(
            screenSize: CGSize(width: 1512, height: 982),
            notchSize: CGSize(width: 180, height: 32),
            displayMode: .simple,
            rowCount: 4,
            passwordInputVisible: false
        )
        let withPassword = ProcessNotchLayout(
            screenSize: CGSize(width: 1512, height: 982),
            notchSize: CGSize(width: 180, height: 32),
            displayMode: .simple,
            rowCount: 4,
            passwordInputVisible: true
        )
        let expandedWithPassword = ProcessNotchLayout(
            screenSize: CGSize(width: 1512, height: 982),
            notchSize: CGSize(width: 180, height: 32),
            displayMode: .fullTree,
            rowCount: 4,
            passwordInputVisible: true
        )

        XCTAssertEqual(withPassword.size.width, 360)
        XCTAssertEqual(withPassword.size.height - withoutPassword.size.height, 50)
        XCTAssertEqual(expandedWithPassword.size.width, 680)
        XCTAssertEqual(expandedWithPassword.size.height, withPassword.size.height)
    }

    func testLayoutStaysInsideSmallScreen() {
        let layout = ProcessNotchLayout(
            screenSize: CGSize(width: 320, height: 240),
            notchSize: CGSize(width: 180, height: 32),
            displayMode: .fullTree,
            rowCount: 20,
            passwordInputVisible: true
        )

        XCTAssertEqual(layout.size, CGSize(width: 288, height: 160))
        let body = ProcessNotchBodyLayout(
            size: layout.size,
            topInset: layout.topInset,
            passwordInputVisible: true
        )
        XCTAssertEqual(body.viewport.minY, layout.topInset)
        XCTAssertGreaterThanOrEqual(body.table.height, 59)
        XCTAssertGreaterThan(body.accessory.minY, body.table.maxY)
        XCTAssertGreaterThan(body.documentSize.height, body.viewport.height)
        XCTAssertLessThanOrEqual(body.accessory.maxY, body.documentSize.height)
    }

    func testNormalScreenDoesNotNeedOuterScrolling() {
        let layout = ProcessNotchLayout(
            screenSize: CGSize(width: 1512, height: 982),
            notchSize: CGSize(width: 180, height: 32),
            displayMode: .simple,
            rowCount: 4,
            passwordInputVisible: true
        )
        let body = ProcessNotchBodyLayout(
            size: layout.size,
            topInset: layout.topInset,
            passwordInputVisible: true
        )

        XCTAssertEqual(body.documentSize.height, body.viewport.height)
        XCTAssertGreaterThan(body.accessory.minY, body.table.maxY)
    }

    func testSmallScreenWithoutPasswordKeepsUsableTableViewport() {
        let body = ProcessNotchBodyLayout(
            size: CGSize(width: 288, height: 120),
            topInset: 44,
            passwordInputVisible: false
        )

        XCTAssertEqual(body.table.height, 68)
        XCTAssertEqual(body.documentSize.height, body.viewport.height)
    }

    func testEmptyTreeKeepsOneRowOfSpace() {
        let empty = ProcessNotchLayout(
            screenSize: CGSize(width: 1920, height: 1080),
            notchSize: nil,
            displayMode: .simple,
            rowCount: 0,
            passwordInputVisible: false
        )
        let oneRow = ProcessNotchLayout(
            screenSize: CGSize(width: 1920, height: 1080),
            notchSize: nil,
            displayMode: .simple,
            rowCount: 1,
            passwordInputVisible: false
        )

        XCTAssertEqual(empty, oneRow)
        XCTAssertEqual(empty.size.height, 117)
    }

    func testPAMSetupActionUsesOneButtonRow() {
        let withoutAction = ProcessNotchLayout(
            screenSize: CGSize(width: 1512, height: 982),
            notchSize: CGSize(width: 180, height: 32),
            displayMode: .simple,
            rowCount: 4,
            passwordInputVisible: false
        )
        let withAction = ProcessNotchLayout(
            screenSize: CGSize(width: 1512, height: 982),
            notchSize: CGSize(width: 180, height: 32),
            displayMode: .simple,
            rowCount: 4,
            passwordInputVisible: false,
            pamActionVisible: true
        )

        XCTAssertEqual(withAction.size.height - withoutAction.size.height, 44)

        let body = ProcessNotchBodyLayout(
            size: withAction.size,
            topInset: withAction.topInset,
            passwordInputVisible: false,
            pamActionVisible: true
        )
        XCTAssertEqual(body.accessory.height, 38)
        XCTAssertGreaterThan(body.accessory.minY, body.table.maxY)
    }
}

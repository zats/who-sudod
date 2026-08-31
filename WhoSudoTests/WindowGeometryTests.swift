import CoreGraphics
import XCTest
@testable import WhoSudo

final class WindowGeometryTests: XCTestCase {
    func testEnvelopeCornerRadiusAddsDialogPadding() {
        XCTAssertEqual(AuthorizationPanelMetrics.systemDialogCornerRadius, 26)
        XCTAssertEqual(AuthorizationPanelMetrics.dialogPadding, 20)
        XCTAssertEqual(AuthorizationPanelMetrics.envelopeCornerRadius, 46)
    }

    func testConvertsMainDisplayCoordinatesToAppKit() throws {
        let display = DisplayGeometry(
            appKitFrame: CGRect(x: 0, y: 0, width: 1920, height: 1080),
            visibleFrame: CGRect(x: 0, y: 24, width: 1920, height: 1056),
            coreGraphicsFrame: CGRect(x: 0, y: 0, width: 1920, height: 1080)
        )

        let result = try XCTUnwrap(
            WindowGeometry.convert(
                coreGraphicsFrame: CGRect(x: 100, y: 200, width: 260, height: 337),
                displays: [display]
            )
        )

        XCTAssertEqual(result.frame, CGRect(x: 100, y: 543, width: 260, height: 337))
        XCTAssertEqual(result.visibleFrame, display.visibleFrame)
    }

    func testConvertsOffsetSecondaryDisplayCoordinates() throws {
        let display = DisplayGeometry(
            appKitFrame: CGRect(x: 1920, y: -44, width: 1280, height: 1024),
            visibleFrame: CGRect(x: 1920, y: -20, width: 1280, height: 1000),
            coreGraphicsFrame: CGRect(x: 1920, y: 100, width: 1280, height: 1024)
        )

        let result = try XCTUnwrap(
            WindowGeometry.convert(
                coreGraphicsFrame: CGRect(x: 2000, y: 150, width: 260, height: 300),
                displays: [display]
            )
        )

        XCTAssertEqual(result.frame, CGRect(x: 2000, y: 630, width: 260, height: 300))
    }

    func testPlacesSidecarOnRightWithTwentyPointEnvelope() {
        let result = WindowGeometry.sidecarFrame(
            authenticationFrame: CGRect(x: 800, y: 500, width: 260, height: 337),
            visibleFrame: CGRect(x: 0, y: 24, width: 1920, height: 1056)
        )

        XCTAssertEqual(result.side, .right)
        XCTAssertEqual(result.reservedDialogWidth, 300)
        XCTAssertEqual(result.frame, CGRect(x: 780, y: 480, width: 940, height: 377))
    }

    func testPlacesSidecarOnLeftNearRightEdge() {
        let result = WindowGeometry.sidecarFrame(
            authenticationFrame: CGRect(x: 900, y: 300, width: 260, height: 337),
            visibleFrame: CGRect(x: 0, y: 24, width: 1280, height: 776)
        )

        XCTAssertEqual(result.side, .left)
        XCTAssertEqual(result.frame, CGRect(x: 240, y: 280, width: 940, height: 377))
    }

    func testReducesWidthWhenNeitherSideFitsDesiredWidth() {
        let result = WindowGeometry.sidecarFrame(
            authenticationFrame: CGRect(x: 510, y: 300, width: 260, height: 337),
            visibleFrame: CGRect(x: 0, y: 24, width: 1280, height: 776)
        )

        XCTAssertEqual(result.side, .right)
        XCTAssertEqual(result.frame, CGRect(x: 490, y: 280, width: 782, height: 377))
    }
}

import CoreGraphics
import XCTest
@testable import WhoSudod

final class WindowGeometryTests: XCTestCase {
    func testEnvelopeCornerRadiusAddsDialogPadding() {
        XCTAssertEqual(AuthorizationPanelMetrics.systemDialogCornerRadius, 26)
        XCTAssertEqual(AuthorizationPanelMetrics.dialogPadding, 20)
        XCTAssertEqual(AuthorizationPanelMetrics.envelopeCornerRadius, 46)
        XCTAssertEqual(ProcessPanelMetrics.regularWindowCornerRadius, 12)
        XCTAssertEqual(
            ProcessPanelMetrics.modeControlWindowMargin,
            ProcessPanelMetrics.modeControlDiameter / 2
        )
    }

    func testPlacementSelectsCornerRadiusForItsHostWindow() {
        let frame = CGRect(x: 100, y: 100, width: 400, height: 300)
        let visibleFrame = CGRect(x: 0, y: 24, width: 1920, height: 1056)

        let authentication = ProcessPanelPlacement.authentication(
            frame: frame,
            visibleFrame: visibleFrame
        )
        let standalone = ProcessPanelPlacement.standalone(
            anchorFrame: frame,
            visibleFrame: visibleFrame
        )

        XCTAssertEqual(
            authentication.materialCornerRadius,
            AuthorizationPanelMetrics.envelopeCornerRadius
        )
        XCTAssertEqual(
            standalone.materialCornerRadius,
            ProcessPanelMetrics.regularWindowCornerRadius
        )
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
        XCTAssertEqual(result.frame, CGRect(x: 780, y: 480, width: 954, height: 377))
    }

    func testPlacesSidecarOnLeftNearRightEdge() {
        let result = WindowGeometry.sidecarFrame(
            authenticationFrame: CGRect(x: 900, y: 300, width: 260, height: 337),
            visibleFrame: CGRect(x: 0, y: 24, width: 1280, height: 776)
        )

        XCTAssertEqual(result.side, .left)
        XCTAssertEqual(result.frame, CGRect(x: 226, y: 280, width: 954, height: 377))
    }

    func testReducesWidthWhenNeitherSideFitsDesiredWidth() {
        let result = WindowGeometry.sidecarFrame(
            authenticationFrame: CGRect(x: 510, y: 300, width: 260, height: 337),
            visibleFrame: CGRect(x: 0, y: 24, width: 1280, height: 776)
        )

        XCTAssertEqual(result.side, .right)
        XCTAssertEqual(result.frame, CGRect(x: 490, y: 280, width: 782, height: 377))
    }

    func testStandaloneSidecarUsesNoDialogReservation() {
        let result = WindowGeometry.standaloneSidecarFrame(
            anchorFrame: CGRect(x: 100, y: 100, width: 600, height: 600),
            visibleFrame: CGRect(x: 0, y: 24, width: 1920, height: 1056),
            displayMode: .fullTree
        )

        XCTAssertEqual(result.side, .right)
        XCTAssertEqual(result.reservedDialogWidth, 0)
        XCTAssertEqual(result.frame.minX, 708)
        XCTAssertEqual(result.frame.height, 320)
    }

    func testStandaloneSidecarUsesLeftSideNearRightScreenEdge() {
        let anchor = CGRect(x: 1400, y: 100, width: 500, height: 600)
        let result = WindowGeometry.standaloneSidecarFrame(
            anchorFrame: anchor,
            visibleFrame: CGRect(x: 0, y: 24, width: 1920, height: 1056),
            displayMode: .fullTree
        )

        XCTAssertEqual(result.side, .left)
        XCTAssertEqual(result.frame.maxX, anchor.minX - 8)
        XCTAssertEqual(result.reservedDialogWidth, 0)
    }

    func testStandaloneSidecarFallsBackInsideAFullScreenAnchor() {
        let visibleFrame = CGRect(x: 0, y: 24, width: 1280, height: 776)
        let simple = WindowGeometry.standaloneSidecarFrame(
            anchorFrame: visibleFrame,
            visibleFrame: visibleFrame,
            displayMode: .simple
        )
        let advanced = WindowGeometry.standaloneSidecarFrame(
            anchorFrame: visibleFrame,
            visibleFrame: visibleFrame,
            displayMode: .fullTree
        )

        XCTAssertTrue(visibleFrame.contains(simple.frame))
        XCTAssertTrue(visibleFrame.contains(advanced.frame))
        XCTAssertLessThan(simple.frame.width, advanced.frame.width)
        XCTAssertEqual(simple.reservedDialogWidth, 0)
        XCTAssertEqual(advanced.reservedDialogWidth, 0)
    }

    func testStandaloneSideChangeRetractsBeforeMoving() throws {
        let source = SidecarGeometry(
            frame: CGRect(x: 700, y: 200, width: 230, height: 320),
            side: .right,
            reservedDialogWidth: 0
        )
        let destination = SidecarGeometry(
            frame: CGRect(x: 40, y: 200, width: 654, height: 320),
            side: .left,
            reservedDialogWidth: 0
        )

        let transition = WindowGeometry.standaloneTransition(
            from: source,
            to: destination
        )
        let departure = try XCTUnwrap(transition.departureBridge)
        let arrival = try XCTUnwrap(transition.arrivalBridge)

        XCTAssertEqual(departure.side, .right)
        XCTAssertEqual(departure.frame.minX, source.frame.minX)
        XCTAssertLessThan(departure.frame.width, source.frame.width)
        XCTAssertEqual(arrival.side, .left)
        XCTAssertEqual(arrival.frame.maxX, destination.frame.maxX)
        XCTAssertLessThan(arrival.frame.width, destination.frame.width)
        XCTAssertEqual(departure.reservedDialogWidth, 0)
        XCTAssertEqual(arrival.reservedDialogWidth, 0)
    }

    func testSimpleTableWidthIsThirtyPercentOfAdvancedTableWidthOnRight() {
        let authenticationFrame = CGRect(x: 800, y: 500, width: 260, height: 337)
        let visibleFrame = CGRect(x: 0, y: 24, width: 1920, height: 1056)
        let advanced = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame,
            displayMode: .fullTree
        )
        let simple = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame,
            displayMode: .simple
        )

        let advancedTableWidth = tableWidth(in: advanced)
        let simpleTableWidth = tableWidth(in: simple)
        XCTAssertEqual(
            simpleTableWidth,
            advancedTableWidth * ProcessPanelMetrics.simpleTableWidthFraction,
            accuracy: 0.001
        )
        XCTAssertEqual(simple.frame.minX, advanced.frame.minX, accuracy: 0.001)
        XCTAssertEqual(simple.side, .right)
        XCTAssertEqual(advanced.side, .right)
    }

    func testSimpleAndAdvancedWidthsKeepTheSameLeftAttachment() {
        let authenticationFrame = CGRect(x: 900, y: 300, width: 260, height: 337)
        let visibleFrame = CGRect(x: 0, y: 24, width: 1280, height: 776)
        let advanced = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame,
            displayMode: .fullTree
        )
        let simple = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame,
            displayMode: .simple
        )

        XCTAssertEqual(
            tableWidth(in: simple),
            tableWidth(in: advanced) * ProcessPanelMetrics.simpleTableWidthFraction,
            accuracy: 0.001
        )
        XCTAssertEqual(simple.frame.maxX, advanced.frame.maxX, accuracy: 0.001)
        XCTAssertEqual(simple.side, .left)
        XCTAssertEqual(advanced.side, .left)
    }

    func testModeControlGutterStaysInsideBothVisibleScreenEdges() {
        let visibleFrame = CGRect(x: 0, y: 24, width: 1280, height: 776)
        let right = WindowGeometry.sidecarFrame(
            authenticationFrame: CGRect(x: 350, y: 300, width: 260, height: 337),
            visibleFrame: visibleFrame,
            displayMode: .fullTree
        )
        let left = WindowGeometry.sidecarFrame(
            authenticationFrame: CGRect(x: 670, y: 300, width: 260, height: 337),
            visibleFrame: visibleFrame,
            displayMode: .fullTree
        )

        XCTAssertEqual(right.side, .right)
        XCTAssertEqual(right.frame.maxX, visibleFrame.maxX - 8, accuracy: 0.001)
        XCTAssertEqual(left.side, .left)
        XCTAssertEqual(left.frame.minX, visibleFrame.minX + 8, accuracy: 0.001)
    }

    func testSimpleUsesItsCurrentWidthAndAdvancedMovesToTheSideThatFits() {
        let authenticationFrame = CGRect(x: 700, y: 300, width: 260, height: 337)
        let visibleFrame = CGRect(x: 0, y: 24, width: 1280, height: 776)
        let simple = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame,
            displayMode: .simple
        )
        let advanced = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame,
            displayMode: .fullTree
        )

        XCTAssertEqual(simple.side, .right)
        XCTAssertEqual(
            tableWidth(in: simple),
            (ProcessPanelMetrics.advancedContentWidth
                - 2 * ProcessPanelMetrics.tableHorizontalInset)
                * ProcessPanelMetrics.simpleTableWidthFraction,
            accuracy: 0.001
        )
        XCTAssertEqual(advanced.side, .left)
        XCTAssertGreaterThanOrEqual(advanced.frame.minX, visibleFrame.minX + 8)
        XCTAssertLessThanOrEqual(advanced.frame.maxX, visibleFrame.maxX - 8)
    }

    func testSameSideTransitionNeedsNoBridge() {
        let authenticationFrame = CGRect(x: 800, y: 500, width: 260, height: 337)
        let visibleFrame = CGRect(x: 0, y: 24, width: 1920, height: 1056)
        let simple = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame,
            displayMode: .simple
        )
        let advanced = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame,
            displayMode: .fullTree
        )

        let transition = WindowGeometry.transition(
            from: simple,
            to: advanced,
            authenticationFrame: authenticationFrame
        )

        XCTAssertEqual(transition.destination, advanced)
        XCTAssertNil(transition.departureBridge)
        XCTAssertNil(transition.arrivalBridge)
    }

    func testSideChangingTransitionRetractsBeforeMovingToTheOtherSide() throws {
        let authenticationFrame = CGRect(x: 700, y: 300, width: 260, height: 337)
        let visibleFrame = CGRect(x: 0, y: 24, width: 1280, height: 776)
        let simple = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame,
            displayMode: .simple
        )
        let advanced = WindowGeometry.sidecarFrame(
            authenticationFrame: authenticationFrame,
            visibleFrame: visibleFrame,
            displayMode: .fullTree
        )

        let transition = WindowGeometry.transition(
            from: simple,
            to: advanced,
            authenticationFrame: authenticationFrame
        )
        let departure = try XCTUnwrap(transition.departureBridge)
        let arrival = try XCTUnwrap(transition.arrivalBridge)

        XCTAssertEqual(departure.side, .right)
        XCTAssertEqual(arrival.side, .left)
        XCTAssertEqual(departure.frame.size, arrival.frame.size)
        XCTAssertEqual(
            WindowGeometry.contentWidth(in: departure),
            2 * ProcessPanelMetrics.tableHorizontalInset,
            accuracy: 0.001
        )
        XCTAssertEqual(
            WindowGeometry.contentWidth(in: arrival),
            2 * ProcessPanelMetrics.tableHorizontalInset,
            accuracy: 0.001
        )
        XCTAssertEqual(
            departure.frame.minX,
            authenticationFrame.minX - AuthorizationPanelMetrics.dialogPadding,
            accuracy: 0.001
        )
        XCTAssertEqual(
            arrival.frame.maxX,
            authenticationFrame.maxX + AuthorizationPanelMetrics.dialogPadding,
            accuracy: 0.001
        )
        XCTAssertEqual(transition.destination, advanced)
    }

    private func tableWidth(in geometry: SidecarGeometry) -> CGFloat {
        geometry.frame.width
            - ProcessPanelMetrics.modeControlWindowMargin
            - geometry.reservedDialogWidth
            - 2 * ProcessPanelMetrics.tableHorizontalInset
    }
}

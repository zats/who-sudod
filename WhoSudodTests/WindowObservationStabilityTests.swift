import XCTest
@testable import WhoSudod

final class WindowObservationStabilityTests: XCTestCase {
    func testRequiresThreeConsecutiveMisses() {
        var stability = WindowObservationStability(requiredMisses: 3)

        XCTAssertFalse(stability.recordMiss())
        XCTAssertFalse(stability.recordMiss())
        XCTAssertTrue(stability.recordMiss())
    }

    func testConfirmationClearsTransientMisses() {
        var stability = WindowObservationStability(requiredMisses: 3)

        XCTAssertFalse(stability.recordMiss())
        XCTAssertFalse(stability.recordMiss())
        stability.recordConfirmation()

        XCTAssertFalse(stability.recordMiss())
        XCTAssertEqual(stability.consecutiveMisses, 1)
    }
}

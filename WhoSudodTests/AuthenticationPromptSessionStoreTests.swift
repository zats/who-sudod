import CoreGraphics
import XCTest
@testable import WhoSudod

final class AuthenticationPromptSessionStoreTests: XCTestCase {
    func testRestoresEachPromptSnapshotWhenFocusReturns() throws {
        var store = AuthenticationPromptSessionStore()
        let first = window(id: 44)
        let second = window(id: 45)
        let firstDate = Date(timeIntervalSince1970: 100)
        let secondDate = firstDate.addingTimeInterval(1)

        let firstSession = store.activate(window: first, at: firstDate)
        store.update(window: first, processSnapshot: .empty, at: firstDate)
        let secondSession = store.activate(window: second, at: secondDate)
        store.update(window: second, processSnapshot: .unavailable, at: secondDate)

        let restoredFirst = store.activate(
            window: first,
            at: secondDate.addingTimeInterval(1)
        )
        let restoredSecond = store.activate(
            window: second,
            at: secondDate.addingTimeInterval(2)
        )

        XCTAssertNotEqual(firstSession.promptSequence, secondSession.promptSequence)
        XCTAssertEqual(restoredFirst.promptSequence, firstSession.promptSequence)
        XCTAssertEqual(restoredFirst.firstSeenAt, firstDate)
        XCTAssertEqual(restoredFirst.processSnapshot, .empty)
        XCTAssertEqual(restoredSecond.promptSequence, secondSession.promptSequence)
        XCTAssertEqual(restoredSecond.processSnapshot, .unavailable)
    }

    func testKeepsSameSizeWindowsFromOnePresenterSeparate() {
        var store = AuthenticationPromptSessionStore()
        let first = window(id: 44)
        let second = window(id: 45)

        store.update(window: first, processSnapshot: .empty, at: .distantPast)
        store.update(window: second, processSnapshot: .unavailable, at: .distantFuture)

        XCTAssertEqual(store.sessions.count, 2)
        XCTAssertEqual(store.session(for: first)?.processSnapshot, .empty)
        XCTAssertEqual(store.session(for: second)?.processSnapshot, .unavailable)
    }

    func testTransfersHistoryAcrossCoreGraphicsAndAccessibilityRepresentations() {
        var store = AuthenticationPromptSessionStore()
        let coreGraphics = window(id: 44)
        let accessibility = window(identity: .accessibility(processID: 321))
        let date = Date(timeIntervalSince1970: 100)

        let original = store.activate(window: coreGraphics, at: date)
        store.update(window: coreGraphics, processSnapshot: .empty, at: date)
        let transferred = store.transfer(
            from: coreGraphics,
            to: accessibility,
            at: date.addingTimeInterval(1)
        )

        XCTAssertEqual(store.sessions.count, 1)
        XCTAssertNil(store.session(for: coreGraphics))
        XCTAssertEqual(transferred.promptSequence, original.promptSequence)
        XCTAssertEqual(transferred.processSnapshot, .empty)
        XCTAssertEqual(store.session(for: accessibility), transferred)
    }

    func testTransferDoesNotOverwriteExistingDestinationHistory() {
        var store = AuthenticationPromptSessionStore()
        let coreGraphics = window(id: 44)
        let accessibility = window(identity: .accessibility(processID: 321))
        store.update(window: coreGraphics, processSnapshot: .empty, at: .distantPast)
        let destination = store.activate(window: accessibility, at: .distantFuture)
        store.update(
            window: accessibility,
            processSnapshot: .unavailable,
            at: .distantFuture
        )

        let transferred = store.transfer(
            from: coreGraphics,
            to: accessibility,
            at: Date()
        )

        XCTAssertEqual(transferred.promptSequence, destination.promptSequence)
        XCTAssertEqual(transferred.processSnapshot, .unavailable)
        XCTAssertEqual(store.session(for: coreGraphics)?.processSnapshot, .empty)
        XCTAssertEqual(store.session(for: accessibility)?.processSnapshot, .unavailable)
    }

    func testDoesNotRestoreReusedWindowIDFromAnotherPresenterProcess() {
        var store = AuthenticationPromptSessionStore()
        let original = window(id: 44, processID: 321)
        let reused = window(id: 44, processID: 654)

        let originalSession = store.activate(window: original, at: .distantPast)
        let reusedSession = store.activate(window: reused, at: .distantFuture)

        XCTAssertNotEqual(originalSession.promptSequence, reusedSession.promptSequence)
        XCTAssertEqual(store.sessions.count, 2)
    }

    func testRemovesClosedCoreGraphicsSessionAfterConfirmedMissingObservations() {
        var store = AuthenticationPromptSessionStore()
        let original = window(id: 44)
        let firstSession = store.activate(window: original, at: .distantPast)
        store.update(window: original, processSnapshot: .empty, at: .distantPast)

        store.observeVisibleCoreGraphicsWindows([], at: Date(timeIntervalSince1970: 1))
        store.observeVisibleCoreGraphicsWindows([], at: Date(timeIntervalSince1970: 2))
        XCTAssertEqual(store.session(for: original)?.processSnapshot, .empty)

        store.observeVisibleCoreGraphicsWindows([], at: Date(timeIntervalSince1970: 3))
        XCTAssertNil(store.session(for: original))

        let reusedSession = store.activate(
            window: original,
            at: Date(timeIntervalSince1970: 4)
        )
        XCTAssertNotEqual(reusedSession.promptSequence, firstSession.promptSequence)
        XCTAssertEqual(reusedSession.processSnapshot, .pending)
    }

    func testVisibleObservationResetsMissingWindowConfirmation() {
        var store = AuthenticationPromptSessionStore()
        let window = window(id: 44)
        _ = store.activate(window: window, at: .distantPast)

        store.observeVisibleCoreGraphicsWindows([], at: Date(timeIntervalSince1970: 1))
        store.observeVisibleCoreGraphicsWindows([window], at: Date(timeIntervalSince1970: 2))
        store.observeVisibleCoreGraphicsWindows([], at: Date(timeIntervalSince1970: 3))
        store.observeVisibleCoreGraphicsWindows([], at: Date(timeIntervalSince1970: 4))

        XCTAssertNotNil(store.session(for: window))
    }

    func testKeepsBackgroundAccessibilitySessionAndRemovesItAfterWindowCloses() {
        var store = AuthenticationPromptSessionStore()
        let window = window(identity: .accessibility(processID: 321))
        store.update(window: window, processSnapshot: .empty, at: .distantPast)

        XCTAssertEqual(store.accessibilityWindowIdentities, [window.identity])
        store.observeVisibleAccessibilityWindows([window], at: Date(timeIntervalSince1970: 1))
        store.observeVisibleAccessibilityWindows([], at: Date(timeIntervalSince1970: 2))
        store.observeVisibleAccessibilityWindows([], at: Date(timeIntervalSince1970: 3))
        XCTAssertEqual(store.session(for: window)?.processSnapshot, .empty)

        store.observeVisibleAccessibilityWindows([], at: Date(timeIntervalSince1970: 4))
        XCTAssertNil(store.session(for: window))
    }

    private func window(
        id: CGWindowID,
        processID: pid_t = 321
    ) -> AuthenticationWindowSnapshot {
        window(identity: .coreGraphics(id), processID: processID)
    }

    private func window(
        identity: AuthenticationWindowIdentity,
        processID: pid_t = 321
    ) -> AuthenticationWindowSnapshot {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        return AuthenticationWindowSnapshot(
            identity: identity,
            processID: processID,
            surfaceKind: .securityAgent,
            coreGraphicsFrame: frame,
            frame: frame,
            visibleFrame: CGRect(x: 0, y: 24, width: 1920, height: 1056)
        )
    }
}

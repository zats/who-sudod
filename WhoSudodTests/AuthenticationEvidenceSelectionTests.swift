import Darwin
import Foundation
import XCTest
@testable import WhoSudod

final class AuthenticationEvidenceSelectionTests: XCTestCase {
    func testSecurityAgentPrefersAuthorizationEvidence() throws {
        let firstSeenAt = Date(timeIntervalSince1970: 100)
        let localAuthentication = event(
            pid: 200,
            at: firstSeenAt,
            source: .localAuthentication
        )
        let authorization = event(
            pid: 300,
            at: firstSeenAt.addingTimeInterval(-2),
            source: .authorization
        )

        let selected = AuthenticationEvidenceSelection.rankedEvents(
            from: [localAuthentication, authorization],
            surfaceKind: .securityAgent,
            firstSeenAt: firstSeenAt,
            now: firstSeenAt.addingTimeInterval(1)
        ).first

        XCTAssertEqual(try XCTUnwrap(selected).processID, 300)
        XCTAssertEqual(selected?.source, .authorization)
    }

    func testLocalAuthenticationSurfaceUsesOnlyLocalAuthenticationEvidence() throws {
        let firstSeenAt = Date(timeIntervalSince1970: 100)
        let authorization = event(
            pid: 300,
            at: firstSeenAt,
            source: .authorization
        )
        let localAuthentication = event(
            pid: 200,
            at: firstSeenAt.addingTimeInterval(-1),
            source: .localAuthentication
        )

        let selected = AuthenticationEvidenceSelection.rankedEvents(
            from: [authorization, localAuthentication],
            surfaceKind: .localAuthentication,
            firstSeenAt: firstSeenAt,
            now: firstSeenAt.addingTimeInterval(1)
        ).first

        XCTAssertEqual(try XCTUnwrap(selected).processID, 200)
        XCTAssertNil(
            AuthenticationEvidenceSelection.rankedEvents(
                from: [authorization],
                surfaceKind: .localAuthentication,
                firstSeenAt: firstSeenAt,
                now: firstSeenAt.addingTimeInterval(1)
            ).first
        )
    }

    func testRejectsEvidenceOutsideLeadAndObservationWindow() throws {
        let firstSeenAt = Date(timeIntervalSince1970: 100)
        let stale = event(
            pid: 100,
            at: firstSeenAt.addingTimeInterval(-3.001),
            source: .localAuthentication
        )
        let eligible = event(
            pid: 200,
            at: firstSeenAt.addingTimeInterval(-2.999),
            source: .localAuthentication
        )
        let future = event(
            pid: 300,
            at: firstSeenAt.addingTimeInterval(1.001),
            source: .localAuthentication
        )

        let selected = AuthenticationEvidenceSelection.rankedEvents(
            from: [stale, eligible, future],
            surfaceKind: .localAuthentication,
            firstSeenAt: firstSeenAt,
            now: firstSeenAt.addingTimeInterval(1),
            maximumLeadTime: 3
        ).first

        XCTAssertEqual(try XCTUnwrap(selected).processID, 200)
    }

    func testChoosesClosestEventAndUsesNewerEventForDistanceTie() throws {
        let firstSeenAt = Date(timeIntervalSince1970: 100)
        let older = event(
            pid: 200,
            at: firstSeenAt.addingTimeInterval(-1),
            source: .localAuthentication
        )
        let newer = event(
            pid: 300,
            at: firstSeenAt.addingTimeInterval(1),
            source: .localAuthentication
        )

        let selected = AuthenticationEvidenceSelection.rankedEvents(
            from: [older, newer],
            surfaceKind: .localAuthentication,
            firstSeenAt: firstSeenAt,
            now: firstSeenAt.addingTimeInterval(2)
        ).first

        XCTAssertEqual(try XCTUnwrap(selected).processID, 300)
    }

    func testSecurityAgentRejectsLocalAuthenticationEvidence() {
        let firstSeenAt = Date(timeIntervalSince1970: 100)
        let authorization = event(
            pid: 300,
            at: firstSeenAt.addingTimeInterval(-2),
            source: .authorization
        )
        let localAuthentication = event(
            pid: 200,
            at: firstSeenAt,
            source: .localAuthentication
        )

        let ranked = AuthenticationEvidenceSelection.rankedEvents(
            from: [localAuthentication, authorization],
            surfaceKind: .securityAgent,
            firstSeenAt: firstSeenAt,
            now: firstSeenAt.addingTimeInterval(1)
        )

        XCTAssertEqual(ranked.map(\.processID), [300])
    }

    func testReturnsNoEvidenceWhenAllEventsAreStaleOrFuture() {
        let firstSeenAt = Date(timeIntervalSince1970: 100)
        let ranked = AuthenticationEvidenceSelection.rankedEvents(
            from: [
                event(
                    pid: 200,
                    at: firstSeenAt.addingTimeInterval(-5.001),
                    source: .localAuthentication
                ),
                event(
                    pid: 300,
                    at: firstSeenAt.addingTimeInterval(2),
                    source: .localAuthentication
                )
            ],
            surfaceKind: .localAuthentication,
            firstSeenAt: firstSeenAt,
            now: firstSeenAt.addingTimeInterval(1)
        )

        XCTAssertTrue(ranked.isEmpty)
    }

    func testRejectsEventLongAfterPromptDiscovery() {
        let firstSeenAt = Date(timeIntervalSince1970: 100)
        let ranked = AuthenticationEvidenceSelection.rankedEvents(
            from: [
                event(
                    pid: 200,
                    at: firstSeenAt.addingTimeInterval(3.001),
                    source: .localAuthentication
                )
            ],
            surfaceKind: .localAuthentication,
            firstSeenAt: firstSeenAt,
            now: firstSeenAt.addingTimeInterval(20),
            maximumLagTime: 3
        )

        XCTAssertTrue(ranked.isEmpty)
    }

    func testAllowsLocalAuthenticationEventBeforeDelayedPresentation() throws {
        let firstSeenAt = Date(timeIntervalSince1970: 100)
        let delayedPresentationEvent = event(
            pid: 200,
            at: firstSeenAt.addingTimeInterval(-4.5),
            source: .localAuthentication
        )

        let selected = AuthenticationEvidenceSelection.rankedEvents(
            from: [delayedPresentationEvent],
            surfaceKind: .localAuthentication,
            firstSeenAt: firstSeenAt,
            now: firstSeenAt
        ).first

        XCTAssertEqual(try XCTUnwrap(selected).processID, 200)
    }

    func testSecurityAgentKeepsShorterDefaultLeadWindow() {
        let firstSeenAt = Date(timeIntervalSince1970: 100)
        let ranked = AuthenticationEvidenceSelection.rankedEvents(
            from: [
                event(
                    pid: 200,
                    at: firstSeenAt.addingTimeInterval(-3.001),
                    source: .authorization
                )
            ],
            surfaceKind: .securityAgent,
            firstSeenAt: firstSeenAt,
            now: firstSeenAt
        )

        XCTAssertTrue(ranked.isEmpty)
    }

    private func event(
        pid: pid_t,
        at date: Date,
        source: AuthenticationEventSource
    ) -> AuthenticationClientEvent {
        AuthenticationClientEvent(
            processID: pid,
            executablePath: source == .localAuthentication ? "/tmp/Client" : nil,
            receivedAt: date,
            source: source
        )
    }
}

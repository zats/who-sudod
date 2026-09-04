import Darwin
import Foundation
import XCTest
@testable import WhoSudod

final class AuthenticationEvidenceSelectionTests: XCTestCase {
    func testNewBeginClearsOrphanedCompletionForReusedIdentifier() {
        let identifier = AuthenticationRequestIdentifier.authorization(
            authdProcessID: 100,
            engineID: 1
        )
        var completions = [identifier: Date(timeIntervalSince1970: 100)]

        AuthenticationCompletionHistory.recordBegin(
            identifier,
            in: &completions
        )

        XCTAssertNil(completions[identifier])
    }

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

final class AuthenticationRequestAssociationTests: XCTestCase {
    func testSelectsOnlyUnassignedActiveIdentifierForRequester() throws {
        let promptKey = self.promptKey(id: 10)
        let identifier = self.identifier(clientID: 1)

        let selected = AuthenticationRequestAssociation.unassignedActiveIdentifier(
            requesterProcessID: 200,
            evidence: [event(pid: 200, identifier: identifier)],
            completedIdentifiers: [],
            existingMappings: [:],
            promptKey: promptKey
        )

        XCTAssertEqual(try XCTUnwrap(selected), identifier)
    }

    func testRejectsIdentifierThatCompletedWhileScanWasRunning() {
        let promptKey = self.promptKey(id: 10)
        let identifier = self.identifier(clientID: 1)

        XCTAssertNil(
            AuthenticationRequestAssociation.unassignedActiveIdentifier(
                requesterProcessID: 200,
                evidence: [event(pid: 200, identifier: identifier)],
                completedIdentifiers: [identifier],
                existingMappings: [:],
                promptKey: promptKey
            )
        )
    }

    func testAssociatesOnlyCompletedIdentifierWhenScanFinishesAfterRequest() throws {
        let promptKey = self.promptKey(id: 10)
        let identifier = self.identifier(clientID: 1)

        let selected = AuthenticationRequestAssociation.unassignedCompletedIdentifier(
            requesterProcessID: 200,
            evidence: [event(pid: 200, identifier: identifier)],
            currentEvidence: [],
            completedIdentifiers: [identifier],
            existingMappings: [:],
            promptKey: promptKey
        )

        XCTAssertEqual(try XCTUnwrap(selected), identifier)
    }

    func testDoesNotAssociateCompletedIdentifierWhenAnotherRequestIsActive() {
        let promptKey = self.promptKey(id: 10)
        let completedIdentifier = self.identifier(clientID: 1)
        let activeIdentifier = self.identifier(clientID: 2)

        XCTAssertNil(
            AuthenticationRequestAssociation.unassignedCompletedIdentifier(
                requesterProcessID: 200,
                evidence: [
                    event(pid: 200, identifier: completedIdentifier),
                    event(pid: 200, identifier: activeIdentifier)
                ],
                currentEvidence: [
                    event(pid: 200, identifier: activeIdentifier)
                ],
                completedIdentifiers: [completedIdentifier],
                existingMappings: [:],
                promptKey: promptKey
            )
        )
    }

    func testDoesNotAssociateCompletedRequestWhenReplacementBeganDuringScan() {
        let promptKey = self.promptKey(id: 10)
        let completedIdentifier = self.identifier(clientID: 1)
        let replacementIdentifier = self.identifier(clientID: 2)

        XCTAssertNil(
            AuthenticationRequestAssociation.unassignedCompletedIdentifier(
                requesterProcessID: 200,
                evidence: [
                    event(pid: 200, identifier: completedIdentifier)
                ],
                currentEvidence: [
                    event(pid: 200, identifier: replacementIdentifier)
                ],
                completedIdentifiers: [completedIdentifier],
                existingMappings: [:],
                promptKey: promptKey
            )
        )
    }

    func testDoesNotAssociateCompletedRequestWhenReplacementHasNoLifecycleIdentifier() {
        let promptKey = self.promptKey(id: 10)
        let completedIdentifier = self.identifier(clientID: 1)

        XCTAssertNil(
            AuthenticationRequestAssociation.unassignedCompletedIdentifier(
                requesterProcessID: 200,
                evidence: [
                    event(pid: 200, identifier: completedIdentifier)
                ],
                currentEvidence: [
                    event(pid: 200, identifier: nil)
                ],
                completedIdentifiers: [completedIdentifier],
                existingMappings: [:],
                promptKey: promptKey
            )
        )
    }

    func testRejectsAmbiguousRequestsFromSameProcess() {
        let promptKey = self.promptKey(id: 10)

        XCTAssertNil(
            AuthenticationRequestAssociation.unassignedActiveIdentifier(
                requesterProcessID: 200,
                evidence: [
                    event(pid: 200, identifier: identifier(clientID: 1)),
                    event(pid: 200, identifier: identifier(clientID: 2))
                ],
                completedIdentifiers: [],
                existingMappings: [:],
                promptKey: promptKey
            )
        )
    }

    func testDoesNotAssignOneRequestToTwoPromptSessions() {
        let firstPrompt = promptKey(id: 10)
        let secondPrompt = promptKey(id: 11)
        let identifier = self.identifier(clientID: 1)

        XCTAssertNil(
            AuthenticationRequestAssociation.unassignedActiveIdentifier(
                requesterProcessID: 200,
                evidence: [event(pid: 200, identifier: identifier)],
                completedIdentifiers: [],
                existingMappings: [firstPrompt: identifier],
                promptKey: secondPrompt
            )
        )
    }

    func testTransferAlwaysRemovesOldMappingAndPreservesExistingDestination() {
        let oldPrompt = promptKey(id: 10)
        let newPrompt = promptKey(id: 11)
        let oldIdentifier = identifier(clientID: 1)
        let existingIdentifier = identifier(clientID: 2)
        var mappings = [
            oldPrompt: oldIdentifier,
            newPrompt: existingIdentifier
        ]

        AuthenticationRequestAssociation.transferMapping(
            in: &mappings,
            from: oldPrompt,
            to: newPrompt
        )

        XCTAssertNil(mappings[oldPrompt])
        XCTAssertEqual(mappings[newPrompt], existingIdentifier)
    }

    private func event(
        pid: pid_t,
        identifier: AuthenticationRequestIdentifier?
    ) -> AuthenticationClientEvent {
        AuthenticationClientEvent(
            processID: pid,
            executablePath: "/Applications/Example.app/Contents/MacOS/Example",
            receivedAt: Date(timeIntervalSince1970: 100),
            source: .localAuthentication,
            requestIdentifier: identifier
        )
    }

    private func identifier(clientID: UInt64) -> AuthenticationRequestIdentifier {
        .localAuthentication(
            LocalAuthenticationRequestKey(
                processID: 200,
                executablePath: "/Applications/Example.app/Contents/MacOS/Example",
                operation: .evaluatePolicy,
                contextComponents: [1, 2, 3],
                clientID: clientID
            )
        )
    }

    private func promptKey(id: CGWindowID) -> AuthenticationPromptSessionKey {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        return AuthenticationPromptSessionKey(
            window: AuthenticationWindowSnapshot(
                identity: .coreGraphics(id),
                processID: 300,
                surfaceKind: .localAuthentication,
                coreGraphicsFrame: frame,
                frame: frame,
                visibleFrame: CGRect(x: 0, y: 24, width: 1920, height: 1056)
            )
        )
    }
}

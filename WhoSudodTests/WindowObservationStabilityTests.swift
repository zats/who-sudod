import XCTest
@testable import WhoSudod

final class WindowObservationStabilityTests: XCTestCase {
    private let first = ProcessIdentity(
        pid: 100,
        startTime: ProcessStartTime(seconds: 10, microseconds: 0)
    )
    private let second = ProcessIdentity(
        pid: 200,
        startTime: ProcessStartTime(seconds: 20, microseconds: 0)
    )

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

    func testForcedDiscoveryInspectsCoreGraphicsBeforeFallbackDeadline() {
        XCTAssertTrue(
            AuthenticationWindowDiscoveryPolicy.shouldInspectCoreGraphics(
                forceDiscovery: true,
                hasActiveSystemPrompt: false,
                isInFastDiscoveryBurst: false,
                now: 10,
                nextFallbackTime: 20
            )
        )
    }

    func testActiveSystemPromptInspectsCoreGraphicsBeforeFallbackDeadline() {
        XCTAssertTrue(
            AuthenticationWindowDiscoveryPolicy.shouldInspectCoreGraphics(
                forceDiscovery: false,
                hasActiveSystemPrompt: true,
                isInFastDiscoveryBurst: false,
                now: 10,
                nextFallbackTime: 20
            )
        )
    }

    func testFastDiscoveryBurstInspectsCoreGraphicsBeforeFallbackDeadline() {
        XCTAssertTrue(
            AuthenticationWindowDiscoveryPolicy.shouldInspectCoreGraphics(
                forceDiscovery: false,
                hasActiveSystemPrompt: false,
                isInFastDiscoveryBurst: true,
                now: 10,
                nextFallbackTime: 20
            )
        )
    }

    func testIdleMonitorSkipsCoreGraphicsBeforeFallbackDeadline() {
        XCTAssertFalse(
            AuthenticationWindowDiscoveryPolicy.shouldInspectCoreGraphics(
                forceDiscovery: false,
                hasActiveSystemPrompt: false,
                isInFastDiscoveryBurst: false,
                now: 19.999,
                nextFallbackTime: 20
            )
        )
    }

    func testIdleMonitorInspectsCoreGraphicsAtAndAfterFallbackDeadline() {
        XCTAssertTrue(
            AuthenticationWindowDiscoveryPolicy.shouldInspectCoreGraphics(
                forceDiscovery: false,
                hasActiveSystemPrompt: false,
                isInFastDiscoveryBurst: false,
                now: 20,
                nextFallbackTime: 20
            )
        )
        XCTAssertTrue(
            AuthenticationWindowDiscoveryPolicy.shouldInspectCoreGraphics(
                forceDiscovery: false,
                hasActiveSystemPrompt: false,
                isInFastDiscoveryBurst: false,
                now: 20.001,
                nextFallbackTime: 20
            )
        )
    }

    func testTerminalPromptKeepsObservedCurrentRequest() {
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: first,
                observed: [second, first],
                active: [first],
                currentMissConfirmed: false
            ),
            .keepCurrent
        )
    }

    func testTerminalPromptHandsOffOnlyToASeparatelyActiveRequest() {
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: first,
                observed: [second, first],
                active: [second],
                currentMissConfirmed: false
            ),
            .select(second)
        )
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: first,
                observed: [second, first],
                active: [],
                currentMissConfirmed: false
            ),
            .keepCurrent
        )
    }

    func testTerminalPromptDebouncesMissingCurrentBeforeReplacement() {
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: first,
                observed: [second],
                active: [second],
                currentMissConfirmed: false
            ),
            .waitForCurrent
        )
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: first,
                observed: [second],
                active: [second],
                currentMissConfirmed: true
            ),
            .select(second)
        )
    }

    func testTerminalPromptStartsAndEndsOnlyWithAnActiveSelection() {
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: nil,
                observed: [first],
                active: [],
                currentMissConfirmed: false
            ),
            .noSelection
        )
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: nil,
                observed: [first],
                active: [first],
                currentMissConfirmed: false
            ),
            .select(first)
        )
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: first,
                observed: [],
                active: [],
                currentMissConfirmed: true
            ),
            .endCurrent
        )
    }
}

final class AuthenticationWindowRecoveryTests: XCTestCase {
    func testRecoversSamePromptWhenCoreGraphicsRepresentationChangesToAccessibility() throws {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let coreGraphics = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let accessibility = authenticationWindow(
            identity: .accessibility(processID: 321),
            processID: 321,
            frame: frame.offsetBy(dx: 2, dy: -1)
        )

        XCTAssertEqual(
            AuthenticationWindowRecovery.continuousReplacement(
                for: coreGraphics,
                candidate: accessibility
            ),
            accessibility
        )
    }

    func testDoesNotRecoverUnrelatedCandidate() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let missing = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let otherProcess = authenticationWindow(
            identity: .accessibility(processID: 654),
            processID: 654,
            frame: frame
        )

        XCTAssertNil(
            AuthenticationWindowRecovery.continuousReplacement(
                for: missing,
                candidate: otherProcess
            )
        )
        XCTAssertNil(
            AuthenticationWindowRecovery.continuousReplacement(
                for: missing,
                candidate: nil
            )
        )
    }

    func testRecoversFreshSnapshotWithTheSameIdentity() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let missing = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let rediscovered = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame.offsetBy(dx: 1, dy: -1)
        )

        XCTAssertEqual(
            AuthenticationWindowRecovery.continuousReplacement(
                for: missing,
                candidate: rediscovered
            ),
            rediscovered
        )
    }

    func testDoesNotRecoverReusedCoreGraphicsIdentityForADifferentProcess() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let missing = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let reusedIdentity = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 654,
            frame: frame
        )

        XCTAssertNil(
            AuthenticationWindowRecovery.continuousReplacement(
                for: missing,
                candidate: reusedIdentity
            )
        )
        XCTAssertEqual(
            AuthenticationWindowFocusTransition.resolve(
                from: missing,
                to: reusedIdentity
            ),
            .differentPrompt(reusedIdentity)
        )
    }

    func testSamePromptFocusTransitionKeepsCurrentPanelVisible() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let coreGraphics = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let accessibility = authenticationWindow(
            identity: .accessibility(processID: 321),
            processID: 321,
            frame: frame.offsetBy(dx: 1, dy: -1)
        )

        let transition = AuthenticationWindowFocusTransition.resolve(
            from: coreGraphics,
            to: accessibility
        )

        XCTAssertEqual(transition, .samePrompt(accessibility))
        XCTAssertFalse(transition.hidesCurrentPanel)
    }

    func testSameIdentityFocusTransitionKeepsCurrentPanelVisible() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let current = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let freshCandidate = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame.offsetBy(dx: 1, dy: -1)
        )

        let transition = AuthenticationWindowFocusTransition.resolve(
            from: current,
            to: freshCandidate
        )

        XCTAssertEqual(transition, .samePrompt(freshCandidate))
        XCTAssertFalse(transition.hidesCurrentPanel)
    }

    func testDifferentPromptHandsOffWithoutHidingButMissingPromptHides() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let current = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let different = authenticationWindow(
            identity: .accessibility(processID: 654),
            processID: 654,
            frame: frame
        )

        XCTAssertFalse(
            AuthenticationWindowFocusTransition.resolve(
                from: current,
                to: different
            ).hidesCurrentPanel
        )
        XCTAssertTrue(
            AuthenticationWindowFocusTransition.resolve(
                from: current,
                to: nil
            ).hidesCurrentPanel
        )
    }

    private func authenticationWindow(
        identity: AuthenticationWindowIdentity,
        processID: pid_t,
        frame: CGRect
    ) -> AuthenticationWindowSnapshot {
        AuthenticationWindowSnapshot(
            identity: identity,
            processID: processID,
            surfaceKind: .localAuthentication,
            coreGraphicsFrame: frame,
            frame: frame,
            visibleFrame: CGRect(x: 0, y: 24, width: 1920, height: 1056)
        )
    }
}

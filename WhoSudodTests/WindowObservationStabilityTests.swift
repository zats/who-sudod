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

    func testInactiveMissingAuthenticationWindowIsRetained() {
        XCTAssertEqual(
            AuthenticationWindowAbsenceResolution.resolve(
                presenterIsRunning: true,
                presenterIsActive: false,
                requesterIsFrontmost: false
            ),
            .retain
        )
    }

    func testActiveMissingAuthenticationWindowCountsAsAConfirmedMiss() {
        XCTAssertEqual(
            AuthenticationWindowAbsenceResolution.resolve(
                presenterIsRunning: true,
                presenterIsActive: true,
                requesterIsFrontmost: false
            ),
            .countMiss
        )
    }

    func testMissingAuthenticationWindowCountsWhenRequesterReturnsToFront() {
        XCTAssertEqual(
            AuthenticationWindowAbsenceResolution.resolve(
                presenterIsRunning: true,
                presenterIsActive: false,
                requesterIsFrontmost: true
            ),
            .countMiss
        )
    }

    func testExitedAuthenticationPresenterEndsImmediately() {
        XCTAssertEqual(
            AuthenticationWindowAbsenceResolution.resolve(
                presenterIsRunning: false,
                presenterIsActive: false,
                requesterIsFrontmost: false
            ),
            .endImmediately
        )
    }

    func testObservedSystemPromptOutlivesRequester() {
        XCTAssertFalse(
            SystemPromptTeardownPolicy.shouldEnd(
                requestHasCompleted: false,
                requesterIsRunning: false,
                promptIsObserved: true
            )
        )
    }

    func testProcessIdentityLivenessRejectsPIDReuse() throws {
        let current = try XCTUnwrap(
            ProcessIdentityLiveness.currentIdentity(processID: getpid())
        )

        XCTAssertTrue(ProcessIdentityLiveness.isRunning(current))
        XCTAssertFalse(
            ProcessIdentityLiveness.isRunning(
                ProcessIdentity(
                    pid: current.pid,
                    startTime: ProcessStartTime(
                        seconds: current.startTime.seconds + 1,
                        microseconds: current.startTime.microseconds
                    )
                )
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

    func testTerminalPromptFocusLossDoesNotEndObservedRequest() {
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: first,
                observed: [first],
                active: [],
                currentMissConfirmed: false
            ),
            .keepCurrent
        )
    }

    func testDismissedTerminalPromptSurvivesRepeatedEmptyObservationsWhileProcessLives() {
        var suppression = TerminalPromptSuppressionState()
        suppression.recordUserDismissal(first)

        for _ in 0..<3 {
            suppression.refresh(
                observed: [],
                isRunning: { $0 == self.first }
            )
        }

        XCTAssertTrue(suppression.suppressesHeuristicPrompt(first))
    }

    func testDismissedTerminalPromptIsPrunedAfterExactProcessExits() {
        var suppression = TerminalPromptSuppressionState()
        suppression.recordUserDismissal(first)
        suppression.recordPAMCompletion(second)

        suppression.refresh(
            observed: [],
            isRunning: { $0 == self.second }
        )

        XCTAssertFalse(suppression.suppressesHeuristicPrompt(first))
        XCTAssertTrue(suppression.suppressesHeuristicPrompt(second))
    }

    func testDismissedTerminalPromptSurvivesOneStaleObservationAfterExit() {
        var suppression = TerminalPromptSuppressionState()
        suppression.recordPAMCompletion(first)

        suppression.refresh(
            observed: [first],
            isRunning: { _ in false }
        )
        XCTAssertTrue(suppression.suppressesHeuristicPrompt(first))

        suppression.refresh(observed: [], isRunning: { _ in false })
        XCTAssertFalse(suppression.suppressesHeuristicPrompt(first))
    }

    func testCompletedPAMRequestSuppressesHeuristicButAllowsSameProcessRetry() {
        var suppression = TerminalPromptSuppressionState()
        suppression.recordPAMCompletion(first)

        XCTAssertTrue(suppression.suppressesHeuristicPrompt(first))
        XCTAssertTrue(suppression.beginVerifiedPAMRequest(first))
        XCTAssertFalse(suppression.suppressesHeuristicPrompt(first))
    }

    func testNewPAMConversationSupersedesSameRunningSudoBeforeOldEnd() throws {
        let firstRequest = PAMPasswordRequest(
            identifier: try XCTUnwrap(
                PAMRequestIdentifier(bytes: Data(repeating: 0x11, count: 16))
            ),
            processID: first.pid,
            realUserID: 501,
            username: "test",
            terminal: "/dev/ttys001",
            prompt: "Password:"
        )
        let retryRequest = PAMPasswordRequest(
            identifier: try XCTUnwrap(
                PAMRequestIdentifier(bytes: Data(repeating: 0x22, count: 16))
            ),
            processID: first.pid,
            realUserID: 501,
            username: "test",
            terminal: "/dev/ttys001",
            prompt: "Password:"
        )

        XCTAssertTrue(
            PAMRequestReplacementPolicy.canSupersede(
                activeRequest: firstRequest,
                activeIdentity: first,
                incomingRequest: retryRequest,
                currentIdentity: first
            )
        )
        XCTAssertFalse(
            PAMRequestReplacementPolicy.canSupersede(
                activeRequest: firstRequest,
                activeIdentity: first,
                incomingRequest: retryRequest,
                currentIdentity: second
            )
        )
    }

    func testExplicitlyDismissedPAMRequestRejectsSameProcessRetry() {
        var suppression = TerminalPromptSuppressionState()
        suppression.recordUserDismissal(first)

        XCTAssertFalse(suppression.beginVerifiedPAMRequest(first))
        XCTAssertTrue(suppression.suppressesActivePAMRequest(first))
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

    func testTwoObservedTerminalPromptsDoNotSwitchWithoutAFocusedWindow() {
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

    func testTerminalPromptEndRequiresThreeConsecutiveMissingScans() {
        var stability = WindowObservationStability(requiredMisses: 3)

        for _ in 0..<2 {
            XCTAssertEqual(
                TerminalPromptObservationResolution.resolve(
                    current: first,
                    observed: [],
                    active: [],
                    currentMissConfirmed: stability.recordMiss()
                ),
                .waitForCurrent
            )
        }

        stability.recordConfirmation()
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: first,
                observed: [first],
                active: [first],
                currentMissConfirmed: false
            ),
            .keepCurrent
        )

        XCTAssertFalse(stability.recordMiss())
        XCTAssertFalse(stability.recordMiss())
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: first,
                observed: [],
                active: [],
                currentMissConfirmed: stability.recordMiss()
            ),
            .endCurrent
        )
    }

    func testTerminalPromptStartsFromVerifiedProcessEvidenceWithoutAWindow() {
        XCTAssertEqual(
            TerminalPromptObservationResolution.resolve(
                current: nil,
                observed: [first],
                active: [],
                currentMissConfirmed: false
            ),
            .select(first)
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

final class CoveredSystemPromptSelectionTests: XCTestCase {
    func testObservedCoveredPromptOutlivesRequester() {
        let covered = window(id: 44)
        let coveredKey = AuthenticationPromptSessionKey(window: covered)

        XCTAssertFalse(
            SystemPromptTeardownPolicy.shouldEnd(
                requestHasCompleted: false,
                requesterIsRunning: false,
                promptKey: coveredKey,
                observedPromptKeys: [coveredKey]
            )
        )
    }

    func testPrefersFrontmostPromptThatDidNotEnd() {
        let ended = window(id: 44)
        let frontmost = window(id: 45)

        XCTAssertEqual(
            CoveredSystemPromptSelection.replacement(
                frontmost: frontmost,
                observed: [frontmost],
                coveredKeys: [],
                excluding: AuthenticationPromptSessionKey(window: ended)
            ),
            frontmost
        )
    }

    func testRestoresNewestCoveredPromptThatIsStillObserved() {
        let oldest = window(id: 44)
        let newest = window(id: 45)
        let ended = window(id: 46)

        XCTAssertEqual(
            CoveredSystemPromptSelection.replacement(
                frontmost: nil,
                observed: [oldest, newest],
                coveredKeys: [
                    AuthenticationPromptSessionKey(window: oldest),
                    AuthenticationPromptSessionKey(window: newest)
                ],
                excluding: AuthenticationPromptSessionKey(window: ended)
            ),
            newest
        )
    }

    func testDoesNotRestoreUnobservedOrEndingPrompt() {
        let covered = window(id: 44)
        let ended = window(id: 45)
        let unrelated = window(id: 46)

        XCTAssertNil(
            CoveredSystemPromptSelection.replacement(
                frontmost: ended,
                observed: [ended, unrelated],
                coveredKeys: [AuthenticationPromptSessionKey(window: covered)],
                excluding: AuthenticationPromptSessionKey(window: ended)
            )
        )
    }

    private func window(id: CGWindowID) -> AuthenticationWindowSnapshot {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        return AuthenticationWindowSnapshot(
            identity: .coreGraphics(id),
            processID: pid_t(id),
            surfaceKind: .localAuthentication,
            coreGraphicsFrame: frame,
            frame: frame,
            visibleFrame: CGRect(x: 0, y: 24, width: 1920, height: 1056)
        )
    }
}

final class AuthenticationWindowRecoveryTests: XCTestCase {
    func testDoesNotRecoverUnprovenCoreGraphicsIdentityAsAccessibilityPrompt() throws {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let coreGraphics = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let accessibility = authenticationWindow(
            identity: .accessibility(processID: 321, elementIdentifier: 17),
            processID: 321,
            frame: frame.offsetBy(dx: 2, dy: -1)
        )

        XCTAssertNil(
            AuthenticationWindowRecovery.continuousReplacement(
                for: coreGraphics,
                candidate: accessibility
            )
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
            identity: .accessibility(processID: 654, elementIdentifier: 17),
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

    func testCrossSourceFocusTransitionDoesNotTransferUnprovenHistory() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let coreGraphics = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let accessibility = authenticationWindow(
            identity: .accessibility(processID: 321, elementIdentifier: 17),
            processID: 321,
            frame: frame.offsetBy(dx: 1, dy: -1)
        )

        let transition = AuthenticationWindowFocusTransition.resolve(
            from: coreGraphics,
            to: accessibility
        )

        XCTAssertEqual(transition, .differentPrompt(accessibility))
    }

    func testSameIdentityFocusTransitionKeepsCurrentPromptSelected() {
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
    }

    func testDifferentAccessibilityWindowInSamePresenterSwitchesPrompt() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let current = authenticationWindow(
            identity: .accessibility(
                processID: 321,
                elementIdentifier: 17
            ),
            processID: 321,
            frame: frame
        )
        let topmost = authenticationWindow(
            identity: .accessibility(
                processID: 321,
                elementIdentifier: 18
            ),
            processID: 321,
            frame: frame
        )

        XCTAssertEqual(
            AuthenticationWindowFocusTransition.resolve(
                from: current,
                to: topmost
            ),
            .differentPrompt(topmost)
        )
    }

    func testFocusedCGWindowDoesNotMergeWithPreviousAccessibilityWindow() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let previous = authenticationWindow(
            identity: .accessibility(
                processID: 321,
                elementIdentifier: 17
            ),
            processID: 321,
            frame: frame
        )
        let topmostCoreGraphics = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )

        XCTAssertEqual(
            AuthenticationWindowFocusTransition.resolve(
                from: previous,
                to: topmostCoreGraphics
            ),
            .differentPrompt(topmostCoreGraphics)
        )
    }

    func testDifferentFocusedPromptHandsOffButNoFocusedCandidateKeepsCurrentPrompt() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let current = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let different = authenticationWindow(
            identity: .accessibility(processID: 654, elementIdentifier: 17),
            processID: 654,
            frame: frame
        )

        XCTAssertEqual(
            AuthenticationWindowFocusTransition.resolve(
                from: current,
                to: different
            ),
            .differentPrompt(different)
        )
        XCTAssertEqual(
            AuthenticationWindowFocusTransition.resolve(
                from: current,
                to: nil
            ),
            .noCandidate
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

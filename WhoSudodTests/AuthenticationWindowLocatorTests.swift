import CoreGraphics
import XCTest
@testable import WhoSudod

final class AuthenticationWindowLocatorTests: XCTestCase {
    private let display = DisplayGeometry(
        appKitFrame: CGRect(x: 0, y: 0, width: 1920, height: 1080),
        visibleFrame: CGRect(x: 0, y: 24, width: 1920, height: 1056),
        coreGraphicsFrame: CGRect(x: 0, y: 0, width: 1920, height: 1080)
    )

    func testMatchesOnlyKnownPresenterPaths() {
        XCTAssertEqual(
            AuthenticationPresenterMatcher.kind(
                bundleIdentifier: "com.apple.SecurityAgent",
                executablePath: AuthenticationPresenterMatcher.securityAgentPath
            ),
            .securityAgent
        )
        XCTAssertEqual(
            AuthenticationPresenterMatcher.kind(
                bundleIdentifier: "com.apple.LocalAuthentication.UIAgent",
                executablePath: AuthenticationPresenterMatcher.coreAuthenticationPath
            ),
            .localAuthentication
        )
        XCTAssertEqual(
            AuthenticationPresenterMatcher.kind(
                bundleIdentifier: "com.apple.LocalAuthenticationRemoteService",
                executablePath: AuthenticationPresenterMatcher.remoteServicePath
            ),
            .localAuthentication
        )
    }

    func testCoreGraphicsPrefilterAcceptsOnlyKnownPresenterNames() {
        for name in [
            "SecurityAgent",
            "coreautha",
            "LocalAuthenticationRemoteService"
        ] {
            XCTAssertTrue(
                AuthenticationPresenterMatcher.isPossibleCoreGraphicsPresenter(
                    processName: name
                ),
                name
            )
        }

        for name in [nil, "ChatGPT", "SecurityAgent copy", "sudo"] {
            XCTAssertFalse(
                AuthenticationPresenterMatcher.isPossibleCoreGraphicsPresenter(
                    processName: name
                ),
                name ?? "nil"
            )
        }
    }

    func testAcceptsKnownSystemPathWhenBundleMetadataIsUnavailable() {
        XCTAssertEqual(
            AuthenticationPresenterMatcher.kind(
                bundleIdentifier: nil,
                executablePath: AuthenticationPresenterMatcher.securityAgentPath
            ),
            .securityAgent
        )
        XCTAssertEqual(
            AuthenticationPresenterMatcher.kind(
                bundleIdentifier: nil,
                executablePath: AuthenticationPresenterMatcher.coreAuthenticationPath
            ),
            .localAuthentication
        )
    }

    func testRejectsTrustedBundleIdentifierAtSpoofedPath() {
        let cases: [(String, String)] = [
            ("com.apple.SecurityAgent", "/tmp/SecurityAgent"),
            (
                "com.apple.SecurityAgent",
                AuthenticationPresenterMatcher.securityAgentPath + ".backup"
            ),
            ("com.apple.LocalAuthentication.UIAgent", "/tmp/coreautha"),
            (
                "com.apple.LocalAuthentication.UIAgent",
                AuthenticationPresenterMatcher.coreAuthenticationPath + ".spoof"
            ),
            (
                "com.apple.LocalAuthenticationRemoteService",
                "/tmp/LocalAuthenticationRemoteService"
            )
        ]

        for (bundleIdentifier, executablePath) in cases {
            XCTAssertNil(
                AuthenticationPresenterMatcher.kind(
                    bundleIdentifier: bundleIdentifier,
                    executablePath: executablePath
                ),
                executablePath
            )
        }
    }

    func testRejectsMismatchedBundleIdentifierAtKnownPath() {
        XCTAssertNil(
            AuthenticationPresenterMatcher.kind(
                bundleIdentifier: "com.example.SecurityAgent",
                executablePath: AuthenticationPresenterMatcher.securityAgentPath
            )
        )
        XCTAssertNil(
            AuthenticationPresenterMatcher.kind(
                bundleIdentifier: "com.example.coreautha",
                executablePath: AuthenticationPresenterMatcher.coreAuthenticationPath
            )
        )
        XCTAssertNil(
            AuthenticationPresenterMatcher.kind(
                bundleIdentifier: "com.apple.LocalAuthentication.UIAgent",
                executablePath: AuthenticationPresenterMatcher.remoteServicePath
            )
        )
    }

    func testRejectsMissingOrUnknownExecutablePath() {
        XCTAssertNil(
            AuthenticationPresenterMatcher.kind(
                bundleIdentifier: "com.apple.SecurityAgent",
                executablePath: nil
            )
        )
        XCTAssertNil(
            AuthenticationPresenterMatcher.kind(
                bundleIdentifier: nil,
                executablePath: "/usr/bin/SecurityAgent"
            )
        )
    }

    func testBuildsAccessibilityBackedCoreAuthenticationWindow() throws {
        let snapshot = try XCTUnwrap(
            AuthenticationWindowSnapshotFactory.accessibilitySnapshot(
                processID: 321,
                elementIdentifier: 17,
                bundleIdentifier: "com.apple.LocalAuthentication.UIAgent",
                executablePath: AuthenticationPresenterMatcher.coreAuthenticationPath,
                focusedFrame: CGRect(x: 100, y: 200, width: 260, height: 289),
                displays: [display]
            )
        )

        XCTAssertEqual(
            snapshot.identity,
            .accessibility(processID: 321, elementIdentifier: 17)
        )
        XCTAssertEqual(snapshot.processID, 321)
        XCTAssertEqual(snapshot.surfaceKind, .localAuthentication)
        XCTAssertEqual(
            snapshot.frame,
            CGRect(x: 100, y: 591, width: 260, height: 289)
        )
        XCTAssertEqual(snapshot.visibleFrame, display.visibleFrame)
    }

    func testRejectsSpoofedAccessibilityPresenter() {
        XCTAssertNil(
            AuthenticationWindowSnapshotFactory.accessibilitySnapshot(
                processID: 321,
                elementIdentifier: 17,
                bundleIdentifier: "com.apple.LocalAuthentication.UIAgent",
                executablePath: "/tmp/coreautha",
                focusedFrame: CGRect(x: 100, y: 200, width: 260, height: 289),
                displays: [display]
            )
        )
    }

    func testRejectsMissingOrUndersizedAccessibilityWindow() {
        XCTAssertNil(
            AuthenticationWindowSnapshotFactory.accessibilitySnapshot(
                processID: 321,
                elementIdentifier: 17,
                bundleIdentifier: "com.apple.LocalAuthentication.UIAgent",
                executablePath: AuthenticationPresenterMatcher.coreAuthenticationPath,
                focusedFrame: nil,
                displays: [display]
            )
        )
        XCTAssertNil(
            AuthenticationWindowSnapshotFactory.accessibilitySnapshot(
                processID: 321,
                elementIdentifier: 17,
                bundleIdentifier: "com.apple.LocalAuthentication.UIAgent",
                executablePath: AuthenticationPresenterMatcher.coreAuthenticationPath,
                focusedFrame: CGRect(x: 100, y: 200, width: 179, height: 119),
                displays: [display]
            )
        )
    }

    func testDoesNotMergeUnprovenCoreGraphicsAndAccessibilityIdentities() {
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

        XCTAssertFalse(
            AuthenticationWindowContinuity.representsSamePrompt(
                coreGraphics,
                accessibility
            )
        )
    }

    func testDoesNotMergeDifferentAuthenticationWindows() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let first = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let otherWindow = authenticationWindow(
            identity: .coreGraphics(45),
            processID: 321,
            frame: frame
        )
        let otherProcess = authenticationWindow(
            identity: .accessibility(processID: 654, elementIdentifier: 17),
            processID: 654,
            frame: frame
        )

        XCTAssertFalse(
            AuthenticationWindowContinuity.representsSamePrompt(first, otherWindow)
        )
        XCTAssertFalse(
            AuthenticationWindowContinuity.representsSamePrompt(first, otherProcess)
        )
    }

    func testAccessibilityFallbackKeepsFocusedAXIdentityForUniqueCoreGraphicsMatch() throws {
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

        XCTAssertEqual(
            AuthenticationWindowAccessibilityFallback.resolve(
                coreGraphicsCandidates: [coreGraphics],
                accessibilityCandidate: accessibility
            ),
            accessibility
        )
    }

    func testAccessibilityFallbackUsesFocusedAXIdentityForAmbiguousSameFrameWindows() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let first = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let second = authenticationWindow(
            identity: .coreGraphics(45),
            processID: 321,
            frame: frame
        )
        let accessibility = authenticationWindow(
            identity: .accessibility(processID: 321, elementIdentifier: 17),
            processID: 321,
            frame: frame
        )

        XCTAssertEqual(
            AuthenticationWindowAccessibilityFallback.resolve(
                coreGraphicsCandidates: [first, second],
                accessibilityCandidate: accessibility
            ),
            accessibility
        )
    }

    func testAccessibilityFallbackUsesAXOnlyWhenNoCoreGraphicsCandidateExists() {
        let accessibility = authenticationWindow(
            identity: .accessibility(processID: 321, elementIdentifier: 17),
            processID: 321,
            frame: CGRect(x: 100, y: 200, width: 260, height: 289)
        )

        XCTAssertEqual(
            AuthenticationWindowAccessibilityFallback.resolve(
                coreGraphicsCandidates: [],
                accessibilityCandidate: accessibility
            ),
            accessibility
        )
    }

    func testUnrelatedCoreGraphicsPromptDoesNotBlockFocusedAccessibilityPrompt() {
        let accessibility = authenticationWindow(
            identity: .accessibility(processID: 321, elementIdentifier: 17),
            processID: 321,
            frame: CGRect(x: 100, y: 200, width: 260, height: 289)
        )
        let unrelated = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 654,
            frame: CGRect(x: 500, y: 200, width: 260, height: 289)
        )

        XCTAssertEqual(
            AuthenticationWindowAccessibilityFallback.resolve(
                coreGraphicsCandidates: [unrelated],
                accessibilityCandidate: accessibility
            ),
            accessibility
        )
    }

    func testTrackedAccessibilityWindowSurvivesLossOfFocus() {
        let previousFrame = CGRect(x: 100, y: 200, width: 260, height: 289)

        XCTAssertEqual(
            AuthenticationTrackedWindowResolver.accessibilityFrame(
                matching: previousFrame,
                currentFrames: [
                    CGRect(x: 10, y: 10, width: 40, height: 40),
                    previousFrame.offsetBy(dx: 2, dy: -2)
                ]
            ),
            previousFrame.offsetBy(dx: 2, dy: -2)
        )
    }

    func testTrackedAccessibilityWindowCanMoveWhileNotFocused() {
        let movedFrame = CGRect(x: 800, y: 400, width: 300, height: 320)

        XCTAssertEqual(
            AuthenticationTrackedWindowResolver.accessibilityFrame(
                matching: CGRect(x: 100, y: 200, width: 260, height: 289),
                currentFrames: [movedFrame]
            ),
            movedFrame
        )
    }

    func testTrackedCoreGraphicsFallbackRejectsAHiddenPlaceholder() {
        XCTAssertNil(
            AuthenticationTrackedWindowResolver.accessibilityFrame(
                matching: CGRect(x: 100, y: 200, width: 260, height: 289),
                currentFrames: [
                    CGRect(x: 0, y: 0, width: 500, height: 500)
                ],
                acceptsMovedSingleWindow: false
            )
        )
    }

    func testTrackedAccessibilityWindowDoesNotGuessBetweenWindows() {
        XCTAssertNil(
            AuthenticationTrackedWindowResolver.accessibilityFrame(
                matching: CGRect(x: 100, y: 200, width: 260, height: 289),
                currentFrames: [
                    CGRect(x: 500, y: 200, width: 260, height: 289),
                    CGRect(x: 900, y: 200, width: 260, height: 289)
                ]
            )
        )
    }

    func testTrackedAccessibilityWindowEndsWhenNoWindowExists() {
        XCTAssertNil(
            AuthenticationTrackedWindowResolver.accessibilityFrame(
                matching: CGRect(x: 100, y: 200, width: 260, height: 289),
                currentFrames: []
            )
        )
    }

    func testExactCoreGraphicsLookupIncludesOffscreenWindow() {
        XCTAssertTrue(
            AuthenticationCoreGraphicsWindowPolicy.includes(
                isOnScreen: false,
                requiresOnScreen: false
            )
        )
        XCTAssertTrue(
            AuthenticationCoreGraphicsWindowPolicy.includes(
                isOnScreen: nil,
                requiresOnScreen: false
            )
        )
    }

    func testCoreGraphicsDiscoveryStillRequiresOnscreenWindow() {
        XCTAssertFalse(
            AuthenticationCoreGraphicsWindowPolicy.includes(
                isOnScreen: false,
                requiresOnScreen: true
            )
        )
        XCTAssertFalse(
            AuthenticationCoreGraphicsWindowPolicy.includes(
                isOnScreen: nil,
                requiresOnScreen: true
            )
        )
        XCTAssertTrue(
            AuthenticationCoreGraphicsWindowPolicy.includes(
                isOnScreen: true,
                requiresOnScreen: true
            )
        )
    }

    func testCoreGraphicsFocusFallbackIsOnlyUsedForSecurityAgent() {
        let frame = CGRect(x: 100, y: 200, width: 260, height: 289)
        let localAuthentication = authenticationWindow(
            identity: .coreGraphics(44),
            processID: 321,
            frame: frame
        )
        let securityAgent = AuthenticationWindowSnapshot(
            identity: .coreGraphics(45),
            processID: 654,
            surfaceKind: .securityAgent,
            coreGraphicsFrame: frame,
            frame: frame,
            visibleFrame: display.visibleFrame
        )

        XCTAssertFalse(
            AuthenticationCoreGraphicsFocusFallbackPolicy.permits(
                localAuthentication
            )
        )
        XCTAssertTrue(
            AuthenticationCoreGraphicsFocusFallbackPolicy.permits(
                securityAgent
            )
        )
    }

    @MainActor
    func testActiveApplicationScreenUsesItsFocusedWindowDisplay() {
        let secondaryDisplay = DisplayGeometry(
            appKitFrame: CGRect(x: 1920, y: 0, width: 1280, height: 1024),
            visibleFrame: CGRect(x: 1920, y: 24, width: 1280, height: 1000),
            coreGraphicsFrame: CGRect(x: 1920, y: 100, width: 1280, height: 1024)
        )

        XCTAssertEqual(
            ActiveApplicationScreenLocator.visibleFrame(
                focusedWindowFrame: CGRect(
                    x: 2100,
                    y: 180,
                    width: 800,
                    height: 600
                ),
                displays: [display, secondaryDisplay]
            ),
            secondaryDisplay.visibleFrame
        )
    }

    @MainActor
    func testActiveApplicationScreenNeedsAFocusedWindow() {
        XCTAssertNil(
            ActiveApplicationScreenLocator.visibleFrame(
                focusedWindowFrame: nil,
                displays: [display]
            )
        )
    }

    @MainActor
    func testActiveApplicationScreenUsesMainWindowWhenFocusedWindowIsMissing() {
        let secondaryDisplay = DisplayGeometry(
            appKitFrame: CGRect(x: 1920, y: 0, width: 1280, height: 1024),
            visibleFrame: CGRect(x: 1920, y: 24, width: 1280, height: 1000),
            coreGraphicsFrame: CGRect(x: 1920, y: 100, width: 1280, height: 1024)
        )

        XCTAssertEqual(
            ActiveApplicationScreenLocator.visibleFrame(
                focusedWindowFrame: nil,
                mainWindowFrame: CGRect(
                    x: 2100,
                    y: 180,
                    width: 800,
                    height: 600
                ),
                displays: [display, secondaryDisplay]
            ),
            secondaryDisplay.visibleFrame
        )
    }

    @MainActor
    func testActiveApplicationScreenUsesFirstEligibleOrderedWindow() {
        let secondaryDisplay = DisplayGeometry(
            appKitFrame: CGRect(x: 1920, y: 0, width: 1280, height: 1024),
            visibleFrame: CGRect(x: 1920, y: 24, width: 1280, height: 1000),
            coreGraphicsFrame: CGRect(x: 1920, y: 100, width: 1280, height: 1024)
        )

        XCTAssertEqual(
            ActiveApplicationScreenLocator.visibleFrame(
                focusedWindowFrame: nil,
                orderedOnScreenWindowFrames: [
                    CGRect(x: 2100, y: 180, width: 800, height: 600),
                    CGRect(x: 100, y: 200, width: 900, height: 640)
                ],
                displays: [display, secondaryDisplay]
            ),
            secondaryDisplay.visibleFrame
        )
    }

    @MainActor
    func testActiveApplicationScreenUsesPointerOnlyWhenAllowed() {
        let secondaryDisplay = DisplayGeometry(
            appKitFrame: CGRect(x: 1920, y: 0, width: 1280, height: 1024),
            visibleFrame: CGRect(x: 1920, y: 24, width: 1280, height: 1000),
            coreGraphicsFrame: CGRect(x: 1920, y: 100, width: 1280, height: 1024)
        )
        let pointer = CGPoint(x: 2200, y: 400)

        XCTAssertNil(
            ActiveApplicationScreenLocator.visibleFrame(
                focusedWindowFrame: nil,
                pointerLocation: pointer,
                allowsPointerFallback: false,
                displays: [display, secondaryDisplay]
            )
        )
        XCTAssertEqual(
            ActiveApplicationScreenLocator.visibleFrame(
                focusedWindowFrame: nil,
                pointerLocation: pointer,
                allowsPointerFallback: true,
                displays: [display, secondaryDisplay]
            ),
            secondaryDisplay.visibleFrame
        )
    }

    @MainActor
    func testTerminalPromptUsesFrontmostWindowWhenFramesMatch() throws {
        let frame = CGRect(x: 100, y: 200, width: 900, height: 640)
        let frontmost = terminalWindow(windowID: 91, frame: frame)
        let covered = terminalWindow(windowID: 92, frame: frame)

        XCTAssertEqual(
            TerminalPromptWindowLocator.frontmostMatch(
                in: [frontmost, covered],
                focusedFrame: frame
            ),
            frontmost
        )
    }

    @MainActor
    func testTerminalPromptRetainsItsWindowWhileOwnerRunsWithoutFocus() {
        let previous = terminalWindow(
            windowID: 91,
            frame: CGRect(x: 100, y: 200, width: 900, height: 640)
        )

        XCTAssertEqual(
            TerminalPromptWindowLocator.retainedCandidate(
                previous: previous,
                updatedSameWindow: nil,
                ownerIsRunning: true
            ),
            previous
        )
    }

    @MainActor
    func testTerminalPromptCanStartFromAnAvailableWindowWithoutFocus() {
        let available = terminalWindow(
            windowID: 91,
            frame: CGRect(x: 100, y: 200, width: 900, height: 640)
        )

        XCTAssertEqual(
            TerminalPromptWindowLocator.initialCandidate(
                focused: nil,
                available: [available]
            ),
            available
        )
    }

    @MainActor
    func testTerminalPromptCanStartFromAUniqueOffscreenWindow() {
        let offscreen = terminalWindow(
            windowID: 91,
            frame: CGRect(x: 100, y: 200, width: 900, height: 640)
        )

        XCTAssertEqual(
            TerminalPromptWindowLocator.initialCandidate(
                focused: nil,
                available: [],
                offscreen: [offscreen]
            ),
            offscreen
        )
    }

    @MainActor
    func testTerminalPromptDoesNotGuessBetweenOffscreenWindows() {
        let first = terminalWindow(
            windowID: 91,
            frame: CGRect(x: 100, y: 200, width: 900, height: 640)
        )
        let second = terminalWindow(
            windowID: 92,
            frame: CGRect(x: 700, y: 200, width: 900, height: 640)
        )

        XCTAssertNil(
            TerminalPromptWindowLocator.initialCandidate(
                focused: nil,
                available: [],
                offscreen: [first, second]
            )
        )
    }

    @MainActor
    func testTerminalPromptPrefersTheFocusedWindowAtStart() {
        let focused = terminalWindow(
            windowID: 91,
            frame: CGRect(x: 100, y: 200, width: 900, height: 640)
        )
        let other = terminalWindow(
            windowID: 92,
            frame: CGRect(x: 700, y: 200, width: 900, height: 640)
        )

        XCTAssertEqual(
            TerminalPromptWindowLocator.initialCandidate(
                focused: focused,
                available: [other]
            ),
            focused
        )
    }

    @MainActor
    func testTerminalPromptUpdatesOnlyItsExactWindow() {
        let previous = terminalWindow(
            windowID: 91,
            frame: CGRect(x: 100, y: 200, width: 900, height: 640)
        )
        let moved = terminalWindow(
            windowID: 91,
            frame: CGRect(x: 300, y: 240, width: 900, height: 640)
        )

        XCTAssertEqual(
            TerminalPromptWindowLocator.retainedCandidate(
                previous: previous,
                updatedSameWindow: moved,
                ownerIsRunning: true
            ),
            moved
        )
    }

    @MainActor
    func testTerminalPromptStopsRetainingItsWindowAfterOwnerExits() {
        let previous = terminalWindow(
            windowID: 91,
            frame: CGRect(x: 100, y: 200, width: 900, height: 640)
        )

        XCTAssertNil(
            TerminalPromptWindowLocator.retainedCandidate(
                previous: previous,
                updatedSameWindow: nil,
                ownerIsRunning: false
            )
        )
    }

    @MainActor
    func testTerminalPromptDoesNotMoveToAnotherFocusedWindow() {
        let previous = terminalWindow(
            windowID: 91,
            frame: CGRect(x: 100, y: 200, width: 900, height: 640)
        )
        let otherWindow = terminalWindow(
            windowID: 92,
            frame: CGRect(x: 700, y: 200, width: 900, height: 640)
        )

        XCTAssertEqual(
            TerminalPromptWindowLocator.retainedCandidate(
                previous: previous,
                updatedSameWindow: otherWindow,
                ownerIsRunning: true
            ),
            previous
        )
    }

    private func terminalWindow(
        windowID: CGWindowID,
        frame: CGRect
    ) -> TerminalPromptWindowSnapshot {
        TerminalPromptWindowSnapshot(
            windowID: windowID,
            processID: 321,
            coreGraphicsFrame: frame,
            frame: frame,
            visibleFrame: display.visibleFrame
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
            visibleFrame: display.visibleFrame
        )
    }
}

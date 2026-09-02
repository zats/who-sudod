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
                bundleIdentifier: "com.apple.LocalAuthentication.UIAgent",
                executablePath: AuthenticationPresenterMatcher.coreAuthenticationPath,
                focusedFrame: CGRect(x: 100, y: 200, width: 260, height: 289),
                displays: [display]
            )
        )

        XCTAssertEqual(snapshot.identity, .accessibility(processID: 321))
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
                bundleIdentifier: "com.apple.LocalAuthentication.UIAgent",
                executablePath: AuthenticationPresenterMatcher.coreAuthenticationPath,
                focusedFrame: nil,
                displays: [display]
            )
        )
        XCTAssertNil(
            AuthenticationWindowSnapshotFactory.accessibilitySnapshot(
                processID: 321,
                bundleIdentifier: "com.apple.LocalAuthentication.UIAgent",
                executablePath: AuthenticationPresenterMatcher.coreAuthenticationPath,
                focusedFrame: CGRect(x: 100, y: 200, width: 179, height: 119),
                displays: [display]
            )
        )
    }

    func testTreatsCoreGraphicsAndAccessibilityViewsOfSameWindowAsOnePrompt() {
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

        XCTAssertTrue(
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
            identity: .accessibility(processID: 654),
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

    func testAccessibilityFallbackUsesUniqueCoreGraphicsMatch() throws {
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

        XCTAssertEqual(
            AuthenticationWindowAccessibilityFallback.resolve(
                coreGraphicsCandidates: [coreGraphics],
                accessibilityCandidate: accessibility
            ),
            coreGraphics
        )
    }

    func testAccessibilityFallbackRejectsAmbiguousSameFrameWindows() {
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
            identity: .accessibility(processID: 321),
            processID: 321,
            frame: frame
        )

        XCTAssertNil(
            AuthenticationWindowAccessibilityFallback.resolve(
                coreGraphicsCandidates: [first, second],
                accessibilityCandidate: accessibility
            )
        )
    }

    func testAccessibilityFallbackUsesAXOnlyWhenNoCoreGraphicsCandidateExists() {
        let accessibility = authenticationWindow(
            identity: .accessibility(processID: 321),
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

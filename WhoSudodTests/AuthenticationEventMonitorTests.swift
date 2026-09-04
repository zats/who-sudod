import Darwin
import Foundation
import XCTest
@testable import WhoSudod

final class AuthenticationEventMonitorTests: XCTestCase {
    func testParsesDirectLocalAuthenticationEvaluation() throws {
        let receivedAt = Date(timeIntervalSince1970: 123)
        let line = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive,SPI,Biometry",
            message: "evaluatePolicy:1008 options:{\n} on LAContext[1:2:3]",
            processID: 82380,
            processImagePath: "/System/Library/ExtensionKit/Extensions/SecurityPrivacyExtension.appex/Contents/MacOS/SecurityPrivacyExtension"
        )

        let event = AuthenticationLogEventParser.parse(line: line, receivedAt: receivedAt)

        XCTAssertEqual(
            event,
            AuthenticationClientEvent(
                processID: 82380,
                executablePath: "/System/Library/ExtensionKit/Extensions/SecurityPrivacyExtension.appex/Contents/MacOS/SecurityPrivacyExtension",
                receivedAt: receivedAt,
                source: .localAuthentication
            )
        )
    }

    func testParsesInteractiveAccessControlEvaluation() throws {
        let receivedAt = Date(timeIntervalSince1970: 234)
        let line = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive,SPI",
            message: "evaluateAccessControl:<SecAccessControlRef> operation:3 options:{} on LAContext[2:3:4]",
            processID: 56018,
            processImagePath: "/Applications/Example.app/Contents/MacOS/Example"
        )

        let event = AuthenticationLogEventParser.parse(line: line, receivedAt: receivedAt)

        XCTAssertEqual(
            event,
            AuthenticationClientEvent(
                processID: 56018,
                executablePath: "/Applications/Example.app/Contents/MacOS/Example",
                receivedAt: receivedAt,
                source: .localAuthentication
            )
        )
    }

    func testRejectsEmbeddedLocalAuthenticationViewEvaluation() throws {
        let line = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy:1 options:{} on LAContext[1:335:481 uiDelegate:<LACUIAuthenticationViewModel: 0x75231c0780>] (async) cid:5",
            processID: 68799,
            processImagePath: "/Applications/Example.app/Contents/MacOS/Example"
        )

        XCTAssertNil(AuthenticationLogEventParser.parse(line: line, receivedAt: Date()))
    }

    func testParsesInteractiveAuthorizationEvaluation() throws {
        let receivedAt = Date(timeIntervalSince1970: 456)
        let line = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "Process /Applications/Example App.app/Contents/MacOS/Example App (PID 42937) evaluates 1 rights with flags 0000000b (engine 176, token 103)",
            processID: 513,
            processImagePath: "/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/authd.xpc/Contents/MacOS/authd"
        )

        let event = AuthenticationLogEventParser.parse(line: line, receivedAt: receivedAt)

        XCTAssertEqual(
            event,
            AuthenticationClientEvent(
                processID: 42937,
                executablePath: "/Applications/Example App.app/Contents/MacOS/Example App",
                receivedAt: receivedAt,
                source: .authorization
            )
        )
    }

    func testAuthorizationEventRequiresMatchingInteractiveMechanism() throws {
        let receivedAt = Date(timeIntervalSince1970: 456)
        let correlator = AuthenticationLogEventCorrelator()
        let evaluation = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "Process /usr/bin/osascript (PID 42937) evaluates 1 rights with flags 00000013 (engine 176, token 103): (",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
        let wrongEngine = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "engine 177: running mechanism builtin:authenticate (1 of 3)",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
        let noninteractiveMechanism = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "engine 176: running mechanism builtin:entitled (1 of 2)",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
        let matchingMechanism = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "engine 176: running mechanism builtin:authenticate (1 of 3)",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )

        XCTAssertNil(correlator.ingest(line: evaluation, receivedAt: receivedAt))
        XCTAssertNil(correlator.ingest(line: wrongEngine, receivedAt: receivedAt.addingTimeInterval(0.1)))
        XCTAssertNil(correlator.ingest(line: noninteractiveMechanism, receivedAt: receivedAt.addingTimeInterval(0.2)))
        XCTAssertEqual(
            correlator.ingest(
                line: matchingMechanism,
                receivedAt: receivedAt.addingTimeInterval(0.3)
            ),
            AuthenticationClientEvent(
                processID: 42937,
                executablePath: "/usr/bin/osascript",
                receivedAt: receivedAt.addingTimeInterval(0.3),
                source: .authorization
            )
        )
    }

    func testAuthorizationCorrelationUsesDelayedMechanismTime() throws {
        let evaluationTime = Date(timeIntervalSince1970: 456)
        let mechanismTime = evaluationTime.addingTimeInterval(5)
        let correlator = AuthenticationLogEventCorrelator()
        let evaluation = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "Process /usr/bin/osascript (PID 42937) evaluates 1 rights with flags 00000013 (engine 176, token 103): (",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
        let mechanism = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "engine 176: running mechanism builtin:authenticate (1 of 3)",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )

        XCTAssertNil(correlator.ingest(line: evaluation, receivedAt: evaluationTime))
        XCTAssertEqual(
            correlator.ingest(line: mechanism, receivedAt: mechanismTime),
            AuthenticationClientEvent(
                processID: 42937,
                executablePath: "/usr/bin/osascript",
                receivedAt: mechanismTime,
                source: .authorization
            )
        )
    }

    func testAuthorizationCorrelationExpires() throws {
        let receivedAt = Date(timeIntervalSince1970: 456)
        let correlator = AuthenticationLogEventCorrelator()
        let evaluation = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "Process /usr/bin/osascript (PID 42937) evaluates 1 rights with flags 00000013 (engine 176, token 103): (",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
        let mechanism = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "engine 176: running mechanism builtin:authenticate (1 of 3)",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )

        XCTAssertNil(correlator.ingest(line: evaluation, receivedAt: receivedAt))
        XCTAssertNil(
            correlator.ingest(
                line: mechanism,
                receivedAt: receivedAt.addingTimeInterval(10.001)
            )
        )
    }

    func testLocalAuthenticationLifecycleMatchesExactReturn() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let startDate = Date(timeIntervalSince1970: 500)
        let endDate = startDate.addingTimeInterval(2)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let start = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy:2 options:{} on LAContext[1:4551:4805] (async) cid:4",
            processID: 45849,
            processImagePath: path
        )
        let end = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy on LAContext[1:4551:4805] cid:4 returned success",
            processID: 45849,
            processImagePath: path
        )
        let requestIdentifier = AuthenticationRequestIdentifier.localAuthentication(
            LocalAuthenticationRequestKey(
                processID: 45849,
                executablePath: path,
                operation: .evaluatePolicy,
                contextComponents: [1, 4551, 4805],
                clientID: 4
            )
        )

        XCTAssertEqual(
            correlator.ingestLifecycle(line: start, receivedAt: startDate),
            .began(
                AuthenticationClientEvent(
                    processID: 45849,
                    executablePath: path,
                    receivedAt: startDate,
                    source: .localAuthentication,
                    requestIdentifier: requestIdentifier
                )
            )
        )
        XCTAssertEqual(
            correlator.ingestLifecycle(line: end, receivedAt: endDate),
            .ended(requestIdentifier, receivedAt: endDate)
        )
    }

    func testLocalAuthenticationLifecycleContinuesAcrossLogStreamRestart() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let startDate = Date(timeIntervalSince1970: 500)
        let endDate = startDate.addingTimeInterval(2)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let start = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy:2 options:{} on LAContext[1:4551:4805] (async) cid:4",
            processID: 45849,
            processImagePath: path
        )
        let end = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy on LAContext[1:4551:4805] cid:4 returned success",
            processID: 45849,
            processImagePath: path
        )
        let requestIdentifier = AuthenticationRequestIdentifier.localAuthentication(
            LocalAuthenticationRequestKey(
                processID: 45849,
                executablePath: path,
                operation: .evaluatePolicy,
                contextComponents: [1, 4551, 4805],
                clientID: 4
            )
        )

        XCTAssertNotNil(
            correlator.ingestLifecycle(line: start, receivedAt: startDate)
        )
        // AuthenticationEventMonitor retains this correlator when its log
        // subprocess restarts, so the exact completion still closes the request.
        XCTAssertEqual(
            correlator.ingestLifecycle(line: end, receivedAt: endDate),
            .ended(requestIdentifier, receivedAt: endDate)
        )
    }

    func testExplicitCorrelatorResetDropsInFlightRequest() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let date = Date(timeIntervalSince1970: 500)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let start = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy:2 options:{} on LAContext[1:4551:4805] (async) cid:4",
            processID: 45849,
            processImagePath: path
        )
        let end = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy on LAContext[1:4551:4805] cid:4 returned success",
            processID: 45849,
            processImagePath: path
        )

        XCTAssertNotNil(correlator.ingestLifecycle(line: start, receivedAt: date))
        correlator.reset()
        XCTAssertNil(
            correlator.ingestLifecycle(
                line: end,
                receivedAt: date.addingTimeInterval(1)
            )
        )
    }

    func testLocalAuthenticationKeyUsesFinalOperationalContext() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let date = Date(timeIntervalSince1970: 500)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let start = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy:2 options:{reason:\"approve on LAContext[9:8:7] cid:99\"} on LAContext[1:4551:4805] (async) cid:4",
            processID: 45849,
            processImagePath: path
        )
        let requestIdentifier = AuthenticationRequestIdentifier.localAuthentication(
            LocalAuthenticationRequestKey(
                processID: 45849,
                executablePath: path,
                operation: .evaluatePolicy,
                contextComponents: [1, 4551, 4805],
                clientID: 4
            )
        )

        XCTAssertEqual(
            correlator.ingestLifecycle(line: start, receivedAt: date),
            .began(
                AuthenticationClientEvent(
                    processID: 45849,
                    executablePath: path,
                    receivedAt: date,
                    source: .localAuthentication,
                    requestIdentifier: requestIdentifier
                )
            )
        )
    }

    func testLocalAuthenticationCompletionUsesOperationAnchoredContext() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let startDate = Date(timeIntervalSince1970: 500)
        let endDate = startDate.addingTimeInterval(2)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let start = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy:2 options:{} on LAContext[1:4551:4805] (async) cid:4",
            processID: 45849,
            processImagePath: path
        )
        let end = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy on LAContext[1:4551:4805] cid:4 returned error with reason on LAContext[9:8:7] cid:99",
            processID: 45849,
            processImagePath: path
        )
        let requestIdentifier = AuthenticationRequestIdentifier.localAuthentication(
            LocalAuthenticationRequestKey(
                processID: 45849,
                executablePath: path,
                operation: .evaluatePolicy,
                contextComponents: [1, 4551, 4805],
                clientID: 4
            )
        )

        XCTAssertNotNil(correlator.ingestLifecycle(line: start, receivedAt: startDate))
        XCTAssertEqual(
            correlator.ingestLifecycle(line: end, receivedAt: endDate),
            .ended(requestIdentifier, receivedAt: endDate)
        )
    }

    func testLocalAuthenticationKeySupportsObservedSheetContext() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let startDate = Date(timeIntervalSince1970: 500)
        let endDate = startDate.addingTimeInterval(2)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let start = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy:2 options:{} on LAContext[1:4969:5233 uiDelegate:<LACUIAuthenticationSheetViewModel: 0x1234>] (async) cid:8",
            processID: 45849,
            processImagePath: path
        )
        let end = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy on LAContext[1:4969:5233] cid:8 returned success",
            processID: 45849,
            processImagePath: path
        )
        let requestIdentifier = AuthenticationRequestIdentifier.localAuthentication(
            LocalAuthenticationRequestKey(
                processID: 45849,
                executablePath: path,
                operation: .evaluatePolicy,
                contextComponents: [1, 4969, 5233],
                clientID: 8
            )
        )

        XCTAssertEqual(
            correlator.ingestLifecycle(line: start, receivedAt: startDate),
            .began(
                AuthenticationClientEvent(
                    processID: 45849,
                    executablePath: path,
                    receivedAt: startDate,
                    source: .localAuthentication,
                    requestIdentifier: requestIdentifier
                )
            )
        )
        XCTAssertEqual(
            correlator.ingestLifecycle(line: end, receivedAt: endDate),
            .ended(requestIdentifier, receivedAt: endDate)
        )
    }

    func testLocalAuthenticationKeyRejectsMalformedContextComponentsAndEarlyClientID() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let messages = [
            "evaluatePolicy:2 options:{} on LAContext[1:bad:2:3] (async) cid:4",
            "evaluatePolicy:2 options:{} on LAContext[1::2:3] (async) cid:4",
            "evaluatePolicy:2 options:{} on LAContext[1:2:3x] (async) cid:4",
            "evaluatePolicy:2 options:{} on LAContext[1:+2:3] (async) cid:4",
            "evaluatePolicy:2 options:{} on LAContext[1:2] (async) cid:4",
            "evaluatePolicy:2 cid:4 options:{} on LAContext[1:2:3]"
        ]

        for (offset, message) in messages.enumerated() {
            let line = try logLine(
                subsystem: "com.apple.LocalAuthentication",
                category: "Client,Interactive",
                message: message,
                processID: 45849,
                processImagePath: path
            )
            guard case let .began(event)? = correlator.ingestLifecycle(
                line: line,
                receivedAt: Date(timeIntervalSince1970: 500 + Double(offset))
            ) else {
                return XCTFail("Expected legacy local-authentication event for \(message)")
            }
            XCTAssertNil(event.requestIdentifier, message)
        }
    }

    func testLocalAuthenticationActiveRequestDoesNotExpireByTime() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let startDate = Date(timeIntervalSince1970: 500)
        let endDate = startDate.addingTimeInterval(601)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let start = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy:2 options:{} on LAContext[1:4551:4805] (async) cid:4",
            processID: 45849,
            processImagePath: path
        )
        let end = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy on LAContext[1:4551:4805] cid:4 returned success",
            processID: 45849,
            processImagePath: path
        )
        let requestIdentifier = AuthenticationRequestIdentifier.localAuthentication(
            LocalAuthenticationRequestKey(
                processID: 45849,
                executablePath: path,
                operation: .evaluatePolicy,
                contextComponents: [1, 4551, 4805],
                clientID: 4
            )
        )

        XCTAssertNotNil(correlator.ingestLifecycle(line: start, receivedAt: startDate))
        XCTAssertEqual(
            correlator.ingestLifecycle(line: end, receivedAt: endDate),
            .ended(requestIdentifier, receivedAt: endDate)
        )
    }

    func testLocalAuthenticationLifecycleRejectsWrongOrUnmatchedReturn() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let date = Date(timeIntervalSince1970: 500)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let unmatched = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy on LAContext[1:2:3] cid:9 returned success",
            processID: 45849,
            processImagePath: path
        )

        XCTAssertNil(
            correlator.ingestLifecycle(line: unmatched, receivedAt: date)
        )
    }

    func testAuthorizationLifecycleEndsAtEngineCompletionAfterInteractiveFailure() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let startDate = Date(timeIntervalSince1970: 500)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let evaluation = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "Process \(path) (PID 42937) evaluates 1 rights with flags 0000000b (engine 733, token 103): (",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
        let mechanism = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "engine 733: running mechanism builtin:authenticate (1 of 3)",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
        let failure = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "Failed to authorize right 'system.preferences' by client '\(path)' [42937] for authorization created by '\(path)' [42937] (B,0) (-60008) (engine 733)",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
        let completion = try authorizationCompletionLine(result: -60008, engineID: 733)
        let requestIdentifier = AuthenticationRequestIdentifier.authorization(
            authdProcessID: 513,
            engineID: 733
        )

        XCTAssertNil(
            correlator.ingestLifecycle(line: evaluation, receivedAt: startDate)
        )
        XCTAssertEqual(
            correlator.ingestLifecycle(
                line: mechanism,
                receivedAt: startDate.addingTimeInterval(1)
            ),
            .began(
                AuthenticationClientEvent(
                    processID: 42937,
                    executablePath: path,
                    receivedAt: startDate.addingTimeInterval(1),
                    source: .authorization,
                    requestIdentifier: requestIdentifier
                )
            )
        )
        XCTAssertNil(
            correlator.ingestLifecycle(
                line: failure,
                receivedAt: startDate.addingTimeInterval(2)
            )
        )
        XCTAssertEqual(
            correlator.ingestLifecycle(
                line: completion,
                receivedAt: startDate.addingTimeInterval(3)
            ),
            .ended(
                requestIdentifier,
                receivedAt: startDate.addingTimeInterval(3)
            )
        )
    }

    func testAuthorizationLifecycleEndsAtEngineCompletionAfterSuccess() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let startDate = Date(timeIntervalSince1970: 500)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let evaluation = try authorizationEvaluationLine(
            path: path,
            rightsCount: 1,
            engineID: 733
        )
        let mechanism = try authorizationMechanismLine(engineID: 733)
        let success = try authorizationSuccessLine(
            right: "system.preferences",
            engineID: 733
        )
        let completion = try authorizationCompletionLine(result: 0, engineID: 733)
        let requestIdentifier = AuthenticationRequestIdentifier.authorization(
            authdProcessID: 513,
            engineID: 733
        )

        XCTAssertNil(correlator.ingestLifecycle(line: evaluation, receivedAt: startDate))
        XCTAssertNotNil(
            correlator.ingestLifecycle(
                line: mechanism,
                receivedAt: startDate.addingTimeInterval(1)
            )
        )
        XCTAssertNil(
            correlator.ingestLifecycle(
                line: success,
                receivedAt: startDate.addingTimeInterval(2)
            )
        )
        XCTAssertEqual(
            correlator.ingestLifecycle(
                line: completion,
                receivedAt: startDate.addingTimeInterval(3)
            ),
            .ended(requestIdentifier, receivedAt: startDate.addingTimeInterval(3))
        )
    }

    func testAuthorizationPartialRightsEndsAfterOneSuccessAndEngineCompletion() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let startDate = Date(timeIntervalSince1970: 500)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let evaluation = try authorizationEvaluationLine(
            path: path,
            rightsCount: 2,
            engineID: 733,
            flags: "0000000f"
        )
        let mechanism = try authorizationMechanismLine(engineID: 733)
        let firstSuccess = try authorizationSuccessLine(
            right: "system.preferences",
            engineID: 733
        )
        let failedRight = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "Failed to authorize right 'system.preferences.admin' by client '\(path)' [42937] for authorization created by '\(path)' [42937] (F,0) (-60005) (engine 733)",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
        let completion = try authorizationCompletionLine(result: 0, engineID: 733)
        let requestIdentifier = AuthenticationRequestIdentifier.authorization(
            authdProcessID: 513,
            engineID: 733
        )

        XCTAssertNil(correlator.ingestLifecycle(line: evaluation, receivedAt: startDate))
        XCTAssertNotNil(
            correlator.ingestLifecycle(
                line: mechanism,
                receivedAt: startDate.addingTimeInterval(1)
            )
        )
        XCTAssertNil(
            correlator.ingestLifecycle(
                line: firstSuccess,
                receivedAt: startDate.addingTimeInterval(2)
            )
        )
        XCTAssertNil(
            correlator.ingestLifecycle(
                line: failedRight,
                receivedAt: startDate.addingTimeInterval(3)
            )
        )
        XCTAssertEqual(
            correlator.ingestLifecycle(
                line: completion,
                receivedAt: startDate.addingTimeInterval(4)
            ),
            .ended(requestIdentifier, receivedAt: startDate.addingTimeInterval(4))
        )
    }

    func testAuthorizationCompletionBeforeInteractiveMechanismPreventsLateBegin() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let startDate = Date(timeIntervalSince1970: 500)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let evaluation = try authorizationEvaluationLine(
            path: path,
            rightsCount: 2,
            engineID: 733
        )
        let mechanism = try authorizationMechanismLine(engineID: 733)
        let completion = try authorizationCompletionLine(result: -60007, engineID: 733)

        XCTAssertNil(correlator.ingestLifecycle(line: evaluation, receivedAt: startDate))
        XCTAssertNil(
            correlator.ingestLifecycle(
                line: completion,
                receivedAt: startDate.addingTimeInterval(0.5)
            )
        )
        XCTAssertNil(
            correlator.ingestLifecycle(
                line: mechanism,
                receivedAt: startDate.addingTimeInterval(1)
            )
        )
    }

    func testAuthorizationActiveRequestDoesNotExpireByTime() throws {
        let correlator = AuthenticationLogEventCorrelator()
        let startDate = Date(timeIntervalSince1970: 500)
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        let evaluation = try authorizationEvaluationLine(
            path: path,
            rightsCount: 1,
            engineID: 733
        )
        let mechanism = try authorizationMechanismLine(engineID: 733)
        let completion = try authorizationCompletionLine(result: 0, engineID: 733)
        let requestIdentifier = AuthenticationRequestIdentifier.authorization(
            authdProcessID: 513,
            engineID: 733
        )

        XCTAssertNil(correlator.ingestLifecycle(line: evaluation, receivedAt: startDate))
        XCTAssertNotNil(
            correlator.ingestLifecycle(
                line: mechanism,
                receivedAt: startDate.addingTimeInterval(1)
            )
        )
        let completionDate = startDate.addingTimeInterval(602)
        XCTAssertEqual(
            correlator.ingestLifecycle(line: completion, receivedAt: completionDate),
            .ended(requestIdentifier, receivedAt: completionDate)
        )
    }

    func testParsesOnlyExactAuthorizationCompletion() throws {
        let completion = try authorizationCompletionLine(result: -60008, engineID: 733)
        let expectedIdentifier = AuthenticationRequestIdentifier.authorization(
            authdProcessID: 513,
            engineID: 733
        )
        XCTAssertEqual(
            AuthenticationLogEventParser.parseRecord(
                line: completion,
                receivedAt: Date()
            ),
            .authorizationCompletion(expectedIdentifier)
        )

        for message in [
            "engine : authorize result: 0",
            "engine nope: authorize result: 0",
            "engine +733: authorize result: 0",
            "engine 733: authorize result:",
            "engine 733: authorize result: nope",
            "engine 733: authorize result: +0",
            "engine 733: authorize result: -60008 trailing"
        ] {
            let line = try logLine(
                subsystem: "com.apple.Authorization",
                category: "authd",
                message: message,
                processID: 513,
                processImagePath: "/usr/libexec/authd"
            )
            XCTAssertNil(
                AuthenticationLogEventParser.parseRecord(
                    line: line,
                    receivedAt: Date()
                ),
                message
            )
        }
    }

    func testRejectsSpoofedMalformedOrNoninteractiveAuthorizationEvaluations() throws {
        let records = [
            (
                "/Applications/Fake.app/Contents/MacOS/authd",
                "Process /Applications/Example.app/Contents/MacOS/Example (PID 47712) evaluates 1 rights with flags 0000000b"
            ),
            (
                "/usr/libexec/authd",
                "Process relative/path (PID 47712) evaluates 1 rights with flags 0000000b"
            ),
            (
                "/usr/libexec/authd",
                "Process /Applications/Example.app/Contents/MacOS/Example (PID 1) evaluates 1 rights with flags 0000000b"
            ),
            (
                "/usr/libexec/authd",
                "Process /Applications/Example.app/Contents/MacOS/Example (PID nope) evaluates 1 rights with flags 0000000b"
            ),
            (
                "/usr/libexec/authd",
                "Process /Applications/Example.app/Contents/MacOS/Example (PID 47712) evaluates 1 rights with flags 00000002"
            ),
            (
                "/usr/libexec/authd",
                "Process /Applications/Example.app/Contents/MacOS/Example (PID 47712) evaluates 0 rights with flags 0000000b (engine 176, token 103): ("
            ),
            (
                "/usr/libexec/authd",
                "Process /Applications/Example.app/Contents/MacOS/Example (PID 47712) evaluates 1 rights with flags fffffffff (engine 176, token 103): ("
            ),
            (
                "/usr/libexec/authd",
                "Process /Applications/Example.app/Contents/MacOS/Example (PID 47712) requested 1 rights with flags 0000000b"
            )
        ]

        for (path, message) in records {
            let line = try logLine(
                subsystem: "com.apple.Authorization",
                category: "authd",
                message: message,
                processID: 549,
                processImagePath: path
            )
            XCTAssertNil(AuthenticationLogEventParser.parse(line: line, receivedAt: Date()))
        }
    }

    func testRejectsCanEvaluateAndReturnedResultRecords() throws {
        let records = [
            "canEvaluatePolicy:1 on LAContext[1:2:3]",
            "evaluatePolicy on LAContext[1:2:3] cid:8 returned success",
            "evaluateAccessControl on LAContext[1:2:3] cid:8 returned success"
        ]

        for message in records {
            let line = try logLine(
                subsystem: "com.apple.LocalAuthentication",
                category: "Client,Interactive,Biometry",
                message: message,
                processID: 200,
                processImagePath: "/Applications/Example.app/Contents/MacOS/Example"
            )
            XCTAssertNil(AuthenticationLogEventParser.parse(line: line, receivedAt: Date()))
        }
    }

    func testRejectsNoninteractiveAccessControlPreflight() throws {
        let line = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,SPI",
            message: "evaluateAccessControl:<SecAccessControlRef> operation:3 options:{} on LAContext[2:3:4]",
            processID: 56018,
            processImagePath: "/Applications/Example.app/Contents/MacOS/Example"
        )

        XCTAssertNil(AuthenticationLogEventParser.parse(line: line, receivedAt: Date()))
    }

    func testRejectsUIBrokerProcesses() throws {
        let brokerPaths = [
            "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreauthd",
            "/System/Library/Frameworks/LocalAuthentication.framework/Support/coreautha.bundle/Contents/MacOS/coreautha",
            "/System/Library/Frameworks/Security.framework/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent",
            "/System/Library/Frameworks/Security.framework/authorizationhost",
            "/System/Library/PrivateFrameworks/LocalAuthenticationUI.framework/XPCServices/LocalAuthenticationRemoteService.xpc/Contents/MacOS/LocalAuthenticationRemoteService"
        ]

        for path in brokerPaths {
            let line = try logLine(
                subsystem: "com.apple.LocalAuthentication",
                category: "Client,Interactive,SPI",
                message: "evaluatePolicy:1 options:{}",
                processID: 200,
                processImagePath: path
            )
            XCTAssertNil(AuthenticationLogEventParser.parse(line: line, receivedAt: Date()), path)
        }
    }

    func testRejectsMalformedJSONNonabsolutePathsAndInvalidPIDs() throws {
        XCTAssertNil(AuthenticationLogEventParser.parse(line: "not JSON", receivedAt: Date()))

        for processID in [-1, 0, 1] {
            let line = try logLine(
                subsystem: "com.apple.LocalAuthentication",
                category: "Client,Interactive",
                message: "evaluatePolicy:1 options:{}",
                processID: processID,
                processImagePath: "/Applications/Example.app/Contents/MacOS/Example"
            )
            XCTAssertNil(AuthenticationLogEventParser.parse(line: line, receivedAt: Date()))
        }

        let relativePath = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client,Interactive",
            message: "evaluatePolicy:1 options:{}",
            processID: 200,
            processImagePath: "Applications/Example.app/Contents/MacOS/Example"
        )
        XCTAssertNil(AuthenticationLogEventParser.parse(line: relativePath, receivedAt: Date()))
    }

    func testRejectsSpoofedAuthorizationEvaluation() throws {
        let line = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "Process /Applications/Example.app/Contents/MacOS/Example (PID 42937) evaluates 1 rights with flags 0000000b",
            processID: 900,
            processImagePath: "/Applications/Example.app/Contents/MacOS/Example"
        )

        XCTAssertNil(AuthenticationLogEventParser.parse(line: line, receivedAt: Date()))
    }

    func testRejectsOldAuthorizationShellRecords() throws {
        for message in [
            "process: PID 1 is shell",
            "process: PID nope is shell",
            "process: PID 999999999999999999999999999 is shell",
            "process: PID 200 is not shell"
        ] {
            let line = try logLine(
                subsystem: "com.apple.Authorization",
                category: "authd",
                message: message,
                processID: 513,
                processImagePath: "/usr/libexec/authd"
            )
            XCTAssertNil(AuthenticationLogEventParser.parse(line: line, receivedAt: Date()))
        }
    }

    func testLifecycleEventQueuePreservesInsertionOrder() async {
        let queue = AuthenticationLifecycleEventQueue()
        let date = Date(timeIntervalSince1970: 500)
        let requestIdentifier = AuthenticationRequestIdentifier.authorization(
            authdProcessID: 513,
            engineID: 733
        )
        let expected: [AuthenticationLifecycleEvent] = [
            .began(
                AuthenticationClientEvent(
                    processID: 42937,
                    executablePath: "/usr/bin/osascript",
                    receivedAt: date,
                    source: .authorization,
                    requestIdentifier: requestIdentifier
                )
            ),
            .ended(requestIdentifier, receivedAt: date.addingTimeInterval(1)),
            .reset
        ]
        let reader = Task { () -> [AuthenticationLifecycleEvent] in
            var events: [AuthenticationLifecycleEvent] = []
            for await event in queue.stream {
                events.append(event)
            }
            return events
        }

        for event in expected {
            queue.yield(event)
        }
        queue.finish()

        let received = await reader.value
        XCTAssertEqual(received, expected)
    }

    private func authorizationEvaluationLine(
        path: String,
        rightsCount: UInt,
        engineID: UInt64,
        flags: String = "0000000b"
    ) throws -> String {
        try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "Process \(path) (PID 42937) evaluates \(rightsCount) rights with flags \(flags) (engine \(engineID), token 103): (",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
    }

    private func authorizationMechanismLine(engineID: UInt64) throws -> String {
        try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "engine \(engineID): running mechanism builtin:authenticate (1 of 3)",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
    }

    private func authorizationSuccessLine(
        right: String,
        engineID: UInt64
    ) throws -> String {
        try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "Succeeded authorizing right '\(right)' by client '/Applications/Example.app/Contents/MacOS/Example' [42937] for authorization created by '/Applications/Example.app/Contents/MacOS/Example' [42937] (2,0) (engine \(engineID))",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
    }

    private func authorizationCompletionLine(
        result: Int32,
        engineID: UInt64
    ) throws -> String {
        try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "engine \(engineID): authorize result: \(result)",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )
    }

    private func logLine(
        subsystem: String,
        category: String,
        message: String,
        processID: Int,
        processImagePath: String
    ) throws -> String {
        let data = try JSONSerialization.data(
            withJSONObject: [
                "subsystem": subsystem,
                "category": category,
                "eventMessage": message,
                "processID": processID,
                "processImagePath": processImagePath
            ],
            options: [.sortedKeys]
        )
        return String(decoding: data, as: UTF8.self)
    }
}

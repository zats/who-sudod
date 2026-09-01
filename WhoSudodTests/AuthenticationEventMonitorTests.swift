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

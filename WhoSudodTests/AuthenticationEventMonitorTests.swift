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

    func testParsesAuthorizationShellCallerPID() throws {
        let receivedAt = Date(timeIntervalSince1970: 456)
        let line = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "process: PID 42937 is shell",
            processID: 513,
            processImagePath: "/usr/libexec/authd"
        )

        let event = AuthenticationLogEventParser.parse(line: line, receivedAt: receivedAt)

        XCTAssertEqual(
            event,
            AuthenticationClientEvent(
                processID: 42937,
                executablePath: nil,
                receivedAt: receivedAt,
                source: .authorizationShell
            )
        )
    }

    func testRejectsCanEvaluateAndReturnedResultRecords() throws {
        let records = [
            "canEvaluatePolicy:1 on LAContext[1:2:3]",
            "evaluatePolicy on LAContext[1:2:3] cid:8 returned success"
        ]

        for message in records {
            let line = try logLine(
                subsystem: "com.apple.LocalAuthentication",
                category: "Client,Biometry",
                message: message,
                processID: 200,
                processImagePath: "/Applications/Example.app/Contents/MacOS/Example"
            )
            XCTAssertNil(AuthenticationLogEventParser.parse(line: line, receivedAt: Date()))
        }
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
                category: "Client,SPI",
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
                category: "Client",
                message: "evaluatePolicy:1 options:{}",
                processID: processID,
                processImagePath: "/Applications/Example.app/Contents/MacOS/Example"
            )
            XCTAssertNil(AuthenticationLogEventParser.parse(line: line, receivedAt: Date()))
        }

        let relativePath = try logLine(
            subsystem: "com.apple.LocalAuthentication",
            category: "Client",
            message: "evaluatePolicy:1 options:{}",
            processID: 200,
            processImagePath: "Applications/Example.app/Contents/MacOS/Example"
        )
        XCTAssertNil(AuthenticationLogEventParser.parse(line: relativePath, receivedAt: Date()))
    }

    func testRejectsSpoofedAuthorizationShellRecord() throws {
        let line = try logLine(
            subsystem: "com.apple.Authorization",
            category: "authd",
            message: "process: PID 42937 is shell",
            processID: 900,
            processImagePath: "/Applications/Example.app/Contents/MacOS/Example"
        )

        XCTAssertNil(AuthenticationLogEventParser.parse(line: line, receivedAt: Date()))
    }

    func testRejectsMalformedAuthorizationShellPID() throws {
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

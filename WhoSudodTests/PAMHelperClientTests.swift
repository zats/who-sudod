import Foundation
import XCTest
@testable import WhoSudod

@MainActor
final class PAMHelperClientTests: XCTestCase {
    func testIdentityErrorHandlerCanRunOnBackgroundQueue() async {
        let replyReceived = expectation(description: "Background XPC error reply")
        let connection = NSXPCConnection(
            machServiceName: "com.zats.WhoSudo.Tests.BackgroundErrorHelper",
            options: []
        )
        let completion = PAMHelperIdentityReply(connection: connection) { result in
            dispatchPrecondition(condition: .onQueue(.main))
            guard case .failure(.serviceUnavailable(let detail)) = result else {
                return XCTFail("Expected a service-unavailable result.")
            }
            XCTAssertEqual(detail, "Background XPC error.")
            replyReceived.fulfill()
        }
        let errorHandler = completion.errorHandler()

        DispatchQueue.global(qos: .userInitiated).async {
            errorHandler(
                NSError(
                    domain: "PAMHelperClientTests",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Background XPC error."]
                )
            )
        }

        await fulfillment(of: [replyReceived], timeout: 1)
    }

    func testBackgroundReplyCleansUpAndCompletesOnMainQueue() async {
        let replyReceived = expectation(description: "Main-queue reply")
        let connection = NSXPCConnection(
            machServiceName: "com.zats.WhoSudo.Tests.BackgroundReplyHelper",
            options: []
        )
        let completion = PAMHelperReply(
            connection: connection,
            retainedObject: nil
        ) { _, _ in
            dispatchPrecondition(condition: .onQueue(.main))
            replyReceived.fulfill()
        }

        DispatchQueue.global(qos: .userInitiated).async {
            completion.finish(PAMIntegrationStateCode.installed.rawValue, nil)
        }

        await fulfillment(of: [replyReceived], timeout: 1)
    }

    func testIdentityReplyTimeoutCompletesPendingCallOnce() async {
        let replyReceived = expectation(description: "Preflight timeout reply")
        replyReceived.assertForOverFulfill = true
        var replies: [Result<PAMHelperBuildIdentity, PAMHelperPreflightError>] = []
        let connection = NSXPCConnection(
            machServiceName: "com.zats.WhoSudo.Tests.UnavailableIdentityHelper",
            options: []
        )
        let completion = PAMHelperIdentityReply(connection: connection) { result in
            replies.append(result)
            replyReceived.fulfill()
        }

        completion.failIfPending(after: 0.01, detail: "Timed out.")

        await fulfillment(of: [replyReceived], timeout: 1)
        completion.finish(.failure(.identityMismatch))
        try? await Task.sleep(for: .milliseconds(25))
        XCTAssertEqual(replies.count, 1)
        guard case .failure(.serviceUnavailable(let detail)) = replies.first else {
            return XCTFail("Expected a service-unavailable result.")
        }
        XCTAssertEqual(detail, "Timed out.")
    }

    func testReplyTimeoutCompletesPendingCallOnce() async {
        let replyReceived = expectation(description: "Timeout reply")
        replyReceived.assertForOverFulfill = true
        var replies: [(Int, String?)] = []
        let connection = NSXPCConnection(
            machServiceName: "com.zats.WhoSudo.Tests.UnavailableHelper",
            options: []
        )
        let completion = PAMHelperReply(
            connection: connection,
            retainedObject: nil
        ) { code, detail in
            replies.append((code, detail))
            replyReceived.fulfill()
        }

        completion.failIfPending(after: 0.01, detail: "Timed out.")

        await fulfillment(of: [replyReceived], timeout: 1)
        completion.finish(PAMIntegrationStateCode.installed.rawValue, "Late reply.")
        try? await Task.sleep(for: .milliseconds(25))
        XCTAssertEqual(replies.count, 1)
        XCTAssertEqual(replies.first?.0, PAMHelperReplyCode.transportFailure)
        XCTAssertEqual(replies.first?.1, "Timed out.")
    }

    func testReplyBeforeTimeoutSuppressesTimeoutReply() async {
        let replyReceived = expectation(description: "Helper reply")
        replyReceived.assertForOverFulfill = true
        var replies: [(Int, String?)] = []
        let connection = NSXPCConnection(
            machServiceName: "com.zats.WhoSudo.Tests.AvailableHelper",
            options: []
        )
        let completion = PAMHelperReply(
            connection: connection,
            retainedObject: nil
        ) { code, detail in
            replies.append((code, detail))
            replyReceived.fulfill()
        }

        completion.failIfPending(after: 0.05, detail: "Timed out.")
        completion.finish(PAMIntegrationStateCode.installed.rawValue, "Installed.")

        await fulfillment(of: [replyReceived], timeout: 1)
        try? await Task.sleep(for: .milliseconds(100))
        XCTAssertEqual(replies.count, 1)
        XCTAssertEqual(replies.first?.0, PAMIntegrationStateCode.installed.rawValue)
        XCTAssertEqual(replies.first?.1, "Installed.")
    }

    func testMutationTransportFailurePreservesHelperDetail() async {
        let replyReceived = expectation(description: "Mutation transport failure")
        let connection = NSXPCConnection(
            machServiceName: "com.zats.WhoSudo.Tests.MutationTransportFailure",
            options: []
        )
        var receivedResult: PAMHelperMutationResult?
        let completion = PAMHelperMutationReply(
            connection: connection,
            retainedObject: nil
        ) { result in
            receivedResult = result
            replyReceived.fulfill()
        }

        completion.mutationReplyHandler()(
            PAMHelperReplyCode.transportFailure,
            nil,
            "The PAM helper is shutting down. Try again."
        )

        await fulfillment(of: [replyReceived], timeout: 1)
        XCTAssertEqual(
            receivedResult?.operationError,
            "The PAM helper is shutting down. Try again."
        )
        XCTAssertNil(receivedResult?.inspection)
    }

}

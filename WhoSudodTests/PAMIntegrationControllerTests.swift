import Foundation
import XCTest
@testable import WhoSudod

enum PAMTestCall: Equatable {
    case register
    case unregister
    case openApprovalSettings
    case preflight
    case authorize
    case status
    case install(Data)
    case uninstall(Data)
}

final class PAMTestCallRecorder {
    var calls: [PAMTestCall] = []
}

final class PAMTestLocalInspector {
    var inspection: PAMIntegrationInspection

    init(state: PAMIntegrationStateCode) {
        inspection = PAMIntegrationInspection(state: state, detail: nil)
    }
}

final class PAMTestUninstallRecoveryStore: PAMUninstallRecoveryStoring {
    var phase: PAMUninstallRecoveryPhase
    var loadError: Error?
    var saveError: Error?
    private(set) var savedPhases: [PAMUninstallRecoveryPhase] = []

    init(phase: PAMUninstallRecoveryPhase = .none) {
        self.phase = phase
    }

    func load() throws -> PAMUninstallRecoveryPhase {
        if let loadError {
            throw loadError
        }
        return phase
    }

    func save(_ phase: PAMUninstallRecoveryPhase) throws {
        savedPhases.append(phase)
        if let saveError {
            throw saveError
        }
        self.phase = phase
    }
}

struct PAMTestHelperResponse {
    let code: Int
    let detail: String?

    init(_ state: PAMIntegrationStateCode, detail: String? = nil) {
        code = state.rawValue
        self.detail = detail
    }

    init(code: Int, detail: String? = nil) {
        self.code = code
        self.detail = detail
    }
}

private func pamMutationResult(
    _ state: PAMIntegrationStateCode,
    detail: String? = nil,
    operationError: String? = nil
) -> PAMHelperMutationResult {
    PAMHelperMutationResult(
        inspection: PAMIntegrationInspection(state: state, detail: detail),
        operationError: operationError
    )
}

@MainActor
final class FakePAMHelperServiceController: PAMHelperServiceControlling {
    var state: PAMHelperServiceState
    var stateAfterRegister: PAMHelperServiceState?
    var registerError: Error?
    var unregisterError: Error?
    var completesUnregisterImmediately = true
    private var pendingUnregisterCompletion: (@MainActor (String?) -> Void)?

    private let recorder: PAMTestCallRecorder

    init(
        state: PAMHelperServiceState,
        stateAfterRegister: PAMHelperServiceState? = .enabled,
        recorder: PAMTestCallRecorder
    ) {
        self.state = state
        self.stateAfterRegister = stateAfterRegister
        self.recorder = recorder
    }

    func register() throws {
        recorder.calls.append(.register)
        if let stateAfterRegister {
            state = stateAfterRegister
        }
        if let registerError {
            throw registerError
        }
    }

    func unregister(completion: @escaping @MainActor (String?) -> Void) {
        recorder.calls.append(.unregister)
        guard completesUnregisterImmediately else {
            pendingUnregisterCompletion = completion
            return
        }
        completeUnregister(completion: completion)
    }

    func openApprovalSettings() {
        recorder.calls.append(.openApprovalSettings)
    }

    func finishPendingUnregister() {
        let completion = pendingUnregisterCompletion
        pendingUnregisterCompletion = nil
        guard let completion else {
            return
        }
        completeUnregister(completion: completion)
    }

    private func completeUnregister(
        completion: @escaping @MainActor (String?) -> Void
    ) {
        if let unregisterError {
            completion(unregisterError.localizedDescription)
        } else {
            state = .notRegistered
            completion(nil)
        }
    }
}

@MainActor
final class FakePAMHelperClient: PAMHelperCalling {
    let buildIdentity = PAMHelperBuildIdentity(
        applicationCodeDirectoryHash: Data([0x41, 0x50, 0x50]),
        helperCodeDirectoryHash: Data([0x48, 0x45, 0x4C, 0x50])
    )
    var preflightResults: [Result<PAMHelperBuildIdentity, PAMHelperPreflightError>] = []
    var statusResponse: PAMTestHelperResponse? = PAMTestHelperResponse(.notInstalled)
    var installResponse: PAMHelperMutationResult? = pamMutationResult(.installed)
    var uninstallResponse: PAMHelperMutationResult? = pamMutationResult(.notInstalled)

    private(set) var pendingStatusReply: ((Int, String?) -> Void)?
    private(set) var pendingInstallReply: ((PAMHelperMutationResult) -> Void)?
    private(set) var pendingUninstallReply: ((PAMHelperMutationResult) -> Void)?
    private let recorder: PAMTestCallRecorder
    private(set) var installBuildIdentity: PAMHelperBuildIdentity?
    private(set) var uninstallBuildIdentity: PAMHelperBuildIdentity?

    init(recorder: PAMTestCallRecorder) {
        self.recorder = recorder
    }

    func preflight(
        reply: @escaping (Result<PAMHelperBuildIdentity, PAMHelperPreflightError>) -> Void
    ) {
        recorder.calls.append(.preflight)
        let result = preflightResults.isEmpty
            ? Result<PAMHelperBuildIdentity, PAMHelperPreflightError>.success(buildIdentity)
            : preflightResults.removeFirst()
        reply(result)
    }

    func status(
        expectedBuildIdentity: PAMHelperBuildIdentity,
        reply: @escaping (Int, String?) -> Void
    ) {
        recorder.calls.append(.status)
        guard let statusResponse else {
            pendingStatusReply = reply
            return
        }
        reply(statusResponse.code, statusResponse.detail)
    }

    func install(
        authorization: PAMOperationAuthorization,
        expectedBuildIdentity: PAMHelperBuildIdentity,
        reply: @escaping (PAMHelperMutationResult) -> Void
    ) {
        installBuildIdentity = expectedBuildIdentity
        recorder.calls.append(.install(authorization.externalFormData))
        guard let installResponse else {
            pendingInstallReply = reply
            return
        }
        reply(installResponse)
    }

    func uninstall(
        authorization: PAMOperationAuthorization,
        expectedBuildIdentity: PAMHelperBuildIdentity,
        reply: @escaping (PAMHelperMutationResult) -> Void
    ) {
        uninstallBuildIdentity = expectedBuildIdentity
        recorder.calls.append(.uninstall(authorization.externalFormData))
        guard let uninstallResponse else {
            pendingUninstallReply = reply
            return
        }
        reply(uninstallResponse)
    }

    func completeStatus(with response: PAMTestHelperResponse) {
        let reply = pendingStatusReply
        pendingStatusReply = nil
        reply?(response.code, response.detail)
    }

    func completeInstall(with response: PAMHelperMutationResult) {
        let reply = pendingInstallReply
        pendingInstallReply = nil
        reply?(response)
    }

    func completeUninstall(with response: PAMHelperMutationResult) {
        let reply = pendingUninstallReply
        pendingUninstallReply = nil
        reply?(response)
    }
}

final class FakePAMOperationAuthorizer: PAMOperationAuthorizing {
    var result: Result<PAMOperationAuthorization, Error>

    private let recorder: PAMTestCallRecorder

    init(
        result: Result<PAMOperationAuthorization, Error>,
        recorder: PAMTestCallRecorder
    ) {
        self.result = result
        self.recorder = recorder
    }

    func requestAuthorization() throws -> PAMOperationAuthorization {
        recorder.calls.append(.authorize)
        return try result.get()
    }
}

private enum PAMControllerTestError: LocalizedError {
    case registration
    case authorization
    case unregistration
    case recoveryWrite

    var errorDescription: String? {
        switch self {
        case .registration:
            "Registration failed."
        case .authorization:
            "Authorization failed."
        case .unregistration:
            "Unregistration failed."
        case .recoveryWrite:
            "Recovery write failed."
        }
    }
}

@MainActor
final class PAMIntegrationControllerTests: XCTestCase {
    func testExactHelperRequirementIncludesCodeDirectoryHash() throws {
        let identity = PAMHelperBuildIdentity(
            applicationCodeDirectoryHash: Data(repeating: 0xAA, count: 20),
            helperCodeDirectoryHash: Data(repeating: 0xBB, count: 20)
        )

        let requirement = try identity.exactHelperSigningRequirement()

        XCTAssertTrue(requirement.contains(PAMIntegrationConstants.helperSigningRequirement))
        XCTAssertTrue(requirement.contains("cdhash H\"\(String(repeating: "bb", count: 20))\""))
        XCTAssertEqual(identity.token.count, 32)
        XCTAssertTrue(identity.matches(token: identity.token))
        XCTAssertFalse(identity.matches(token: Data(repeating: 0, count: 32)))
    }

    func testInstallRegistersHelperBeforeAuthorizationAndInstallCall() {
        let values = dependencies(serviceState: .notRegistered)

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [.register, .preflight, .authorize, .install(values.authorization)]
        )
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertEqual(values.controller.snapshot.helper, .enabled)
        XCTAssertNil(values.controller.snapshot.operationError)
    }

    func testInstallUsesEnabledHelperWithoutRegisteringAgain() {
        let values = dependencies(serviceState: .enabled)

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .authorize, .install(values.authorization)]
        )
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertEqual(values.helper.installBuildIdentity, values.helper.buildIdentity)
    }

    func testInstallWaitsForSafeUnregisterBeforeReplacingMismatchedHelper() {
        let values = dependencies(serviceState: .enabled)
        values.helper.preflightResults = [.failure(.identityMismatch)]
        values.service.completesUnregisterImmediately = false

        values.controller.install()

        XCTAssertEqual(values.recorder.calls, [.preflight, .unregister])

        values.service.finishPendingUnregister()

        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .unregister,
                .register,
                .preflight,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
    }

    func testInstallRecoversEnabledUnreachableHelperOnlyOnce() {
        let values = dependencies(serviceState: .enabled)
        values.helper.preflightResults = [
            .failure(.serviceUnavailable("Old helper did not start.")),
            .failure(.serviceUnavailable("New helper did not start.")),
        ]

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .unregister, .register, .preflight]
        )
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "New helper did not start."
        )
    }

    func testInvalidEmbeddedHelperDoesNotRemoveRegisteredServiceOrAuthorize() {
        let values = dependencies(serviceState: .enabled)
        values.helper.preflightResults = [
            .failure(.invalidEmbeddedBuild("Embedded helper is invalid."))
        ]

        values.controller.install()

        XCTAssertEqual(values.recorder.calls, [.preflight])
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "Embedded helper is invalid."
        )
    }

    func testInstallOpensApprovalSettingsWhenRegistrationNeedsApproval() {
        let values = dependencies(serviceState: .notRegistered)
        values.service.stateAfterRegister = .requiresApproval

        values.controller.install()

        XCTAssertEqual(values.recorder.calls, [.register, .openApprovalSettings])
        XCTAssertEqual(values.controller.snapshot.helper, .requiresApproval)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "Allow the Who Sudo'd helper in Login Items, then try again."
        )
    }

    func testInstallOpensApprovalSettingsWhenRegistrationThrowsAfterApprovalIsRequired() {
        let values = dependencies(serviceState: .notRegistered)
        values.service.stateAfterRegister = .requiresApproval
        values.service.registerError = PAMControllerTestError.registration

        values.controller.install()

        XCTAssertEqual(values.recorder.calls, [.register, .openApprovalSettings])
        XCTAssertEqual(values.controller.snapshot.helper, .requiresApproval)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "Allow the Who Sudo'd helper in Login Items, then try again."
        )
    }

    func testInstallDoesNotAuthorizeWhenHelperIsUnavailable() {
        let values = dependencies(serviceState: .unavailable)

        values.controller.install()

        XCTAssertTrue(values.recorder.calls.isEmpty)
        XCTAssertEqual(values.controller.snapshot.helper, .unavailable)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "The PAM helper is missing from this application build."
        )
    }

    func testCancelledAuthorizationDoesNotCallHelperOrShowAnError() {
        let values = dependencies(
            serviceState: .enabled,
            authorizationResult: .failure(PAMOperationAuthorizationError.cancelled)
        )

        values.controller.install()

        XCTAssertEqual(values.recorder.calls, [.preflight, .authorize])
        XCTAssertNil(values.controller.snapshot.operationError)
    }

    func testAuthorizationFailureDoesNotCallHelperAndShowsError() {
        let values = dependencies(
            serviceState: .enabled,
            authorizationResult: .failure(PAMControllerTestError.authorization)
        )

        values.controller.install()

        XCTAssertEqual(values.recorder.calls, [.preflight, .authorize])
        XCTAssertEqual(values.controller.snapshot.operationError, "Authorization failed.")
    }

    func testInstallTransportFailureKeepsInstallActionRetryable() {
        let values = dependencies(serviceState: .enabled, localState: .notInstalled)
        values.helper.installResponse = .transportFailure(
            "The exact helper connection failed."
        )

        values.controller.install()

        XCTAssertEqual(values.controller.snapshot.integration.state, .notInstalled)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "The exact helper connection failed."
        )
    }

    func testRepairUsesTheInstallOperation() {
        let values = dependencies(serviceState: .enabled)
        values.helper.statusResponse = PAMTestHelperResponse(
            .needsRepair,
            detail: "Repair is required."
        )
        values.controller.refresh()
        values.recorder.calls.removeAll()

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .authorize, .install(values.authorization)]
        )
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertNil(values.controller.snapshot.operationError)
    }

    func testInstallIgnoresAnotherActionUntilTheHelperReplies() {
        let values = dependencies(serviceState: .enabled)
        values.helper.installResponse = nil

        values.controller.install()
        values.controller.install()
        values.controller.uninstall()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .authorize, .install(values.authorization)]
        )

        values.helper.completeInstall(with: pamMutationResult(.installed))
        values.controller.uninstall()

        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .authorize,
                .install(values.authorization),
                .preflight,
                .authorize,
                .uninstall(values.authorization),
                .unregister,
            ]
        )
    }

    func testUninstallAuthorizesThenCallsHelperThenUnregisters() {
        let values = dependencies(serviceState: .enabled)

        values.controller.uninstall()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .authorize, .uninstall(values.authorization), .unregister]
        )
        XCTAssertEqual(values.controller.snapshot.helper, .notRegistered)
        XCTAssertNil(values.controller.snapshot.operationError)
        XCTAssertEqual(values.helper.uninstallBuildIdentity, values.helper.buildIdentity)
    }

    func testUninstallWritesPendingPhaseBeforeHelperRepliesAndKeepsItOnFailure() {
        let values = dependencies(serviceState: .enabled)
        values.helper.uninstallResponse = nil

        values.controller.uninstall()

        XCTAssertEqual(values.recoveryStore.phase, .uninstallPending)

        values.helper.completeUninstall(
            with: pamMutationResult(
                .needsRepair,
                operationError: "Removal failed."
            )
        )

        XCTAssertEqual(values.recoveryStore.phase, .uninstallPending)
    }

    func testUninstallStopsBeforeHelperCallWhenPendingPhaseCannotBeSaved() {
        let values = dependencies(serviceState: .enabled)
        values.recoveryStore.saveError = PAMControllerTestError.recoveryWrite

        values.controller.uninstall()

        XCTAssertEqual(values.recorder.calls, [.preflight, .authorize])
        XCTAssertEqual(values.recoveryStore.savedPhases, [.uninstallPending])
        XCTAssertEqual(values.recoveryStore.phase, .none)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "Recovery write failed."
        )
    }

    func testUninstallTransportFailureKeepsPendingPhaseAndInspectedState() {
        let values = dependencies(serviceState: .enabled)
        values.helper.uninstallResponse = .transportFailure(
            "The exact helper connection failed."
        )

        values.controller.uninstall()

        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertEqual(values.recoveryStore.phase, .uninstallPending)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "The exact helper connection failed."
        )
    }

    func testUninstallDoesNotUnregisterWhenHelperReportsIntegrationStillPresent() {
        let values = dependencies(serviceState: .enabled)
        values.helper.uninstallResponse = pamMutationResult(
            .needsRepair,
            detail: "Installed files are incomplete.",
            operationError: "Removal failed."
        )

        values.controller.uninstall()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .authorize, .uninstall(values.authorization)]
        )
        XCTAssertEqual(values.controller.snapshot.integration.state, .needsRepair)
        XCTAssertEqual(
            values.controller.snapshot.integration.detail,
            "Installed files are incomplete."
        )
        XCTAssertEqual(values.controller.snapshot.operationError, "Removal failed.")
        XCTAssertTrue(values.controller.snapshot.uninstallPending)
        XCTAssertEqual(values.controller.snapshot.helper, .enabled)
    }

    func testUninstallOperationErrorKeepsPendingPhaseEvenWhenInspectionIsInstalled() {
        let values = dependencies(serviceState: .enabled)
        values.helper.uninstallResponse = pamMutationResult(
            .installed,
            operationError: "Removal failed."
        )

        values.controller.uninstall()

        XCTAssertEqual(values.recorder.calls, [
            .preflight,
            .authorize,
            .uninstall(values.authorization),
        ])
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertEqual(values.controller.snapshot.operationError, "Removal failed.")
        XCTAssertEqual(
            values.controller.snapshot.uninstallRecoveryPhase,
            .uninstallPending
        )
    }

    func testRelaunchedPendingUninstallRetriesMutationBeforeHelperCleanup() {
        let values = dependencies(
            serviceState: .enabled,
            localState: .needsRepair,
            recoveryPhase: .uninstallPending
        )

        values.controller.uninstall()

        XCTAssertEqual(values.recorder.calls, [
            .preflight,
            .authorize,
            .uninstall(values.authorization),
            .unregister,
        ])
        XCTAssertEqual(values.controller.snapshot.helper, .notRegistered)
        XCTAssertEqual(values.controller.snapshot.uninstallRecoveryPhase, .none)
    }

    func testRefreshMovesPendingUninstallToCleanupAfterConfirmedRemoval() {
        let values = dependencies(
            serviceState: .enabled,
            localState: .needsRepair,
            recoveryPhase: .uninstallPending
        )
        values.helper.statusResponse = PAMTestHelperResponse(.notInstalled)

        values.controller.refresh()

        XCTAssertEqual(values.recorder.calls, [.preflight, .status])
        XCTAssertEqual(
            values.controller.snapshot.uninstallRecoveryPhase,
            .helperCleanupRequired
        )
    }

    func testUnregisterFailureIsReported() {
        let values = dependencies(serviceState: .enabled)
        values.service.unregisterError = PAMControllerTestError.unregistration

        values.controller.uninstall()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .authorize, .uninstall(values.authorization), .unregister]
        )
        XCTAssertEqual(values.controller.snapshot.operationError, "Unregistration failed.")
        XCTAssertEqual(values.controller.snapshot.integration.state, .notInstalled)
        XCTAssertTrue(values.controller.snapshot.helperCleanupRequired)

        values.service.unregisterError = nil
        values.localInspector.inspection = PAMIntegrationInspection(
            state: .notInstalled,
            detail: nil
        )
        values.recorder.calls.removeAll()

        values.controller.finishRemoval()

        XCTAssertEqual(values.recorder.calls, [.unregister])
        XCTAssertEqual(values.controller.snapshot.helper, .notRegistered)
        XCTAssertFalse(values.controller.snapshot.helperCleanupRequired)
    }

    func testRefreshRequestsStatusFromEnabledHelper() {
        let values = dependencies(serviceState: .enabled)
        values.helper.statusResponse = PAMTestHelperResponse(
            .installed,
            detail: "Current state."
        )

        values.controller.refresh()

        XCTAssertEqual(values.recorder.calls, [.preflight, .status])
        XCTAssertEqual(
            values.controller.snapshot.integration,
            PAMIntegrationInspection(state: .installed, detail: "Current state.")
        )
        XCTAssertEqual(values.controller.snapshot.helper, .enabled)
        XCTAssertNil(values.controller.snapshot.operationError)
    }

    func testRefreshWaitsForAsynchronousHelperReply() {
        let values = dependencies(serviceState: .enabled)
        values.helper.statusResponse = nil

        values.controller.refresh()

        XCTAssertEqual(values.recorder.calls, [.preflight, .status])
        XCTAssertEqual(values.controller.snapshot.integration.state, .notInstalled)

        values.helper.completeStatus(with: PAMTestHelperResponse(.installed))

        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
    }

    func testPendingRefreshCannotOverwriteNewerInstallResult() {
        let values = dependencies(serviceState: .enabled)
        values.helper.statusResponse = nil

        values.controller.refresh()
        values.controller.install()
        values.helper.completeStatus(
            with: PAMTestHelperResponse(.needsRepair, detail: "Stale state.")
        )

        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .status,
                .preflight,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertNil(values.controller.snapshot.integration.detail)
    }

    func testRefreshDoesNotCallUnavailableHelper() {
        let values = dependencies(serviceState: .unavailable)

        values.controller.refresh()

        XCTAssertTrue(values.recorder.calls.isEmpty)
        XCTAssertEqual(values.controller.snapshot.helper, .unavailable)
        XCTAssertNil(values.controller.snapshot.operationError)
    }

    func testUnsupportedHelperReplyUsesItsDetailAsTheOperationError() {
        let values = dependencies(serviceState: .enabled)
        values.helper.statusResponse = PAMTestHelperResponse(
            .unsupported,
            detail: "Unsupported configuration."
        )

        values.controller.refresh()

        XCTAssertEqual(values.controller.snapshot.integration.state, .unsupported)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "Unsupported configuration."
        )
    }

    func testStatusTransportFailureUsesFreshLocalInspection() {
        let values = dependencies(serviceState: .enabled, localState: .installed)
        values.helper.statusResponse = PAMTestHelperResponse(
            code: PAMHelperReplyCode.transportFailure,
            detail: "The exact helper connection failed."
        )

        values.controller.refresh()

        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "The exact helper connection failed."
        )
    }

    func testUnknownHelperReplyIsReported() {
        let values = dependencies(serviceState: .enabled)
        values.helper.statusResponse = PAMTestHelperResponse(code: 99)

        values.controller.refresh()

        XCTAssertEqual(values.recorder.calls, [.preflight, .status])
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "The PAM helper returned an unknown state."
        )
    }

    private func dependencies(
        serviceState: PAMHelperServiceState,
        localState: PAMIntegrationStateCode = .installed,
        recoveryPhase: PAMUninstallRecoveryPhase = .none,
        authorizationResult: Result<PAMOperationAuthorization, Error>? = nil
    ) -> (
        controller: PAMIntegrationController,
        service: FakePAMHelperServiceController,
        helper: FakePAMHelperClient,
        authorizer: FakePAMOperationAuthorizer,
        recorder: PAMTestCallRecorder,
        authorization: Data,
        recoveryStore: PAMTestUninstallRecoveryStore,
        localInspector: PAMTestLocalInspector
    ) {
        let authorization = Data([0x57, 0x53])
        let recorder = PAMTestCallRecorder()
        let service = FakePAMHelperServiceController(
            state: serviceState,
            recorder: recorder
        )
        let helper = FakePAMHelperClient(recorder: recorder)
        let authorizationValue = PAMOperationAuthorization(
            externalFormData: authorization
        )
        let authorizer = FakePAMOperationAuthorizer(
            result: authorizationResult ?? .success(authorizationValue),
            recorder: recorder
        )
        let recoveryStore = PAMTestUninstallRecoveryStore(phase: recoveryPhase)
        let localInspector = PAMTestLocalInspector(state: localState)
        let controller = PAMIntegrationController(
            bundleURL: FileManager.default.temporaryDirectory
                .appendingPathComponent("PAMIntegrationControllerTests.app"),
            service: service,
            helper: helper,
            authorizer: authorizer,
            recoveryStore: recoveryStore,
            localInspection: {
                localInspector.inspection
            }
        )
        return (
            controller,
            service,
            helper,
            authorizer,
            recorder,
            authorization,
            recoveryStore,
            localInspector
        )
    }
}

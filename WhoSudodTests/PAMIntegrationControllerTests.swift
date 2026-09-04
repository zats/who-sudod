import Foundation
import ServiceManagement
@testable import WhoSudod
import XCTest

enum PAMTestCall: Equatable {
    case requestSystemAdministrationAccess
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
        expectedBuildIdentity _: PAMHelperBuildIdentity,
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

final class FakePAMSystemAdministrationAccessAuthorizer:
    PAMSystemAdministrationAccessAuthorizing
{
    var error: Error?

    private let recorder: PAMTestCallRecorder

    init(error: Error?, recorder: PAMTestCallRecorder) {
        self.error = error
        self.recorder = recorder
    }

    func requestAccess() throws {
        recorder.calls.append(.requestSystemAdministrationAccess)
        if let error {
            throw error
        }
    }
}

private enum PAMControllerTestError: LocalizedError {
    case systemAdministrationAccess
    case registration
    case authorization
    case unregistration
    case recoveryWrite

    var errorDescription: String? {
        switch self {
        case .systemAdministrationAccess:
            "System administration access failed."
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
    #if DEBUG
        func testDevelopmentBuildCannotRegisterTheProductionPAMService() {
            let service = SystemPAMHelperServiceController()

            XCTAssertEqual(service.state, .unavailable)
            XCTAssertThrowsError(try service.register()) { error in
                XCTAssertEqual(
                    error.localizedDescription,
                    "PAM registration is available only in Developer ID builds."
                )
            }
        }
    #endif

    func testNeverSeenPackagedHelperIsRegisterable() {
        XCTAssertEqual(
            SystemPAMHelperServiceController.resolvedState(
                for: .notFound,
                embeddedServiceExists: true
            ),
            .notRegistered
        )
    }

    func testMissingPackagedHelperIsUnavailable() {
        XCTAssertEqual(
            SystemPAMHelperServiceController.resolvedState(
                for: .notFound,
                embeddedServiceExists: false
            ),
            .unavailable
        )
    }

    func testConstructorSnapshotIsNotATrustedRefreshResult() {
        let values = dependencies(serviceState: .notRegistered)

        XCTAssertFalse(values.controller.hasCompletedRefresh)
        XCTAssertEqual(values.controller.snapshot.integration.state, .notInstalled)
    }

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

        XCTAssertFalse(values.controller.hasCompletedRefresh)
        XCTAssertEqual(
            values.recorder.calls,
            [
                .register,
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
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
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertEqual(values.helper.installBuildIdentity, values.helper.buildIdentity)
    }

    func testInstallWaitsForSafeUnregisterBeforeReplacingMismatchedHelper() {
        let values = dependencies(serviceState: .enabled)
        values.helper.preflightResults = [.failure(.identityMismatch)]
        values.service.completesUnregisterImmediately = false

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .unregister]
        )

        values.service.finishPendingUnregister()

        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .unregister,
                .register,
                .preflight,
                .requestSystemAdministrationAccess,
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
            [
                .preflight,
                .unregister,
                .register,
                .preflight,
            ]
        )
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "New helper did not start."
        )
    }

    func testInvalidEmbeddedHelperDoesNotRemoveRegisteredServiceOrAuthorize() {
        let values = dependencies(serviceState: .enabled)
        values.helper.preflightResults = [
            .failure(.invalidEmbeddedBuild("Embedded helper is invalid.")),
        ]

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight]
        )
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "Embedded helper is invalid."
        )
    }

    func testInstallOpensApprovalSettingsWhenRegistrationNeedsApproval() {
        let values = dependencies(serviceState: .notRegistered)
        values.service.stateAfterRegister = .requiresApproval

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [.register, .openApprovalSettings]
        )
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

        XCTAssertEqual(
            values.recorder.calls,
            [.register, .openApprovalSettings]
        )
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

    func testInstallAccessDenialStopsAfterHelperPreparationAndBeforeMutation() {
        let values = dependencies(
            serviceState: .notRegistered,
            systemAdministrationAccessError: PAMControllerTestError.systemAdministrationAccess
        )

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [.register, .preflight, .requestSystemAdministrationAccess]
        )
        XCTAssertEqual(values.service.state, .enabled)
        XCTAssertNil(values.helper.installBuildIdentity)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "System administration access failed."
        )
    }

    func testCancelledAuthorizationDoesNotCallHelperOrShowAnError() {
        let values = dependencies(
            serviceState: .enabled,
            authorizationResult: .failure(PAMOperationAuthorizationError.cancelled)
        )

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .requestSystemAdministrationAccess, .authorize]
        )
        XCTAssertNil(values.controller.snapshot.operationError)
    }

    func testAuthorizationFailureDoesNotCallHelperAndShowsError() {
        let values = dependencies(
            serviceState: .enabled,
            authorizationResult: .failure(PAMControllerTestError.authorization)
        )

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .requestSystemAdministrationAccess, .authorize]
        )
        XCTAssertEqual(values.controller.snapshot.operationError, "Authorization failed.")
    }

    func testInstallTransportFailureAllowsOnlySafeInstallRetry() {
        let values = dependencies(serviceState: .enabled, localState: .notInstalled)
        values.helper.installResponse = .transportFailure(
            "The exact helper connection failed."
        )

        values.controller.install()
        values.controller.uninstall()

        XCTAssertEqual(values.recoveryStore.phase, .installOutcomeUnknown)
        XCTAssertTrue(values.controller.snapshot.mutationOutcomeUnknown)
        XCTAssertFalse(values.controller.snapshot.operationInProgress)
        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )

        values.helper.installResponse = pamMutationResult(.installed)
        values.controller.install()

        XCTAssertEqual(values.recoveryStore.phase, .none)
        XCTAssertFalse(values.controller.snapshot.mutationOutcomeUnknown)
        XCTAssertFalse(values.controller.snapshot.operationInProgress)
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertNil(values.controller.snapshot.operationError)
    }

    func testMissingInstallReplyOffersSameMutationRetryAfterTheWatchdog() async {
        let values = dependencies(
            serviceState: .enabled,
            localState: .notInstalled,
            mutationReplyTimeout: .milliseconds(10)
        )
        values.helper.installResponse = nil

        values.controller.install()

        XCTAssertEqual(values.recoveryStore.phase, .installOutcomeUnknown)
        XCTAssertTrue(values.controller.snapshot.operationInProgress)

        try? await Task.sleep(for: .milliseconds(30))

        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(values.recoveryStore.phase, .installOutcomeUnknown)
        XCTAssertTrue(values.controller.snapshot.mutationOutcomeUnknown)
        XCTAssertFalse(values.controller.snapshot.operationInProgress)

        values.helper.installResponse = pamMutationResult(.installed)
        values.controller.install()

        XCTAssertEqual(values.recoveryStore.phase, .none)
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertFalse(values.controller.snapshot.operationInProgress)
    }

    func testLateInstallReplyStillCompletesTheOwnedUnknownMutation() async {
        let values = dependencies(
            serviceState: .enabled,
            localState: .notInstalled,
            mutationReplyTimeout: .milliseconds(10)
        )
        values.helper.installResponse = nil

        values.controller.install()
        try? await Task.sleep(for: .milliseconds(30))
        values.helper.completeInstall(with: pamMutationResult(.installed))

        XCTAssertEqual(values.recoveryStore.phase, .none)
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertFalse(values.controller.snapshot.mutationOutcomeUnknown)
        XCTAssertFalse(values.controller.snapshot.operationInProgress)
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
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertNil(values.controller.snapshot.operationError)
    }

    func testRepairAccessDenialStopsAfterHelperPreparationAndBeforeMutation() {
        let values = dependencies(
            serviceState: .enabled,
            systemAdministrationAccessError: PAMControllerTestError.systemAdministrationAccess
        )
        values.helper.statusResponse = PAMTestHelperResponse(
            .needsRepair,
            detail: "Repair is required."
        )
        values.controller.refresh()
        values.recorder.calls.removeAll()

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .requestSystemAdministrationAccess]
        )
        XCTAssertNil(values.helper.installBuildIdentity)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "System administration access failed."
        )
    }

    func testInstallIgnoresAnotherActionUntilTheHelperReplies() {
        let values = dependencies(serviceState: .enabled)
        values.helper.installResponse = nil

        values.controller.install()
        values.controller.install()
        values.controller.uninstall()

        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )

        values.helper.completeInstall(with: pamMutationResult(.installed))
        values.controller.uninstall()

        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
                .preflight,
                .requestSystemAdministrationAccess,
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
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .uninstall(values.authorization),
                .unregister,
            ]
        )
        XCTAssertEqual(values.controller.snapshot.helper, .notRegistered)
        XCTAssertNil(values.controller.snapshot.operationError)
        XCTAssertEqual(values.helper.uninstallBuildIdentity, values.helper.buildIdentity)
    }

    func testUninstallAccessDenialStopsAfterHelperPreparationAndBeforeMutation() {
        let values = dependencies(
            serviceState: .enabled,
            systemAdministrationAccessError: PAMControllerTestError.systemAdministrationAccess
        )

        values.controller.uninstall()

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .requestSystemAdministrationAccess]
        )
        XCTAssertNil(values.helper.uninstallBuildIdentity)
        XCTAssertTrue(values.recoveryStore.savedPhases.isEmpty)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "System administration access failed."
        )
    }

    func testUninstallWritesUnknownPhaseBeforeHelperRepliesAndMarksKnownFailurePending() {
        let values = dependencies(serviceState: .enabled)
        values.helper.uninstallResponse = nil

        values.controller.uninstall()

        XCTAssertEqual(values.recoveryStore.phase, .uninstallOutcomeUnknown)

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

        XCTAssertEqual(
            values.recorder.calls,
            [.preflight, .requestSystemAdministrationAccess, .authorize]
        )
        XCTAssertEqual(values.recoveryStore.savedPhases, [.uninstallOutcomeUnknown])
        XCTAssertEqual(values.recoveryStore.phase, .none)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "Recovery write failed."
        )
    }

    func testUninstallTransportFailureAllowsOnlySafeRemovalRetry() {
        let values = dependencies(serviceState: .enabled)
        values.helper.uninstallResponse = .transportFailure(
            "The exact helper connection failed."
        )

        values.controller.uninstall()
        values.controller.install()

        XCTAssertEqual(values.recoveryStore.phase, .uninstallOutcomeUnknown)
        XCTAssertTrue(values.controller.snapshot.mutationOutcomeUnknown)
        XCTAssertFalse(values.controller.snapshot.operationInProgress)

        values.helper.uninstallResponse = pamMutationResult(.notInstalled)
        values.controller.uninstall()

        XCTAssertEqual(values.controller.snapshot.integration.state, .notInstalled)
        XCTAssertEqual(values.recoveryStore.phase, .none)
        XCTAssertEqual(values.controller.snapshot.helper, .notRegistered)
        XCTAssertFalse(values.controller.snapshot.mutationOutcomeUnknown)
        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .uninstall(values.authorization),
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .uninstall(values.authorization),
                .unregister,
            ]
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
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .uninstall(values.authorization),
            ]
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
            .requestSystemAdministrationAccess,
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
            .requestSystemAdministrationAccess,
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
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .uninstall(values.authorization),
                .unregister,
            ]
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

        XCTAssertTrue(values.controller.hasCompletedRefresh)
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

        XCTAssertFalse(values.controller.hasCompletedRefresh)
        XCTAssertEqual(values.recorder.calls, [.preflight, .status])
        XCTAssertEqual(values.controller.snapshot.integration.state, .notInstalled)

        values.helper.completeStatus(with: PAMTestHelperResponse(.installed))

        XCTAssertTrue(values.controller.hasCompletedRefresh)
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
    }

    func testPersistedUnknownInstallAllowsOnlyTheSameMutation() {
        let values = dependencies(
            serviceState: .enabled,
            localState: .notInstalled,
            recoveryPhase: .installOutcomeUnknown
        )

        values.controller.uninstall()

        XCTAssertTrue(values.recorder.calls.isEmpty)
        XCTAssertTrue(values.controller.snapshot.mutationOutcomeUnknown)

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(values.recoveryStore.phase, .none)
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertFalse(values.controller.snapshot.mutationOutcomeUnknown)
        XCTAssertFalse(values.controller.snapshot.operationInProgress)
    }

    func testPersistedUnknownInstallRegistersMissingHelperBeforeRetry() {
        let values = dependencies(
            serviceState: .notRegistered,
            localState: .notInstalled,
            recoveryPhase: .installOutcomeUnknown
        )

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [
                .register,
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(values.recoveryStore.phase, .none)
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
    }

    func testPersistedUnknownInstallReplacesMismatchedHelperBeforeRetry() {
        let values = dependencies(
            serviceState: .enabled,
            localState: .needsRepair,
            recoveryPhase: .installOutcomeUnknown
        )
        values.helper.preflightResults = [
            .failure(.identityMismatch),
            .success(values.helper.buildIdentity),
        ]

        values.controller.install()

        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .unregister,
                .register,
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(values.recoveryStore.phase, .none)
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
    }

    func testRefreshKeepsUnknownOutcomeAndDoesNotUseUnorderedStatus() {
        let values = dependencies(
            serviceState: .enabled,
            localState: .notInstalled,
            recoveryPhase: .installOutcomeUnknown
        )

        values.controller.refresh()

        XCTAssertEqual(values.recoveryStore.phase, .installOutcomeUnknown)
        XCTAssertTrue(values.controller.snapshot.mutationOutcomeUnknown)
        XCTAssertFalse(values.controller.snapshot.operationInProgress)
        XCTAssertTrue(values.recorder.calls.isEmpty)
    }

    func testLateInstallReplyCannotOverwriteACompletedRetry() async {
        let values = dependencies(
            serviceState: .enabled,
            localState: .notInstalled,
            mutationReplyTimeout: .milliseconds(10)
        )
        values.helper.installResponse = nil
        values.controller.install()
        let staleReply = values.helper.pendingInstallReply
        try? await Task.sleep(for: .milliseconds(30))

        values.helper.installResponse = pamMutationResult(.installed)
        values.controller.install()
        staleReply?(
            pamMutationResult(
                .needsRepair,
                detail: "Stale state.",
                operationError: "Stale failure."
            )
        )

        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertNil(values.controller.snapshot.integration.detail)
        XCTAssertNil(values.controller.snapshot.operationError)
    }

    func testPersistedUnknownUninstallRetriesTheRemovalMutation() {
        let values = dependencies(
            serviceState: .enabled,
            recoveryPhase: .uninstallOutcomeUnknown
        )

        values.controller.uninstall()

        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .uninstall(values.authorization),
                .unregister,
            ]
        )
        XCTAssertEqual(values.recoveryStore.phase, .none)
        XCTAssertFalse(values.controller.snapshot.mutationOutcomeUnknown)
        XCTAssertNil(values.controller.snapshot.operationError)
    }

    func testPendingRefreshCannotOverwriteNewerInstallResult() {
        let values = dependencies(serviceState: .enabled)
        values.helper.statusResponse = nil

        values.controller.refresh()
        values.controller.install()
        values.helper.completeStatus(
            with: PAMTestHelperResponse(.needsRepair, detail: "Stale state.")
        )

        XCTAssertFalse(values.controller.hasCompletedRefresh)
        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .status,
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertNil(values.controller.snapshot.integration.detail)
    }

    func testRefreshDoesNotCallUnavailableHelper() {
        let values = dependencies(serviceState: .unavailable)
        var observerSawCompletedRefresh = false
        values.controller.didChange = { _ in
            observerSawCompletedRefresh = values.controller.hasCompletedRefresh
        }

        values.controller.refresh()

        XCTAssertTrue(values.controller.hasCompletedRefresh)
        XCTAssertTrue(observerSawCompletedRefresh)
        XCTAssertTrue(values.recorder.calls.isEmpty)
        XCTAssertEqual(values.controller.snapshot.helper, .unavailable)
        XCTAssertNil(values.controller.snapshot.operationError)
    }

    func testRefreshReportsUnreachableHelperWithoutMutatingService() {
        let values = dependencies(serviceState: .enabled, localState: .installed)
        values.helper.preflightResults = [
            .failure(.serviceUnavailable("The old helper did not start.")),
        ]

        values.controller.refresh()

        XCTAssertTrue(values.controller.hasCompletedRefresh)
        XCTAssertEqual(values.recorder.calls, [.preflight])
        XCTAssertEqual(values.controller.snapshot.integration.state, .installed)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            "The old helper did not start."
        )
    }

    func testRefreshReportsMismatchedHelperWithoutMutatingService() {
        let values = dependencies(serviceState: .enabled, localState: .needsRepair)
        values.helper.preflightResults = [.failure(.identityMismatch)]

        values.controller.refresh()

        XCTAssertTrue(values.controller.hasCompletedRefresh)
        XCTAssertEqual(values.recorder.calls, [.preflight])
        XCTAssertEqual(values.controller.snapshot.integration.state, .needsRepair)
        XCTAssertEqual(
            values.controller.snapshot.operationError,
            PAMHelperBuildIdentityError.mismatch.errorDescription
        )
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
        systemAdministrationAccessError: Error? = nil,
        authorizationResult: Result<PAMOperationAuthorization, Error>? = nil,
        mutationReplyTimeout: Duration = .seconds(5)
    ) -> (
        controller: PAMIntegrationController,
        service: FakePAMHelperServiceController,
        helper: FakePAMHelperClient,
        systemAdministrationAccess: FakePAMSystemAdministrationAccessAuthorizer,
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
        let systemAdministrationAccess = FakePAMSystemAdministrationAccessAuthorizer(
            error: systemAdministrationAccessError,
            recorder: recorder
        )
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
            systemAdministrationAccess: systemAdministrationAccess,
            authorizer: authorizer,
            recoveryStore: recoveryStore,
            localInspection: {
                localInspector.inspection
            },
            mutationReplyTimeout: mutationReplyTimeout
        )
        return (
            controller,
            service,
            helper,
            systemAdministrationAccess,
            authorizer,
            recorder,
            authorization,
            recoveryStore,
            localInspector
        )
    }
}

import Foundation
import XCTest
@testable import WhoSudod

@MainActor
final class SettingsModelTests: XCTestCase {
    func testPaneSelectionDefaultsToGeneralAndPersists() {
        let defaults = isolatedUserDefaults()
        let firstValues = dependencies()
        let model = SettingsModel(
            pamIntegration: firstValues.controller,
            pamConversationError: nil,
            userDefaults: defaults
        )

        XCTAssertEqual(model.selectedPane, .general)
        model.selectedPane = .ignoredApps

        let restoredValues = dependencies()
        let restored = SettingsModel(
            pamIntegration: restoredValues.controller,
            pamConversationError: nil,
            userDefaults: defaults
        )
        XCTAssertEqual(restored.selectedPane, .ignoredApps)
    }

    func testNotInstalledPresentationOffersInstall() {
        let value = presentation(state: .notInstalled)

        XCTAssertNil(value.detail)
        XCTAssertEqual(value.action, .install)
        XCTAssertEqual(value.actionTitle, "Install…")
        XCTAssertFalse(value.isWarning)
        XCTAssertFalse(value.isLoading)
    }

    func testRefreshingPresentationDoesNotOfferAnAction() {
        let value = PAMSettingsPresentation(
            snapshot: snapshot(state: .notInstalled),
            conversationError: nil,
            isRefreshing: true
        )

        XCTAssertNil(value.detail)
        XCTAssertNil(value.action)
        XCTAssertTrue(value.actionTitle.isEmpty)
        XCTAssertFalse(value.isWarning)
        XCTAssertTrue(value.isLoading)
    }

    func testUnavailableHelperCannotInstall() {
        let value = presentation(
            state: .notInstalled,
            helper: .unavailable
        )

        XCTAssertNil(value.detail)
        XCTAssertNil(value.action)
        XCTAssertEqual(value.actionTitle, "PAM Unavailable")
        XCTAssertFalse(value.isWarning)
    }

    func testHelperThatNeedsApprovalStillOffersTheRequestedAction() {
        for state in [
            PAMIntegrationStateCode.notInstalled,
            .installed,
            .needsRepair,
            .removalOnly,
        ] {
            let value = presentation(state: state, helper: .requiresApproval)

            XCTAssertNotNil(value.action)
        }
    }

    func testInstalledPresentationOffersUninstall() {
        let value = presentation(state: .installed)

        XCTAssertNil(value.detail)
        XCTAssertEqual(value.action, .uninstall)
        XCTAssertEqual(value.actionTitle, "Uninstall…")
        XCTAssertFalse(value.isWarning)
    }

    func testNeedsRepairPresentationOffersRepair() {
        let value = presentation(
            state: .needsRepair,
            detail: "Installed files do not match."
        )

        XCTAssertEqual(value.detail, "Installed files do not match.")
        XCTAssertEqual(value.action, .repair)
        XCTAssertEqual(value.actionTitle, "Repair…")
        XCTAssertTrue(value.isWarning)
    }

    func testUnsupportedPresentationHasNoAction() {
        let value = presentation(
            state: .unsupported,
            detail: "Unsupported configuration."
        )

        XCTAssertEqual(value.detail, "Unsupported configuration.")
        XCTAssertNil(value.action)
        XCTAssertEqual(value.actionTitle, "PAM Unavailable")
        XCTAssertTrue(value.isWarning)
    }

    func testRemovalOnlyPresentationOffersUninstall() {
        let value = presentation(
            state: .removalOnly,
            detail: "The password entry cannot be changed safely."
        )

        XCTAssertEqual(value.detail, "The password entry cannot be changed safely.")
        XCTAssertEqual(value.action, .uninstall)
        XCTAssertEqual(value.actionTitle, "Uninstall…")
        XCTAssertTrue(value.isWarning)
    }

    func testOperationErrorTakesPriorityOverInspectionDetail() {
        let value = presentation(
            state: .installed,
            detail: "Inspection detail.",
            operationError: "Operation failed."
        )

        XCTAssertEqual(value.detail, "Operation failed.")
        XCTAssertTrue(value.isWarning)
    }

    func testConversationErrorAllowsOnlyRemovalOfPresentIntegration() {
        for state in [PAMIntegrationStateCode.installed, .needsRepair, .removalOnly] {
            let value = presentation(
                state: state,
                detail: "Integration detail.",
                conversationError: "Conversation server failed."
            )

            XCTAssertEqual(
                value.detail,
                "Conversation server failed. Integration detail."
            )
            XCTAssertEqual(value.action, .uninstall)
            XCTAssertEqual(value.actionTitle, "Uninstall…")
            XCTAssertTrue(value.isWarning)
        }

        for state in [PAMIntegrationStateCode.notInstalled, .unsupported] {
            let value = presentation(
                state: state,
                conversationError: "Conversation server failed."
            )

            XCTAssertEqual(value.detail, "Conversation server failed.")
            XCTAssertNil(value.action)
            XCTAssertEqual(value.actionTitle, "PAM Unavailable")
            XCTAssertTrue(value.isWarning)
        }
    }

    func testConversationErrorDoesNotOfferRemovalWhenHelperIsUnavailable() {
        let value = presentation(
            state: .installed,
            helper: .unavailable,
            conversationError: "Conversation server failed."
        )

        XCTAssertEqual(value.detail, "Conversation server failed.")
        XCTAssertNil(value.action)
        XCTAssertEqual(value.actionTitle, "PAM Unavailable")
        XCTAssertTrue(value.isWarning)
    }

    func testRequestAndCancelPAMActionUpdatesConfirmationState() {
        let values = dependencies()
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )

        model.requestPAMAction()

        XCTAssertEqual(model.pendingPAMAction, .install)
        XCTAssertTrue(model.isPAMConfirmationPresented)

        model.cancelPAMAction()

        XCTAssertNil(model.pendingPAMAction)
        XCTAssertFalse(model.isPAMConfirmationPresented)
    }

    func testConfirmInstallRunsAuthorizationAndHelperInstall() {
        let values = dependencies()
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )

        model.confirmPAMAction(.install)

        XCTAssertEqual(
            values.recorder.calls,
            [
                .requestSystemAdministrationAccess,
                .preflight,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(model.pamSnapshot.integration.state, .installed)
    }

    func testConfirmRepairRunsAuthorizationAndHelperInstall() {
        let values = dependencies(integrationState: .needsRepair)
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )
        values.recorder.calls.removeAll()

        model.confirmPAMAction(.repair)

        XCTAssertEqual(
            values.recorder.calls,
            [
                .requestSystemAdministrationAccess,
                .preflight,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(model.pamSnapshot.integration.state, .installed)
    }

    func testConfirmUninstallRunsAuthorizationHelperRemovalAndUnregistration() {
        let values = dependencies(integrationState: .installed)
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )
        values.recorder.calls.removeAll()

        model.confirmPAMAction(.uninstall)

        XCTAssertEqual(
            values.recorder.calls,
            [
                .requestSystemAdministrationAccess,
                .preflight,
                .authorize,
                .uninstall(values.authorization),
                .unregister,
            ]
        )
        XCTAssertEqual(model.pamSnapshot.helper, .notRegistered)
    }

    func testHelperCleanupFailureOffersFinishRemovalInsteadOfInstall() {
        let value = PAMSettingsPresentation(
            snapshot: PAMIntegrationSnapshot(
                integration: PAMIntegrationInspection(
                    state: .notInstalled,
                    detail: nil
                ),
                helper: .enabled,
                operationError: "Helper removal failed.",
                uninstallRecoveryPhase: .helperCleanupRequired
            ),
            conversationError: nil
        )

        XCTAssertEqual(value.detail, "Helper removal failed.")
        XCTAssertEqual(value.action, .finishRemoval)
        XCTAssertEqual(value.actionTitle, "Finish Removal…")
        XCTAssertTrue(value.isWarning)
    }

    func testPendingUninstallOffersRetryInsteadOfRepair() {
        let value = PAMSettingsPresentation(
            snapshot: PAMIntegrationSnapshot(
                integration: PAMIntegrationInspection(
                    state: .needsRepair,
                    detail: "Some installed files remain."
                ),
                helper: .enabled,
                operationError: "Removal failed.",
                uninstallRecoveryPhase: .uninstallPending
            ),
            conversationError: nil
        )

        XCTAssertEqual(value.detail, "Removal failed.")
        XCTAssertEqual(value.action, .uninstall)
        XCTAssertEqual(value.actionTitle, "Retry Removal…")
        XCTAssertTrue(value.isWarning)
    }

    func testRefreshShowsLoadingUntilHelperReplies() {
        let values = dependencies()
        values.helper.statusResponse = nil
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )

        model.refreshPAMIntegration()

        XCTAssertTrue(model.isPAMRefreshPending)
        XCTAssertTrue(model.pamPresentation.isLoading)
        XCTAssertEqual(values.recorder.calls, [.preflight, .status])

        values.helper.completeStatus(with: PAMTestHelperResponse(.installed))

        XCTAssertFalse(model.isPAMRefreshPending)
        XCTAssertFalse(model.pamPresentation.isLoading)
        XCTAssertEqual(model.pamSnapshot.integration.state, .installed)
    }

    func testRefreshDoesNotStartASecondStatusRequestWhileOneIsPending() {
        let values = dependencies()
        values.helper.statusResponse = nil
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )

        model.refreshPAMIntegration()
        model.refreshPAMIntegration()

        XCTAssertEqual(values.recorder.calls, [.preflight, .status])
    }

    private func presentation(
        state: PAMIntegrationStateCode,
        helper: PAMHelperServiceState = .enabled,
        detail: String? = nil,
        operationError: String? = nil,
        conversationError: String? = nil
    ) -> PAMSettingsPresentation {
        PAMSettingsPresentation(
            snapshot: snapshot(
                state: state,
                helper: helper,
                detail: detail,
                operationError: operationError
            ),
            conversationError: conversationError
        )
    }

    private func snapshot(
        state: PAMIntegrationStateCode,
        helper: PAMHelperServiceState = .enabled,
        detail: String? = nil,
        operationError: String? = nil
    ) -> PAMIntegrationSnapshot {
        PAMIntegrationSnapshot(
            integration: PAMIntegrationInspection(
                state: state,
                detail: detail
            ),
            helper: helper,
            operationError: operationError
        )
    }

    private func dependencies(
        integrationState: PAMIntegrationStateCode = .notInstalled
    ) -> (
        controller: PAMIntegrationController,
        service: FakePAMHelperServiceController,
        helper: FakePAMHelperClient,
        authorizer: FakePAMOperationAuthorizer,
        recorder: PAMTestCallRecorder,
        authorization: Data
    ) {
        let authorization = Data([0x57, 0x53])
        let recorder = PAMTestCallRecorder()
        let service = FakePAMHelperServiceController(
            state: .enabled,
            recorder: recorder
        )
        let helper = FakePAMHelperClient(recorder: recorder)
        helper.statusResponse = PAMTestHelperResponse(integrationState)
        let authorizer = FakePAMOperationAuthorizer(
            result: .success(
                PAMOperationAuthorization(externalFormData: authorization)
            ),
            recorder: recorder
        )
        let systemAdministrationAccess = FakePAMSystemAdministrationAccessAuthorizer(
            error: nil,
            recorder: recorder
        )
        let controller = PAMIntegrationController(
            bundleURL: FileManager.default.temporaryDirectory
                .appendingPathComponent("SettingsModelTests.app"),
            service: service,
            helper: helper,
            systemAdministrationAccess: systemAdministrationAccess,
            authorizer: authorizer,
            recoveryStore: PAMTestUninstallRecoveryStore(),
            localInspection: {
                PAMIntegrationInspection(state: integrationState, detail: nil)
            }
        )
        if integrationState != .notInstalled {
            controller.refresh()
        }
        return (
            controller,
            service,
            helper,
            authorizer,
            recorder,
            authorization
        )
    }

    private func isolatedUserDefaults() -> UserDefaults {
        let suiteName = "SettingsModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        addTeardownBlock {
            defaults.removePersistentDomain(forName: suiteName)
        }
        return defaults
    }
}

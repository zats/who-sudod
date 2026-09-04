import Foundation
@testable import WhoSudod
import XCTest

@MainActor
final class SettingsModelTests: XCTestCase {
    func testAccessibilityPermissionRefreshesFromSystemState() {
        var isTrusted = false
        let controller = AccessibilityPermissionController(
            isTrusted: { isTrusted },
            requestHandler: {}
        )

        XCTAssertFalse(controller.isGranted)
        isTrusted = true
        controller.refresh()

        XCTAssertTrue(controller.isGranted)
    }

    func testAccessibilityPermissionRequestsAccessOnlyWhenMissing() {
        var isTrusted = false
        var requestCount = 0
        let controller = AccessibilityPermissionController(
            isTrusted: { isTrusted },
            requestHandler: { requestCount += 1 }
        )

        controller.requestAccess()
        XCTAssertEqual(requestCount, 1)

        isTrusted = true
        controller.requestAccess()
        XCTAssertEqual(requestCount, 1)
        XCTAssertTrue(controller.isGranted)
    }

    func testAccessibilityPermissionAcceptsMonitorUpdates() {
        let controller = AccessibilityPermissionController(
            isTrusted: { false },
            requestHandler: {}
        )

        controller.update(isGranted: true)

        XCTAssertTrue(controller.isGranted)
    }

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

    func testUnknownInstallPresentationOffersSafeRetry() {
        let value = PAMSettingsPresentation(
            snapshot: PAMIntegrationSnapshot(
                integration: PAMIntegrationInspection(state: .notInstalled, detail: nil),
                helper: .enabled,
                operationError: "The helper connection closed.",
                uninstallRecoveryPhase: .installOutcomeUnknown
            ),
            conversationError: nil
        )

        XCTAssertEqual(value.detail, "The helper connection closed.")
        XCTAssertEqual(value.action, .install)
        XCTAssertEqual(value.actionTitle, "Retry Install…")
        XCTAssertTrue(value.isWarning)
        XCTAssertFalse(value.isLoading)
    }

    func testUnknownRemovalPresentationOffersOnlyRemovalRetry() {
        let value = PAMSettingsPresentation(
            snapshot: PAMIntegrationSnapshot(
                integration: PAMIntegrationInspection(state: .needsRepair, detail: nil),
                helper: .enabled,
                operationError: nil,
                uninstallRecoveryPhase: .uninstallOutcomeUnknown
            ),
            conversationError: nil
        )

        XCTAssertEqual(value.action, .uninstall)
        XCTAssertEqual(value.actionTitle, "Retry Removal…")
        XCTAssertTrue(value.isWarning)
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

    func testNotchActionIncludesOnlyInstallAndRepair() {
        XCTAssertEqual(
            presentation(state: .notInstalled).notchAction,
            PAMNotchAction(action: .install, title: "Install…")
        )
        XCTAssertEqual(
            presentation(state: .needsRepair).notchAction,
            PAMNotchAction(action: .repair, title: "Repair…")
        )

        for state in [
            PAMIntegrationStateCode.installed,
            .removalOnly,
            .unsupported,
        ] {
            XCTAssertNil(presentation(state: state).notchAction)
        }
        XCTAssertNil(
            presentation(
                state: .notInstalled,
                helper: .unavailable
            ).notchAction
        )
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

    func testRequestInstallRunsImmediatelyWithoutConfirmation() {
        let values = dependencies()
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )

        model.requestPAMAction()

        XCTAssertNil(model.pendingPAMConfirmation)
        XCTAssertFalse(model.isPAMConfirmationPresented)
        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(model.pamSnapshot.integration.state, .installed)
    }

    func testRequestRepairRunsImmediatelyWithoutConfirmation() {
        let values = dependencies(integrationState: .needsRepair)
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )
        values.recorder.calls.removeAll()

        model.requestPAMAction()

        XCTAssertNil(model.pendingPAMConfirmation)
        XCTAssertFalse(model.isPAMConfirmationPresented)
        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )
        XCTAssertEqual(model.pamSnapshot.integration.state, .installed)
    }

    func testRequestUninstallStillRequiresConfirmation() {
        let values = dependencies(integrationState: .installed)
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )
        values.recorder.calls.removeAll()

        model.requestPAMAction(.uninstall)

        XCTAssertEqual(model.pendingPAMConfirmation?.action, .uninstall)
        XCTAssertTrue(model.isPAMConfirmationPresented)
        XCTAssertTrue(values.recorder.calls.isEmpty)

        model.cancelPAMAction()

        XCTAssertNil(model.pendingPAMConfirmation)
        XCTAssertFalse(model.isPAMConfirmationPresented)
    }

    func testExplicitPAMActionRequestRejectsMismatchedAction() {
        let values = dependencies()
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )

        model.requestPAMAction(.repair)

        XCTAssertNil(model.pendingPAMConfirmation)
        XCTAssertFalse(model.isPAMConfirmationPresented)
        XCTAssertTrue(values.recorder.calls.isEmpty)
    }

    func testExplicitPAMActionRequestRejectsStaleAction() throws {
        let values = dependencies()
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )
        let staleAction = try XCTUnwrap(model.pamPresentation.notchAction?.action)
        values.helper.statusResponse = PAMTestHelperResponse(.installed)
        values.controller.refresh()
        values.recorder.calls.removeAll()

        model.requestPAMAction(staleAction)

        XCTAssertNil(model.pendingPAMConfirmation)
        XCTAssertFalse(model.isPAMConfirmationPresented)
        XCTAssertEqual(model.pamPresentation.action, .uninstall)
        XCTAssertTrue(values.recorder.calls.isEmpty)
    }

    func testOnlyRemovalActionsRequireConfirmation() {
        XCTAssertNil(PAMSettingsAction.install.confirmation)
        XCTAssertNil(PAMSettingsAction.repair.confirmation)
        XCTAssertNotNil(PAMSettingsAction.uninstall.confirmation)
        XCTAssertNotNil(PAMSettingsAction.finishRemoval.confirmation)
    }

    func testConfirmUninstallRunsAuthorizationHelperRemovalAndUnregistration() throws {
        let values = dependencies(integrationState: .installed)
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )
        values.recorder.calls.removeAll()

        model.requestPAMAction(.uninstall)
        let confirmation = try XCTUnwrap(model.pendingPAMConfirmation)
        model.confirmPAMAction(confirmation)

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
        XCTAssertEqual(model.pamSnapshot.helper, .notRegistered)
    }

    func testStaleRemovalConfirmationCannotRun() throws {
        let values = dependencies(integrationState: .installed)
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )
        values.recorder.calls.removeAll()

        model.requestPAMAction(.uninstall)
        let confirmation = try XCTUnwrap(model.pendingPAMConfirmation)
        values.helper.statusResponse = PAMTestHelperResponse(.notInstalled)
        values.controller.refresh()
        values.recorder.calls.removeAll()

        model.confirmPAMAction(confirmation)

        XCTAssertTrue(values.recorder.calls.isEmpty)
        XCTAssertNil(model.pendingPAMConfirmation)
        XCTAssertFalse(model.isPAMConfirmationPresented)
        XCTAssertEqual(model.pamPresentation.action, .install)
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

    func testRefreshDuringPendingMutationDoesNotShowLoading() {
        let values = dependencies()
        values.helper.installResponse = nil
        let model = SettingsModel(
            pamIntegration: values.controller,
            pamConversationError: nil,
            userDefaults: isolatedUserDefaults()
        )
        values.controller.install()

        model.refreshPAMIntegration()

        XCTAssertFalse(model.isPAMRefreshPending)
        XCTAssertFalse(model.pamPresentation.isLoading)
        XCTAssertNil(model.pamPresentation.action)
        XCTAssertEqual(model.pamPresentation.actionTitle, "Finishing…")
        XCTAssertEqual(
            values.recorder.calls,
            [
                .preflight,
                .requestSystemAdministrationAccess,
                .authorize,
                .install(values.authorization),
            ]
        )
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

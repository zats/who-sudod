import Foundation
import Observation

@MainActor
@Observable
final class AccessibilityPermissionController {
    private(set) var isGranted: Bool

    @ObservationIgnored private let isTrusted: () -> Bool
    @ObservationIgnored private let requestHandler: () -> Void

    init(
        isTrusted: @escaping () -> Bool,
        requestHandler: @escaping () -> Void
    ) {
        self.isTrusted = isTrusted
        self.requestHandler = requestHandler
        isGranted = isTrusted()
    }

    func refresh() {
        isGranted = isTrusted()
    }

    func update(isGranted: Bool) {
        self.isGranted = isGranted
    }

    func requestAccess() {
        refresh()
        guard !isGranted else {
            return
        }
        requestHandler()
    }
}

enum SettingsPane: String, CaseIterable, Identifiable {
    case general
    case ignoredApps

    static let selectionDefaultsKey = "settingsSelectedPane"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .general:
            "General"
        case .ignoredApps:
            "Ignored Apps"
        }
    }

    var systemImage: String {
        switch self {
        case .general:
            "gearshape.fill"
        case .ignoredApps:
            "eye.slash.fill"
        }
    }
}

enum PAMSettingsAction: Equatable {
    case install
    case repair
    case uninstall
    case finishRemoval

    var confirmation: PAMSettingsConfirmation? {
        switch self {
        case .uninstall:
            PAMSettingsConfirmation(
                action: self,
                title: "Uninstall PAM Password Input?",
                message: "This removes only the two Who Sudo'd sudo PAM entries and its installed components. Other PAM entries stay unchanged.",
                buttonTitle: "Uninstall"
            )
        case .finishRemoval:
            PAMSettingsConfirmation(
                action: self,
                title: "Finish PAM Removal?",
                message: "This removes the unused privileged helper registration. The PAM entries and installed components are already removed.",
                buttonTitle: "Finish Removal"
            )
        case .install, .repair:
            nil
        }
    }
}

struct PAMSettingsConfirmation: Equatable {
    let action: PAMSettingsAction
    let title: String
    let message: String
    let buttonTitle: String
}

struct PAMSettingsPresentation: Equatable {
    let detail: String?
    let action: PAMSettingsAction?
    let actionTitle: String
    let isWarning: Bool
    let isLoading: Bool

    var notchAction: PAMNotchAction? {
        guard let action, action == .install || action == .repair else {
            return nil
        }
        return PAMNotchAction(action: action, title: actionTitle)
    }

    init(
        snapshot: PAMIntegrationSnapshot,
        conversationError: String?,
        isRefreshing: Bool = false
    ) {
        let helperIsAvailable = snapshot.helper != .unavailable
        if isRefreshing {
            detail = nil
            action = nil
            actionTitle = ""
            isWarning = false
            isLoading = true
            return
        }

        if snapshot.operationInProgress {
            detail = nil
            action = nil
            actionTitle = "Finishing…"
            isWarning = false
            isLoading = false
            return
        }

        if snapshot.mutationOutcomeUnknown {
            detail = snapshot.operationError
                ?? "The last PAM change was not confirmed. Retry the same change."
            if !helperIsAvailable {
                action = nil
                actionTitle = "PAM Unavailable"
            } else {
                switch snapshot.uninstallRecoveryPhase {
                case .installOutcomeUnknown:
                    action = snapshot.integration.state == .needsRepair ? .repair : .install
                    actionTitle = snapshot.integration.state == .needsRepair
                        ? "Retry Repair…"
                        : "Retry Install…"
                case .uninstallOutcomeUnknown:
                    action = .uninstall
                    actionTitle = "Retry Removal…"
                case .none, .uninstallPending, .helperCleanupRequired:
                    action = nil
                    actionTitle = "PAM Unavailable"
                }
            }
            isWarning = true
            isLoading = false
            return
        }

        isLoading = false
        if snapshot.helperCleanupRequired {
            detail = snapshot.operationError
                ?? "PAM was removed, but its helper registration remains."
            if snapshot.helper == .notRegistered {
                action = nil
                actionTitle = "Removal Complete"
            } else {
                action = .finishRemoval
                actionTitle = "Finish Removal…"
            }
            isWarning = true
            return
        }
        if snapshot.uninstallPending {
            detail = snapshot.operationError
                ?? snapshot.integration.detail
                ?? "PAM removal did not finish."
            action = helperIsAvailable ? .uninstall : nil
            actionTitle = helperIsAvailable ? "Retry Removal…" : "PAM Unavailable"
            isWarning = true
            return
        }

        if let conversationError {
            detail = Self.joinedDetail(
                conversationError,
                snapshot.integration.detail
            )
            isWarning = true
            switch snapshot.integration.state {
            case .installed, .needsRepair, .removalOnly:
                action = helperIsAvailable ? .uninstall : nil
                actionTitle = helperIsAvailable
                    ? "Uninstall…"
                    : "PAM Unavailable"
            case .notInstalled, .unsupported:
                action = nil
                actionTitle = "PAM Unavailable"
            }
            return
        }

        detail = snapshot.operationError ?? snapshot.integration.detail
        switch snapshot.integration.state {
        case .notInstalled:
            if helperIsAvailable {
                action = .install
                actionTitle = "Install…"
            } else {
                action = nil
                actionTitle = "PAM Unavailable"
            }
            isWarning = detail != nil
        case .installed:
            action = helperIsAvailable ? .uninstall : nil
            actionTitle = helperIsAvailable ? "Uninstall…" : "PAM Unavailable"
            isWarning = detail != nil
        case .needsRepair:
            action = helperIsAvailable ? .repair : nil
            actionTitle = helperIsAvailable ? "Repair…" : "PAM Unavailable"
            isWarning = detail != nil
        case .removalOnly:
            action = helperIsAvailable ? .uninstall : nil
            actionTitle = helperIsAvailable ? "Uninstall…" : "PAM Unavailable"
            isWarning = detail != nil
        case .unsupported:
            action = nil
            actionTitle = "PAM Unavailable"
            isWarning = detail != nil
        }
    }

    private static func joinedDetail(_ values: String?...) -> String? {
        let detail = values
            .compactMap { value in
                guard let value, !value.isEmpty else {
                    return nil
                }
                return value
            }
            .joined(separator: " ")
        return detail.isEmpty ? nil : detail
    }
}

struct PAMNotchAction: Equatable {
    let action: PAMSettingsAction
    let title: String
}

@MainActor
@Observable
final class SettingsModel {
    var selectedPane: SettingsPane {
        didSet {
            userDefaults.set(
                selectedPane.rawValue,
                forKey: SettingsPane.selectionDefaultsKey
            )
        }
    }

    private(set) var pamSnapshot: PAMIntegrationSnapshot
    private(set) var pamConversationError: String?
    private(set) var pendingPAMConfirmation: PAMSettingsConfirmation?
    private(set) var isPAMRefreshPending = false
    var isPAMConfirmationPresented = false {
        didSet {
            if !isPAMConfirmationPresented {
                pendingPAMConfirmation = nil
            }
        }
    }

    @ObservationIgnored private let userDefaults: UserDefaults
    @ObservationIgnored private let pamIntegration: PAMIntegrationController

    init(
        pamIntegration: PAMIntegrationController,
        pamConversationError: String?,
        userDefaults: UserDefaults = .standard
    ) {
        self.pamIntegration = pamIntegration
        self.pamConversationError = pamConversationError
        self.userDefaults = userDefaults
        pamSnapshot = pamIntegration.snapshot
        let rawPane = userDefaults.string(forKey: SettingsPane.selectionDefaultsKey)
        selectedPane = rawPane.flatMap(SettingsPane.init(rawValue:)) ?? .general

        pamIntegration.didChange = { [weak self] snapshot in
            self?.pamSnapshot = snapshot
            self?.isPAMRefreshPending = false
        }
    }

    var pamPresentation: PAMSettingsPresentation {
        PAMSettingsPresentation(
            snapshot: pamSnapshot,
            conversationError: pamConversationError,
            isRefreshing: isPAMRefreshPending
        )
    }

    func refreshPAMIntegration() {
        guard !isPAMRefreshPending else {
            return
        }
        isPAMRefreshPending = true
        if !pamIntegration.refresh() {
            isPAMRefreshPending = false
        }
    }

    func updatePAMConversationError(_ error: String?) {
        pamConversationError = error
    }

    func requestPAMAction() {
        guard let action = pamPresentation.action else {
            return
        }
        requestPAMAction(action)
    }

    func requestPAMAction(_ action: PAMSettingsAction) {
        guard pamPresentation.action == action else {
            return
        }
        guard let confirmation = action.confirmation else {
            performPAMAction(action)
            return
        }
        pendingPAMConfirmation = confirmation
        isPAMConfirmationPresented = true
    }

    func cancelPAMAction() {
        isPAMConfirmationPresented = false
    }

    func confirmPAMAction(_ confirmation: PAMSettingsConfirmation) {
        guard pendingPAMConfirmation == confirmation else {
            return
        }
        isPAMConfirmationPresented = false
        guard pamPresentation.action == confirmation.action else {
            return
        }
        performPAMAction(confirmation.action)
    }

    private func performPAMAction(_ action: PAMSettingsAction) {
        switch action {
        case .install, .repair:
            pamIntegration.install()
        case .uninstall:
            pamIntegration.uninstall()
        case .finishRemoval:
            pamIntegration.finishRemoval()
        }
    }
}

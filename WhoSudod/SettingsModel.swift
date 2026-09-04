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

    var confirmationTitle: String {
        switch self {
        case .install:
            "Install PAM Password Input?"
        case .repair:
            "Repair PAM Password Input?"
        case .uninstall:
            "Uninstall PAM Password Input?"
        case .finishRemoval:
            "Finish PAM Removal?"
        }
    }

    var confirmationMessage: String {
        switch self {
        case .install:
            "This adds two signed components and two entries to the sudo PAM configuration. Terminal password input will continue to work. A restart is not required."
        case .repair:
            "This replaces the Who Sudo'd PAM components and restores its two sudo PAM entries. Other PAM entries stay in their current order."
        case .uninstall:
            "This removes only the two Who Sudo'd sudo PAM entries and its installed components. Other PAM entries stay unchanged."
        case .finishRemoval:
            "This removes the unused privileged helper registration. The PAM entries and installed components are already removed."
        }
    }

    var confirmationButtonTitle: String {
        switch self {
        case .install:
            "Install"
        case .repair:
            "Repair"
        case .uninstall:
            "Uninstall"
        case .finishRemoval:
            "Finish Removal"
        }
    }
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
    private(set) var pendingPAMAction: PAMSettingsAction?
    private(set) var isPAMRefreshPending = false
    var isPAMConfirmationPresented = false {
        didSet {
            if !isPAMConfirmationPresented {
                pendingPAMAction = nil
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
        pamIntegration.refresh()
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
        pendingPAMAction = action
        isPAMConfirmationPresented = true
    }

    func cancelPAMAction() {
        isPAMConfirmationPresented = false
    }

    func confirmPAMAction(_ action: PAMSettingsAction) {
        isPAMConfirmationPresented = false
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

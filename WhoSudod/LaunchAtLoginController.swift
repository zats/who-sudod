import Foundation
import Observation
import ServiceManagement

enum LaunchAtLoginState: Equatable {
    case disabled
    case enabled
    case requiresApproval
    case unavailable
}

@MainActor
protocol LaunchAtLoginServicing: AnyObject {
    var status: SMAppService.Status { get }
    func register() throws
    func unregister() throws
}

extension SMAppService: LaunchAtLoginServicing {}

@MainActor
@Observable
final class LaunchAtLoginController {
    static let initialDefaultAppliedKey = "launchAtLoginInitialDefaultApplied"

    private(set) var state: LaunchAtLoginState
    private(set) var operationError: String?
    private(set) var isUpdating = false

    var isEnabled: Bool {
        get { state == .enabled }
        set { setEnabled(newValue) }
    }

    @ObservationIgnored private let service: LaunchAtLoginServicing
    @ObservationIgnored private let userDefaults: UserDefaults
    @ObservationIgnored private let openLoginItems: () -> Void

    init(
        service: LaunchAtLoginServicing = SMAppService.mainApp,
        userDefaults: UserDefaults = .standard,
        openLoginItems: @escaping () -> Void = {
            SMAppService.openSystemSettingsLoginItems()
        }
    ) {
        self.service = service
        self.userDefaults = userDefaults
        self.openLoginItems = openLoginItems
        state = Self.state(for: service.status)
        operationError = nil
    }

    func applyInitialDefaultIfNeeded() {
        guard userDefaults.object(forKey: Self.initialDefaultAppliedKey) == nil else {
            refresh()
            return
        }

        switch service.status {
        case .notRegistered:
            perform { try service.register() }
            recordInitialDefaultIfAccepted()
        case .enabled, .requiresApproval:
            userDefaults.set(true, forKey: Self.initialDefaultAppliedKey)
            refresh()
        case .notFound:
            refresh()
        @unknown default:
            refresh()
        }
    }

    private func recordInitialDefaultIfAccepted() {
        guard service.status == .enabled || service.status == .requiresApproval else {
            return
        }
        userDefaults.set(true, forKey: Self.initialDefaultAppliedKey)
    }

    func refresh(preservingOperationError: Bool = false) {
        let refreshedState = Self.state(for: service.status)
        if !preservingOperationError || refreshedState != state {
            operationError = nil
        }
        state = refreshedState
    }

    private func setEnabled(_ enabled: Bool) {
        guard !isUpdating else {
            return
        }

        if enabled {
            switch service.status {
            case .notRegistered:
                perform { try service.register() }
                if service.status == .requiresApproval {
                    openLoginItems()
                }
            case .enabled, .notFound:
                refresh()
            case .requiresApproval:
                refresh()
                openLoginItems()
            @unknown default:
                refresh()
            }
        } else {
            guard service.status == .enabled || service.status == .requiresApproval else {
                refresh()
                return
            }
            perform { try service.unregister() }
        }
    }

    private func perform(_ operation: () throws -> Void) {
        isUpdating = true
        operationError = nil
        do {
            try operation()
        } catch {
            operationError = error.localizedDescription
        }
        state = Self.state(for: service.status)
        isUpdating = false
    }

    private static func state(for status: SMAppService.Status) -> LaunchAtLoginState {
        return switch status {
        case .notRegistered:
            .disabled
        case .enabled:
            .enabled
        case .requiresApproval:
            .requiresApproval
        case .notFound:
            .unavailable
        @unknown default:
            .unavailable
        }
    }
}

import AppKit
import SwiftUI

@MainActor
final class SettingsWindowController: NSWindowController, NSWindowDelegate {
    private static let frameAutosaveName = "WhoSudod.SettingsWindow"

    private let model: SettingsModel
    private let launchAtLogin: LaunchAtLoginController
    private let accessibilityPermission: AccessibilityPermissionController
    private let ignoredApplicationsViewController: IgnoredApplicationsSettingsViewController
    private let didClose: () -> Void

    init(
        ignoredApplications: IgnoredApplicationsStore,
        pamIntegration: PAMIntegrationController,
        launchAtLogin: LaunchAtLoginController,
        accessibilityPermission: AccessibilityPermissionController,
        pamConversationError: String?,
        didClose: @escaping () -> Void
    ) {
        let model = SettingsModel(
            pamIntegration: pamIntegration,
            pamConversationError: pamConversationError
        )
        let ignoredApplicationsViewController =
            IgnoredApplicationsSettingsViewController(store: ignoredApplications)
        self.model = model
        self.launchAtLogin = launchAtLogin
        self.accessibilityPermission = accessibilityPermission
        self.ignoredApplicationsViewController = ignoredApplicationsViewController
        self.didClose = didClose

        let hostingController = NSHostingController(
            rootView: SettingsView(
                model: model,
                launchAtLogin: launchAtLogin,
                accessibilityPermission: accessibilityPermission,
                ignoredApplicationsViewController: ignoredApplicationsViewController
            )
        )
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 520),
            styleMask: [
                .titled,
                .closable,
                .miniaturizable,
                .resizable,
                .fullSizeContentView
            ],
            backing: .buffered,
            defer: false
        )
        window.contentViewController = hostingController
        window.title = "Who Sudo'd Settings"
        window.titleVisibility = .hidden
        window.titlebarAppearsTransparent = true
        window.titlebarSeparatorStyle = .none
        window.isReleasedWhenClosed = false
        window.minSize = NSSize(width: 680, height: 460)
        window.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        if !window.setFrameUsingName(Self.frameAutosaveName) {
            window.center()
        }
        window.setFrameAutosaveName(Self.frameAutosaveName)

        super.init(window: window)
        window.delegate = self
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is unavailable")
    }

    func present() {
        model.refreshPAMIntegration()
        launchAtLogin.refresh(preservingOperationError: true)
        accessibilityPermission.refresh()
        ignoredApplicationsViewController.reload()
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        if model.selectedPane == .ignoredApps {
            DispatchQueue.main.async { [weak self] in
                self?.ignoredApplicationsViewController.focusApplicationList()
            }
        }
    }

    func presentPAMAction(_ action: PAMSettingsAction) {
        model.requestPAMAction(action)
        present()
    }

    func updatePAMConversationError(_ error: String?) {
        model.updatePAMConversationError(error)
    }

    func windowWillClose(_ notification: Notification) {
        didClose()
    }

    func windowDidBecomeKey(_ notification: Notification) {
        model.refreshPAMIntegration()
        launchAtLogin.refresh(preservingOperationError: true)
        accessibilityPermission.refresh()
    }
}

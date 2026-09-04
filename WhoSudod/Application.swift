import AppKit
import Permiso
import os

enum ApplicationLaunchContext {
    static func shouldStartMonitor(environment: [String: String]) -> Bool {
        environment["XCTestConfigurationFilePath"] == nil
            && environment["XCODE_RUNNING_FOR_PREVIEWS"] != "1"
    }
}

enum SettingsKeyboardShortcut {
    static func closesSettings(for event: NSEvent) -> Bool {
        guard event.modifierFlags.intersection(.deviceIndependentFlagsMask) == .command,
              let character = event.charactersIgnoringModifiers?.lowercased() else {
            return false
        }
        return character == "q"
    }
}

@MainActor
private struct AppDelegateDependencies {
    let ignoredApplications = IgnoredApplicationsStore()
    let pamIntegration = PAMIntegrationController()
    let launchAtLogin = LaunchAtLoginController()
    let accessibilityPermission = AccessibilityPermissionController(
        isTrusted: { AccessibilityFocusReader.isTrusted },
        requestHandler: {
            PermisoAssistant.shared.present(panel: .accessibility)
        }
    )
}

@main
@MainActor
enum WhoSudodApplication {
    static func main() {
        let application = NSApplication.shared
        let delegate = AppDelegate()
        application.delegate = delegate
        application.run()
        withExtendedLifetime(delegate) {}
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let logger = Logger(subsystem: "com.zats.WhoSudo", category: "Application")
    private let environment: [String: String]
    private(set) var dependenciesAreLoaded = false
    private lazy var dependencies: AppDelegateDependencies = {
        dependenciesAreLoaded = true
        return AppDelegateDependencies()
    }()
    private var ignoredApplications: IgnoredApplicationsStore {
        dependencies.ignoredApplications
    }
    private var pamIntegration: PAMIntegrationController {
        dependencies.pamIntegration
    }
    private var launchAtLogin: LaunchAtLoginController {
        dependencies.launchAtLogin
    }
    private var accessibilityPermission: AccessibilityPermissionController {
        dependencies.accessibilityPermission
    }
    private var monitor: AuthorizationPromptMonitor?
    private var pamConversationServer: PAMConversationServer?
    private var pamConversationError: String?
    private var statusItem: NSStatusItem?
    private var settingsWindowController: SettingsWindowController?
    private var settingsKeyboardMonitor: Any?
    private var displayMode = ProcessDisplayMode.initial()

    init(environment: [String: String] = ProcessInfo.processInfo.environment) {
        self.environment = environment
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        guard ApplicationLaunchContext.shouldStartMonitor(
            environment: environment
        ) else {
            return
        }
        launchAtLogin.applyInitialDefaultIfNeeded()
        NSApp.setActivationPolicy(.accessory)
        configureMainMenu()
        configureStatusItem()
        configureSettingsKeyboardMonitor()

        let monitor = AuthorizationPromptMonitor(
            displayMode: displayMode,
            ignoredApplications: ignoredApplications,
            displayModeRequestHandler: { [weak self] mode in
                self?.setDisplayMode(mode)
            },
            pamSetupActionProvider: { [weak self] in
                guard let self,
                      pamIntegration.hasCompletedRefresh,
                      pamConversationError == nil else {
                    return nil
                }
                return PAMSettingsPresentation(
                    snapshot: pamIntegration.snapshot,
                    conversationError: nil
                ).notchAction
            },
            pamSetupActionHandler: { [weak self] action in
                self?.presentSettings(pamAction: action)
            },
            statusHandler: { [weak self] status in
                self?.updateStatus(status)
            }
        )
        self.monitor = monitor
        startPAMConversationServer()
        pamIntegration.refresh()
        monitor.start()

        accessibilityPermission.refresh()
        if !accessibilityPermission.isGranted {
            DispatchQueue.main.async { [weak self] in
                self?.accessibilityPermission.requestAccess()
            }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let settingsKeyboardMonitor {
            NSEvent.removeMonitor(settingsKeyboardMonitor)
        }
        monitor?.stop()
        pamConversationServer?.stop()
    }

    func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows flag: Bool
    ) -> Bool {
        guard ApplicationLaunchContext.shouldStartMonitor(
            environment: environment
        ) else {
            return false
        }
        openSettings()
        return true
    }

    private func configureMainMenu() {
        let mainMenu = NSMenu()

        let applicationMenuItem = NSMenuItem(title: "Who Sudo'd", action: nil, keyEquivalent: "")
        let applicationMenu = NSMenu(title: "Who Sudo'd")
        applicationMenu.addItem(
            responderMenuItem(
                title: "About Who Sudo'd",
                action: #selector(NSApplication.orderFrontStandardAboutPanel(_:))
            )
        )
        applicationMenu.addItem(.separator())
        let settings = NSMenuItem(
            title: "Settings…",
            action: #selector(openSettings),
            keyEquivalent: ","
        )
        settings.target = self
        applicationMenu.addItem(settings)
        applicationMenu.addItem(.separator())

        let servicesMenuItem = NSMenuItem(title: "Services", action: nil, keyEquivalent: "")
        let servicesMenu = NSMenu(title: "Services")
        servicesMenuItem.submenu = servicesMenu
        applicationMenu.addItem(servicesMenuItem)
        NSApp.servicesMenu = servicesMenu

        applicationMenu.addItem(.separator())
        applicationMenu.addItem(
            responderMenuItem(
                title: "Hide Who Sudo'd",
                action: #selector(NSApplication.hide(_:)),
                keyEquivalent: "h"
            )
        )
        applicationMenu.addItem(
            responderMenuItem(
                title: "Hide Others",
                action: #selector(NSApplication.hideOtherApplications(_:)),
                keyEquivalent: "h",
                modifiers: [.command, .option]
            )
        )
        applicationMenu.addItem(
            responderMenuItem(
                title: "Show All",
                action: #selector(NSApplication.unhideAllApplications(_:))
            )
        )
        applicationMenu.addItem(.separator())
        let closeWithQuitShortcut = NSMenuItem(
            title: "Close Settings",
            action: #selector(closeSettings),
            keyEquivalent: "q"
        )
        closeWithQuitShortcut.target = self
        applicationMenu.addItem(closeWithQuitShortcut)
        applicationMenuItem.submenu = applicationMenu
        mainMenu.addItem(applicationMenuItem)

        let fileMenuItem = NSMenuItem(title: "File", action: nil, keyEquivalent: "")
        let fileMenu = NSMenu(title: "File")
        fileMenu.addItem(
            responderMenuItem(
                title: "Close Window",
                action: #selector(NSWindow.performClose(_:)),
                keyEquivalent: "w"
            )
        )
        fileMenuItem.submenu = fileMenu
        mainMenu.addItem(fileMenuItem)

        let editMenuItem = NSMenuItem(title: "Edit", action: nil, keyEquivalent: "")
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(
            responderMenuItem(
                title: "Undo",
                action: Selector(("undo:")),
                keyEquivalent: "z"
            )
        )
        editMenu.addItem(
            responderMenuItem(
                title: "Redo",
                action: Selector(("redo:")),
                keyEquivalent: "z",
                modifiers: [.command, .shift]
            )
        )
        editMenu.addItem(.separator())
        editMenu.addItem(
            responderMenuItem(
                title: "Cut",
                action: #selector(NSText.cut(_:)),
                keyEquivalent: "x"
            )
        )
        editMenu.addItem(
            responderMenuItem(
                title: "Copy",
                action: #selector(NSText.copy(_:)),
                keyEquivalent: "c"
            )
        )
        editMenu.addItem(
            responderMenuItem(
                title: "Paste",
                action: #selector(NSText.paste(_:)),
                keyEquivalent: "v"
            )
        )
        editMenu.addItem(
            responderMenuItem(
                title: "Paste and Match Style",
                action: #selector(NSTextView.pasteAsPlainText(_:)),
                keyEquivalent: "v",
                modifiers: [.command, .option, .shift]
            )
        )
        editMenu.addItem(
            responderMenuItem(
                title: "Delete",
                action: #selector(NSText.delete(_:))
            )
        )
        editMenu.addItem(.separator())
        editMenu.addItem(
            responderMenuItem(
                title: "Select All",
                action: #selector(NSText.selectAll(_:)),
                keyEquivalent: "a"
            )
        )
        editMenuItem.submenu = editMenu
        mainMenu.addItem(editMenuItem)

        let windowMenuItem = NSMenuItem(title: "Window", action: nil, keyEquivalent: "")
        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(
            responderMenuItem(
                title: "Minimize",
                action: #selector(NSWindow.performMiniaturize(_:)),
                keyEquivalent: "m"
            )
        )
        windowMenu.addItem(
            responderMenuItem(
                title: "Zoom",
                action: #selector(NSWindow.performZoom(_:))
            )
        )
        windowMenu.addItem(.separator())
        windowMenu.addItem(
            responderMenuItem(
                title: "Bring All to Front",
                action: #selector(NSApplication.arrangeInFront(_:))
            )
        )
        windowMenuItem.submenu = windowMenu
        mainMenu.addItem(windowMenuItem)
        NSApp.windowsMenu = windowMenu
        NSApp.mainMenu = mainMenu
    }

    private func responderMenuItem(
        title: String,
        action: Selector,
        keyEquivalent: String = "",
        modifiers: NSEvent.ModifierFlags = .command
    ) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: keyEquivalent)
        item.target = nil
        item.keyEquivalentModifierMask = keyEquivalent.isEmpty ? [] : modifiers
        return item
    }

    private func configureSettingsKeyboardMonitor() {
        settingsKeyboardMonitor = NSEvent.addLocalMonitorForEvents(
            matching: .keyDown
        ) { [weak self] event in
            guard let self,
                  self.settingsWindowController?.window?.isVisible == true,
                  SettingsKeyboardShortcut.closesSettings(for: event) else {
                return event
            }
            self.closeSettings()
            return nil
        }
    }

    private func configureStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        let statusImage = NSImage(named: "StatusFingerprint")
        statusImage?.isTemplate = true
        statusImage?.size = NSSize(width: 18, height: 18)
        statusImage?.accessibilityDescription = "Who Sudo'd"
        item.button?.image = statusImage
        item.button?.toolTip = "Who Sudo'd"

        item.menu = makeStatusMenu()
        statusItem = item
    }

    func makeStatusMenu() -> NSMenu {
        let menu = NSMenu()
        let settings = NSMenuItem(
            title: "Settings…",
            action: #selector(openSettings),
            keyEquivalent: ","
        )
        settings.target = self
        menu.addItem(settings)
        menu.addItem(.separator())

        let quit = NSMenuItem(title: "Quit Who Sudo'd", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)

        return menu
    }

    private func updateStatus(_ status: AuthorizationMonitorStatus) {
        accessibilityPermission.update(isGranted: status.accessibilityTrusted)
        if status.accessibilityTrusted {
            PermisoAssistant.shared.dismiss()
        }
    }

    private func startPAMConversationServer() {
        let server = PAMConversationServer(
            requestHandler: { [weak self] request, lease in
                guard let self, let monitor = self.monitor else {
                    return false
                }
                return await monitor.offerPAMPasswordRequest(
                    request,
                    lease: lease,
                    passwordHandler: { [weak self] password in
                        self?.pamConversationServer?.submit(
                            password: password,
                            for: request.identifier
                        )
                    },
                    useTerminalHandler: { [weak self] in
                        self?.pamConversationServer?.useTerminal(
                            for: request.identifier
                        )
                    }
                )
            },
            endHandler: { [weak self] requestIdentifier in
                self?.monitor?.endPAMPasswordRequest(requestIdentifier)
            }
        )
        pamConversationServer = server
        do {
            try server.start()
            pamConversationError = nil
        } catch {
            pamConversationServer = nil
            pamConversationError = error.localizedDescription
            logger.error("PAM conversation server failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func setDisplayMode(_ mode: ProcessDisplayMode) {
        displayMode = mode
        UserDefaults.standard.set(mode.rawValue, forKey: ProcessDisplayMode.defaultsKey)
        monitor?.setDisplayMode(mode)
    }

    @objc
    private func openSettings() {
        presentSettings(pamAction: nil)
    }

    private func presentSettings(pamAction action: PAMSettingsAction?) {
        NSApp.setActivationPolicy(.regular)
        let controller: SettingsWindowController
        if let settingsWindowController {
            controller = settingsWindowController
        } else {
            let created = SettingsWindowController(
                ignoredApplications: ignoredApplications,
                pamIntegration: pamIntegration,
                launchAtLogin: launchAtLogin,
                accessibilityPermission: accessibilityPermission,
                pamConversationError: pamConversationError,
                didClose: { [weak self] in
                    self?.settingsDidClose()
                }
            )
            settingsWindowController = created
            controller = created
        }
        controller.updatePAMConversationError(pamConversationError)
        if let action {
            controller.presentPAMAction(action)
        } else {
            controller.present()
        }
    }

    @objc
    private func closeSettings() {
        settingsWindowController?.close()
    }

    private func settingsDidClose() {
        NSApp.setActivationPolicy(.accessory)
        NSApp.deactivate()
    }

    @objc
    private func quit() {
        NSApp.terminate(nil)
    }
}

import AppKit
import ApplicationServices
import Permiso

enum ApplicationLaunchContext {
    static func shouldStartMonitor(environment: [String: String]) -> Bool {
        environment["XCTestConfigurationFilePath"] == nil
    }
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
    private var monitor: AuthorizationPromptMonitor?
    private var statusItem: NSStatusItem?
    private var accessMenuItem: NSMenuItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        guard ApplicationLaunchContext.shouldStartMonitor(
            environment: ProcessInfo.processInfo.environment
        ) else {
            return
        }
        NSApp.setActivationPolicy(.accessory)
        configureStatusItem()

        let monitor = AuthorizationPromptMonitor { [weak self] status in
            self?.updateStatus(status)
        }
        self.monitor = monitor
        monitor.start()

        if !AccessibilityFocusReader.isTrusted {
            DispatchQueue.main.async { [weak self] in
                self?.presentAccessibilityAssistant()
            }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        monitor?.stop()
    }

    private func configureStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = NSImage(
            systemSymbolName: "person.badge.key.fill",
            accessibilityDescription: "Who Sudo'd"
        )
        item.button?.toolTip = "Who Sudo'd"

        let menu = NSMenu()
        let access = NSMenuItem(
            title: "Request Accessibility Access…",
            action: #selector(requestAccessibilityAccess),
            keyEquivalent: ""
        )
        access.target = self
        menu.addItem(access)
        menu.addItem(.separator())

        let quit = NSMenuItem(title: "Quit Who Sudo'd", action: #selector(quit), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)

        item.menu = menu
        statusItem = item
        accessMenuItem = access
    }

    private func updateStatus(_ status: AuthorizationMonitorStatus) {
        accessMenuItem?.title = status.accessibilityTrusted
            ? "Accessibility: Allowed"
            : "Request Accessibility Access…"
        accessMenuItem?.isEnabled = !status.accessibilityTrusted
        statusItem?.button?.contentTintColor = status.isShowingPanel ? .systemGreen : nil
        if status.accessibilityTrusted {
            PermisoAssistant.shared.dismiss()
        }
    }

    @objc
    private func requestAccessibilityAccess() {
        presentAccessibilityAssistant()
    }

    private func presentAccessibilityAssistant() {
        guard !AccessibilityFocusReader.isTrusted else {
            return
        }
        PermisoAssistant.shared.present(panel: .accessibility)
    }

    @objc
    private func quit() {
        NSApp.terminate(nil)
    }
}

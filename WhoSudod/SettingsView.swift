import SwiftUI

struct SettingsView: View {
    @Bindable var model: SettingsModel
    let launchAtLogin: LaunchAtLoginController
    let accessibilityPermission: AccessibilityPermissionController
    let ignoredApplicationsViewController: IgnoredApplicationsSettingsViewController

    var body: some View {
        HStack(spacing: 0) {
            SettingsSidebarView(model: model)
                .frame(width: 210)
                .background {
                    SettingsSidebarMaterial()
                        .ignoresSafeArea()
                }

            Divider()
                .ignoresSafeArea()

            SettingsDetailView(
                model: model,
                launchAtLogin: launchAtLogin,
                accessibilityPermission: accessibilityPermission,
                ignoredApplicationsViewController: ignoredApplicationsViewController
            )
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(
            minWidth: 680,
            idealWidth: 760,
            maxWidth: .infinity,
            minHeight: 460,
            idealHeight: 520,
            maxHeight: .infinity
        )
    }
}

private struct SettingsSidebarView: View {
    @Bindable var model: SettingsModel

    var body: some View {
        VStack(spacing: 2) {
            ForEach(SettingsPane.allCases) { pane in
                Button {
                    model.selectedPane = pane
                } label: {
                    SettingsSidebarRow(
                        pane: pane,
                        isSelected: model.selectedPane == pane
                    )
                }
                .buttonStyle(.plain)
                .focusEffectDisabled()
            }
            Spacer()
        }
        .padding(.horizontal, 8)
        .padding(.top, 12)
    }
}

private struct SettingsSidebarRow: View {
    let pane: SettingsPane
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 8) {
            SettingsIconChip(
                systemImage: pane.systemImage,
                color: pane.color
            )
            Text(pane.title)
            Spacer()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .contentShape(Rectangle())
        .background {
            if isSelected {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(Color.accentColor.opacity(0.18))
            }
        }
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }
}

private struct SettingsIconChip: View {
    let systemImage: String
    let color: Color

    var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 20, height: 20)
            .background(
                RoundedRectangle(cornerRadius: 5, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: [color.opacity(0.85), color],
                            startPoint: .top,
                            endPoint: .bottom
                        )
                    )
                    .shadow(color: .black.opacity(0.15), radius: 1, y: 1)
            )
            .accessibilityHidden(true)
    }
}

private struct SettingsDetailView: View {
    let model: SettingsModel
    let launchAtLogin: LaunchAtLoginController
    let accessibilityPermission: AccessibilityPermissionController
    let ignoredApplicationsViewController: IgnoredApplicationsSettingsViewController

    var body: some View {
        VStack {
            switch model.selectedPane {
            case .general:
                GeneralSettingsPane(
                    model: model,
                    launchAtLogin: launchAtLogin,
                    accessibilityPermission: accessibilityPermission
                )
            case .ignoredApps:
                IgnoredApplicationsPane(
                    viewController: ignoredApplicationsViewController
                )
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct GeneralSettingsPane: View {
    @Bindable var model: SettingsModel
    let launchAtLogin: LaunchAtLoginController
    let accessibilityPermission: AccessibilityPermissionController

    var body: some View {
        Form {
            PermissionsSettingsSection(
                model: model,
                accessibilityPermission: accessibilityPermission
            )
            LaunchAtLoginSettingsSection(controller: launchAtLogin)
        }
        .formStyle(.grouped)
        .labeledContentStyle(CenteredLabeledContentStyle())
        .scrollContentBackground(.hidden)
    }
}

private struct PermissionsSettingsSection: View {
    @Bindable var model: SettingsModel
    @Bindable var accessibilityPermission: AccessibilityPermissionController

    var body: some View {
        let presentation = model.pamPresentation
        Section {
            LabeledContent("Accessibility") {
                if accessibilityPermission.isGranted {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                        .accessibilityLabel("Allowed")
                } else {
                    Button("Allow…") {
                        accessibilityPermission.requestAccess()
                    }
                }
            }

            PAMSettingsRow(
                presentation: presentation,
                requestAction: model.requestPAMAction
            )
        } header: {
            Text("Permissions")
        } footer: {
            Text("Allows to enter sudo passwords here, while keeping your preferred terminal app working as is. Your passwords never leave your computer.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .alert(
            model.pendingPAMConfirmation?.title ?? "Change PAM Password Input?",
            isPresented: $model.isPAMConfirmationPresented,
            presenting: model.pendingPAMConfirmation
        ) { confirmation in
            Button(confirmation.buttonTitle, role: .destructive) {
                model.confirmPAMAction(confirmation)
            }
            Button("Cancel", role: .cancel) {
                model.cancelPAMAction()
            }
        } message: { confirmation in
            Text(confirmation.message)
        }
    }
}

private struct PAMSettingsRow: View {
    let presentation: PAMSettingsPresentation
    let requestAction: () -> Void

    var body: some View {
        LabeledContent {
            if presentation.isLoading {
                ProgressView()
                    .controlSize(.small)
            } else {
                Button(presentation.actionTitle) {
                    requestAction()
                }
                .disabled(presentation.action == nil)
            }
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text("PAM")
                if let detail = presentation.detail, !detail.isEmpty {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(presentation.isWarning ? .orange : .secondary)
                }
            }
            .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct LaunchAtLoginSettingsSection: View {
    @Bindable var controller: LaunchAtLoginController

    var body: some View {
        Section("Startup") {
            VStack(alignment: .leading, spacing: 3) {
                Toggle("Launch at Login", isOn: $controller.isEnabled)
                    .toggleStyle(.switch)
                    .disabled(controller.isUpdating || controller.state == .unavailable)

                if let operationError = controller.operationError {
                    Text(operationError)
                        .font(.caption)
                        .foregroundStyle(.orange)
                } else if controller.state == .requiresApproval {
                    Text("Approval is required in Login Items.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if controller.state == .unavailable {
                    Text("Launch at Login is unavailable.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

private struct IgnoredApplicationsPane: NSViewControllerRepresentable {
    let viewController: IgnoredApplicationsSettingsViewController

    func makeNSViewController(context: Context) -> IgnoredApplicationsSettingsViewController {
        viewController.reload()
        DispatchQueue.main.async {
            viewController.focusApplicationList()
        }
        return viewController
    }

    func updateNSViewController(
        _ nsViewController: IgnoredApplicationsSettingsViewController,
        context: Context
    ) {
        nsViewController.reload()
    }
}

private extension SettingsPane {
    var color: Color {
        switch self {
        case .general:
            .gray
        case .ignoredApps:
            .orange
        }
    }
}

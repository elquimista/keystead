import AppKit
import SwiftUI

struct SettingsView: View {
    /// The sheets the Account tab opens, in the Settings window itself.
    enum AccountSheet: String, Identifiable {
        case recoveryKit, signOut
        var id: String { rawValue }
    }

    enum Tab: String {
        case general, security, account
    }

    /// Where the last tab chosen is kept, so Settings opens on it again.
    static let tabKey = "SettingsTab"

    let model: AppModel
    @AppStorage(DockIcon.preferenceKey) private var showInDock = true
    @AppStorage(AutoLock.minutesKey) private var autoLockMinutes = AutoLock.defaultMinutes
    @AppStorage(QuickSearchShortcut.preferenceKey)
    private var shortcut = QuickSearchShortcut.standard
    @AppStorage(SettingsView.tabKey) private var tab = Tab.general
    /// macOS refused the chosen shortcut, usually because another app has it.
    @State private var shortcutTaken = false
    @State private var sheet: AccountSheet?

    var body: some View {
        TabView(selection: $tab) {
            Form {
                Section {
                    Picker("Quick search shortcut", selection: $shortcut) {
                        ForEach(QuickSearchShortcut.allCases) { Text($0.label).tag($0) }
                    }
                } footer: {
                    SettingsFooter(
                        shortcutTaken
                            ? "Another app already uses that shortcut. Choose a different one."
                            : "Opens a search box over any app: type, then press Return to copy the "
                                + "password, Shift-Return for the username, or Option-Return for the "
                                + "one-time code.",
                        color: shortcutTaken ? .orange : nil)
                }
                Section {
                    Toggle("Show \(appName) in the Dock", isOn: $showInDock)
                } footer: {
                    SettingsFooter("When this is off, \(appName) lives only in the menu bar. Open its "
                        + "window from the menu bar icon.")
                }
            }
            .settingsTab()
            .tabItem { Label("General", systemImage: "gearshape") }
            .tag(Tab.general)

            Form {
                Section {
                    Picker("Lock after not using \(appName) for", selection: $autoLockMinutes) {
                        ForEach(AutoLock.choices, id: \.self) { minutes in
                            Text(minutes == 0 ? "Never" : minutes == 1 ? "1 minute" : "\(minutes) minutes")
                                .tag(minutes)
                        }
                    }
                } footer: {
                    SettingsFooter("Counted from your last click or key press in \(appName), whatever "
                        + "you do in other apps, so its keys don't stay in memory while you work "
                        + "elsewhere. It also locks as soon as the screen locks or the Mac sleeps, "
                        + "and then clears the clipboard if it still holds a password \(appName) "
                        + "copied.")
                }
            }
            .settingsTab()
            .tabItem { Label("Security", systemImage: "lock") }
            .tag(Tab.security)

            AccountSettings(model: model, sheet: $sheet)
                .settingsTab()
                .tabItem { Label("Account", systemImage: "person.crop.circle") }
                .tag(Tab.account)
        }
        .sheet(item: $sheet) { sheet in
            Group {
                switch sheet {
                case .recoveryKit:
                    RecoveryKitSheet(model: model, afterSetup: false)
                case .signOut:
                    SignOutSheet(model: model) { self.sheet = .recoveryKit }
                }
            }
            .windowFollowsHeight()
        }
        .onChange(of: shortcut) {
            shortcutTaken = QuickSearch.shared?.applyShortcut() == false
        }
        .onChange(of: showInDock) {
            DockIcon.applyPreference()
            // Changing the Dock setting deactivates the app; keep this window in front.
            NSApp.activate()
        }
        .onAppear { NSApp.activate() }
    }
}

extension View {
    /// A Settings tab: a grouped form as tall as what's in it, with the window gliding to
    /// fit each tab as AppKit's preference windows do.
    fileprivate func settingsTab() -> some View {
        formStyle(.grouped)
            .scrollDisabled(true)
            .frame(width: 500)
            .windowFollowsHeight()
    }
}

/// A note under a Settings section, reading from the left.
private struct SettingsFooter: View {
    let text: String
    var color: Color?

    init(_ text: String, color: Color? = nil) {
        self.text = text
        self.color = color
    }

    var body: some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(color.map { AnyShapeStyle($0) } ?? AnyShapeStyle(.secondary))
            .frame(maxWidth: .infinity, alignment: .leading)
            .multilineTextAlignment(.leading)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct AccountSettings: View {
    let model: AppModel
    @Binding var sheet: SettingsView.AccountSheet?

    var body: some View {
        Form {
            if let identity = model.identity {
                Section {
                    LabeledContent("Server", value: identity.server)
                    LabeledContent("Fingerprint") {
                        Text(identity.fingerprint)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                } header: {
                    PageHeader(
                        title: identity.name,
                        subtitle: "\(identity.isOwner ? "Owner" : "Member") of \(host(identity.server))"
                    ) {
                        Avatar(name: identity.name, size: 44)
                    }
                } footer: {
                    SettingsFooter("Your fingerprint proves your keys are yours. Read it out when "
                        + "someone checks it, in person or on a call.")
                }
                Section {
                    ActionRow(title: "Recovery Kit", button: "Show\u{2026}") { sheet = .recoveryKit }
                    ActionRow(title: "Sign out of this Mac", button: "Sign Out\u{2026}") { sheet = .signOut }
                } footer: {
                    SettingsFooter("Your Recovery Kit brings your account back on a new Mac if this "
                        + "one is lost. Signing out makes this Mac forget your account.")
                }
            } else {
                Text(model.phase == .welcome
                    ? "\(appName) isn't set up on this Mac yet."
                    : "Unlock \(appName) to see your account.")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

import AppKit
import SwiftUI

struct SettingsView: View {
    /// The sheets the Account tab opens, in the Settings window itself.
    enum AccountSheet: String, Identifiable {
        case recoveryKit, signOut
        var id: String { rawValue }
    }

    let model: AppModel
    @AppStorage(DockIcon.preferenceKey) private var showInDock = true
    @AppStorage(AutoLock.minutesKey) private var autoLockMinutes = AutoLock.defaultMinutes
    @AppStorage(QuickSearchShortcut.preferenceKey)
    private var shortcut = QuickSearchShortcut.standard
    /// macOS refused the chosen shortcut, usually because another app has it.
    @State private var shortcutTaken = false
    @State private var sheet: AccountSheet?

    var body: some View {
        TabView {
            Form {
                Section {
                    Picker("Quick search shortcut", selection: $shortcut) {
                        ForEach(QuickSearchShortcut.allCases) { Text($0.label).tag($0) }
                    }
                    Text(shortcutTaken
                        ? "Another app already uses that shortcut. Choose a different one."
                        : "Opens a search box over any app: type, then press Return to copy the "
                            + "password, Shift-Return for the username, or Option-Return for the "
                            + "one-time code.")
                        .font(.caption)
                        .foregroundStyle(shortcutTaken ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                        .fixedSize(horizontal: false, vertical: true)
                }
                Section {
                    Toggle("Show \(appName) in the Dock", isOn: $showInDock)
                    Text("When this is off, \(appName) lives only in the menu bar. Open its window "
                        + "from the menu bar icon.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .formStyle(.grouped)
            .tabItem { Label("General", systemImage: "gearshape") }

            Form {
                Picker("Lock after not using \(appName) for", selection: $autoLockMinutes) {
                    ForEach(AutoLock.choices, id: \.self) { minutes in
                        Text(minutes == 0 ? "Never" : minutes == 1 ? "1 minute" : "\(minutes) minutes")
                            .tag(minutes)
                    }
                }
                Text("Counted from your last click or key press in \(appName), whatever you do "
                    + "in other apps, so its keys don't stay in memory while you work elsewhere. "
                    + "It also locks as soon as the screen locks or the Mac sleeps, and then "
                    + "clears the clipboard if it still holds a password \(appName) copied.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .formStyle(.grouped)
            .tabItem { Label("Security", systemImage: "lock") }

            AccountSettings(model: model, sheet: $sheet)
                .tabItem { Label("Account", systemImage: "person.crop.circle") }
        }
        .frame(width: 480, height: 360)
        .sheet(item: $sheet) { sheet in
            switch sheet {
            case .recoveryKit:
                RecoveryKitSheet(model: model, afterSetup: false)
            case .signOut:
                SignOutSheet(model: model) { self.sheet = .recoveryKit }
            }
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

private struct AccountSettings: View {
    let model: AppModel
    @Binding var sheet: SettingsView.AccountSheet?

    var body: some View {
        Form {
            if let identity = model.identity {
                LabeledContent("Name", value: identity.name)
                LabeledContent("Server", value: identity.server)
                LabeledContent("Role", value: identity.isOwner ? "Owner" : "Member")
                LabeledContent("Fingerprint") {
                    Text(identity.fingerprint)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                }
                LabeledContent("Recovery Kit") {
                    Button("Show Recovery Kit…") { sheet = .recoveryKit }
                }
                LabeledContent("This Mac") {
                    Button("Sign Out…") { sheet = .signOut }
                }
            } else {
                Text(model.phase == .welcome
                    ? "\(appName) isn't set up on this Mac yet."
                    : "Unlock \(appName) to see your account.")
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

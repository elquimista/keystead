import AppKit
import SwiftUI

struct SettingsView: View {
    let model: AppModel
    @AppStorage(DockIcon.preferenceKey) private var showInDock = true

    var body: some View {
        TabView {
            Form {
                Toggle("Show \(appName) in the Dock", isOn: $showInDock)
                Text("When this is off, \(appName) lives only in the menu bar. Open its window "
                    + "from the menu bar icon.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .formStyle(.grouped)
            .tabItem { Label("General", systemImage: "gearshape") }

            AccountSettings(model: model)
                .tabItem { Label("Account", systemImage: "person.crop.circle") }
        }
        .frame(width: 480, height: 260)
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

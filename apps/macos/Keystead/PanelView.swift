import SwiftUI

/// The panel that opens from the menu bar icon: search and copy, without opening the
/// main window. Setting up and everything else happens in the main window.
struct PanelView: View {
    @Bindable var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            switch model.phase {
            case .welcome:
                welcome
            case .working(let what):
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(what)
                }
            case .locked:
                locked
            case .unlocked:
                unlocked
            }
            if let message = model.message {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            footer
        }
        .padding(14)
        .frame(width: 360)
    }

    private var header: some View {
        HStack {
            Text(appName).font(.headline)
            Spacer()
            if let identity = model.identity {
                Text(identity.name).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Set up \(appName) on this Mac to get started: join your team with an invite, "
                + "or set up a new team.")
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            Button("Open \(appName)") { openMainWindow() }
                .keyboardShortcut(.defaultAction)
        }
    }

    private var locked: some View {
        Button {
            Task { await model.unlock() }
        } label: {
            Label("Unlock with Touch ID", systemImage: "touchid")
        }
        .keyboardShortcut(.defaultAction)
    }

    private var unlocked: some View {
        VStack(alignment: .leading, spacing: 8) {
            TextField("Search", text: $model.search)
                .textFieldStyle(.roundedBorder)
            if model.filteredItems.isEmpty {
                Text(model.items.isEmpty ? "Nothing has been shared with you yet." : "No matches.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 4)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(model.filteredItems, id: \.id) { item in
                            ItemRowView(item: item) {
                                Task { await model.copyPassword(of: item) }
                            }
                        }
                    }
                }
                .frame(maxHeight: 300)
            }
            if let copied = model.copiedName {
                Text("Copied the password for \(copied). It clears in 30 seconds.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var footer: some View {
        HStack(spacing: 12) {
            Button("Open \(appName)") { openMainWindow() }
            if model.phase == .unlocked {
                Button("Sync") { Task { await model.refresh() } }
                Button("Lock") { model.lock() }
            }
            Spacer()
            SettingsLink {
                Image(systemName: "gearshape")
            }
            .help("Settings")
            Button("Quit") { NSApplication.shared.terminate(nil) }
        }
        .buttonStyle(.borderless)
    }

    private func openMainWindow() {
        openWindow(id: MainWindow.id)
        NSApp.activate()
    }
}

/// One login. Clicking it copies the password.
private struct ItemRowView: View {
    let item: ItemSummary
    let copy: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: copy) {
            HStack {
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.name)
                    Text(item.username.isEmpty ? item.place : "\(item.username) · \(item.place)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "doc.on.doc")
                    .foregroundStyle(.secondary)
                    .opacity(hovering ? 1 : 0.4)
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 6)
            .contentShape(Rectangle())
            .background(
                hovering ? Color.accentColor.opacity(0.12) : .clear,
                in: RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help("Copy password")
    }
}

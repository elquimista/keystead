import SwiftUI

/// The panel that opens from the menu bar icon: search and copy, without opening the
/// main window. Setting up and everything else happens in the main window.
struct PanelView: View {
    @Bindable var model: AppModel
    @Environment(\.openWindow) private var openWindow
    @FocusState private var searchFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(.horizontal, 14)
                .padding(.top, 12)
                .padding(.bottom, 10)
            Group {
                switch model.phase {
                case .welcome:
                    welcome
                case .working(let what):
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text(what)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, minHeight: 80)
                case .locked:
                    locked
                case .unlocked:
                    unlocked
                }
            }
            .padding(.horizontal, 10)
            if let message = model.message {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 14)
                    .padding(.top, 8)
            }
            Divider()
                .padding(.top, 10)
            footer
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
        }
        .frame(width: 360)
        // The panel glides to its new height as a search narrows the list.
        .windowFollowsHeight()
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 22, height: 22)
                .accessibilityHidden(true)
            Text(appName)
                .font(.headline)
            Spacer()
            if model.isSyncing {
                ProgressView()
                    .controlSize(.mini)
                    .help("Syncing\u{2026}")
            }
            if let identity = model.identity {
                Text(identity.name)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var welcome: some View {
        VStack(spacing: 12) {
            Text("Set up \(appName) on this Mac to get started: join your team with an invite, "
                + "or set up a new team.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Button("Open \(appName)") { openMainWindow() }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }

    private var locked: some View {
        VStack(spacing: 10) {
            Image(systemName: "lock.fill")
                .font(.system(size: 26, weight: .medium))
                .foregroundStyle(.secondary)
            Text("\(appName) Is Locked")
                .font(.headline)
            Button {
                Task { await model.unlock() }
            } label: {
                Label("Unlock with Touch ID", systemImage: "touchid")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
    }

    private var unlocked: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Search logins", text: $model.search)
                    .textFieldStyle(.plain)
                    .focused($searchFocused)
                    // Return copies the first match's password, as quick search does.
                    .onSubmit {
                        if let first = model.filteredItems.first {
                            Task { await model.copyPassword(of: first) }
                        }
                    }
                if !model.search.isEmpty {
                    Button {
                        model.search = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .help("Clear")
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            if model.filteredItems.isEmpty {
                Text(model.items.isEmpty ? "Nothing has been shared with you yet." : "No matches.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 60)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(model.filteredItems, id: \.id) { item in
                            ItemRowView(item: item) {
                                Task { await model.copyPassword(of: item) }
                            }
                        }
                    }
                }
                .frame(maxHeight: 320)
            }
            if let copied = model.copiedName {
                Label("Copied the \(model.copiedWhat) for \(copied). It clears in 30 seconds.",
                      systemImage: "checkmark.circle.fill")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 4)
                    .transition(.opacity)
            }
        }
        .animation(.snappy(duration: 0.2), value: model.copiedName)
        .onAppear { searchFocused = true }
    }

    private var footer: some View {
        HStack(spacing: 2) {
            Button("Open \(appName)") { openMainWindow() }
                .buttonStyle(.borderless)
                .padding(.horizontal, 4)
            Spacer()
            if model.phase == .unlocked {
                FooterIcon(symbol: "arrow.clockwise", help: "Sync now") {
                    Task { await model.refresh() }
                }
                .disabled(model.isSyncing)
                FooterIcon(symbol: "lock", help: "Lock") { model.lock() }
            }
            SettingsLink {
                Image(systemName: "gearshape")
                    .frame(width: 26, height: 22)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .help("Settings")
            FooterIcon(symbol: "power", help: "Quit \(appName)") { NSApplication.shared.terminate(nil) }
        }
    }

    private func openMainWindow() {
        openWindow(id: MainWindow.id)
        NSApp.activate()
    }
}

/// A small symbol button in the panel's footer.
private struct FooterIcon: View {
    let symbol: String
    let help: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .frame(width: 26, height: 22)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .help(help)
        .accessibilityLabel(help)
    }
}

/// One login. Clicking it copies the password.
private struct ItemRowView: View {
    let item: ItemSummary
    let copy: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: copy) {
            HStack(spacing: 10) {
                LoginTile(name: item.name, url: item.url, size: 26)
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.name)
                        .lineLimit(1)
                    Text(item.username.isEmpty ? item.place : "\(item.username) · \(item.place)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                Image(systemName: "doc.on.doc")
                    .foregroundStyle(.secondary)
                    .opacity(hovering ? 1 : 0)
            }
            .padding(.vertical, 5)
            .padding(.horizontal, 6)
            .contentShape(Rectangle())
            .background(
                hovering ? AnyShapeStyle(.quaternary) : AnyShapeStyle(.clear),
                in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help("Copy password")
    }
}

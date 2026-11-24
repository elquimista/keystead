import SwiftUI

/// The unlocked vault: folders and people on the left, then a list, then the details.
struct VaultView: View {
    @Bindable var model: AppModel
    @State private var search = ""

    var body: some View {
        NavigationSplitView {
            Sidebar(model: model, selection: $model.section)
                .navigationSplitViewColumnWidth(min: 180, ideal: 210)
        } content: {
            switch model.section ?? .allLogins {
            case .allLogins:
                LoginList(model: model, folder: nil, search: $search, selection: $model.selectedItemID)
            case .folder(let folder):
                LoginList(model: model, folder: folder, search: $search, selection: $model.selectedItemID)
            case .people:
                PeopleList(model: model, selection: $model.selectedUserID)
            }
        } detail: {
            if model.section == .people {
                if let user = model.users.first(where: { $0.id == model.selectedUserID }) {
                    PersonDetail(model: model, user: user)
                } else {
                    Text("Select a person")
                        .foregroundStyle(.secondary)
                }
            } else if let item = model.items.first(where: { $0.id == model.selectedItemID }) {
                LoginDetail(model: model, item: item)
                    .id(item.id)
            } else {
                Text("Select a login")
                    .foregroundStyle(.secondary)
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    Task { await model.refresh() }
                } label: {
                    Label("Sync", systemImage: "arrow.triangle.2.circlepath")
                }
                .help("Fetch changes from the server")
                Button {
                    model.lock()
                } label: {
                    Label("Lock", systemImage: "lock")
                }
                .help("Lock \(appName)")
            }
        }
        .overlay(alignment: .bottom) {
            Notices(model: model)
        }
        .onChange(of: model.folders) {
            // A folder that's gone (renamed, or access removed) can't stay selected.
            if case .folder(let folder) = model.section, !model.folders.contains(folder) {
                model.section = .allLogins
            }
        }
    }
}

private struct Sidebar: View {
    let model: AppModel
    @Binding var selection: AppModel.Section?

    var body: some View {
        List(selection: $selection) {
            Label("All Logins", systemImage: "key")
                .tag(AppModel.Section.allLogins)
            Section("Folders") {
                ForEach(model.folders, id: \.self) { folder in
                    Label(folder, systemImage: "folder")
                        .tag(AppModel.Section.folder(folder))
                        .contextMenu {
                            Button("New Login in \u{201C}\(folder)\u{201D}…") {
                                model.sheet = .addLogin(folder: folder)
                            }
                            Button("Share \u{201C}\(folder)\u{201D}…") {
                                model.sheet = .share(folder: folder, user: nil)
                            }
                        }
                }
                Button {
                    model.sheet = .newFolder
                } label: {
                    Label("New Folder…", systemImage: "plus")
                }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
            }
            Section("Team") {
                Label("People", systemImage: "person.2")
                    .badge(model.isOwner ? model.users.filter { !$0.approved }.count : 0)
                    .tag(AppModel.Section.people)
            }
        }
        .safeAreaInset(edge: .bottom) {
            if let identity = model.identity {
                HStack(spacing: 8) {
                    Image(systemName: "person.crop.circle.fill")
                        .font(.title2)
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(identity.name)
                        Text(identity.isOwner ? "Owner · \(host(identity.server))" : host(identity.server))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
                .padding(10)
            }
        }
    }
}

// MARK: - Logins

private struct LoginList: View {
    let model: AppModel
    let folder: String?
    @Binding var search: String
    @Binding var selection: ItemSummary.ID?

    var body: some View {
        let items = model.items(matching: search, in: folder)
        Group {
            if items.isEmpty {
                emptyState
            } else {
                List(items, selection: $selection) { item in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.name)
                        Text(subtitle(for: item))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 2)
                }
                .contextMenu(forSelectionType: ItemSummary.ID.self) { ids in
                    if let item = items.first(where: { ids.contains($0.id) }) {
                        Button("Copy Password") { Task { await model.copyPassword(of: item) } }
                        Button("Copy Username") { model.copy(item.username) }
                            .disabled(item.username.isEmpty)
                        Divider()
                        Button("Change Password…") { model.sheet = .changePassword(item) }
                    }
                } primaryAction: { ids in
                    // Double-click or Return copies the password.
                    if let item = items.first(where: { ids.contains($0.id) }) {
                        Task { await model.copyPassword(of: item) }
                    }
                }
            }
        }
        .navigationTitle(folder ?? "All Logins")
        .searchable(text: $search, prompt: "Search logins")
        .toolbar {
            ToolbarItem {
                Button {
                    model.sheet = .addLogin(folder: folder)
                } label: {
                    Label("New Login", systemImage: "plus")
                }
                .help("Add a login")
                .disabled(model.folders.isEmpty)
            }
        }
    }

    private func subtitle(for item: ItemSummary) -> String {
        let parts = [item.username, folder == nil ? item.folder : ""].filter { !$0.isEmpty }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder
    private var emptyState: some View {
        if !search.trimmed.isEmpty {
            ContentUnavailableView.search(text: search)
        } else if model.folders.isEmpty {
            ContentUnavailableView {
                Label(model.isOwner ? "Start with a folder" : "Nothing shared with you yet", systemImage: "folder")
            } description: {
                Text(
                    model.isOwner
                        ? "Logins live in folders, and you share whole folders with people. "
                            + "Create one, for example \u{201C}Production\u{201D}, then add logins to it."
                        : "Once the owner approves you and shares a folder, its logins show up "
                            + "here. You can also keep your own folders.")
            } actions: {
                Button("New Folder…") { model.sheet = .newFolder }
            }
        } else {
            ContentUnavailableView {
                Label("No logins yet", systemImage: "key")
            } description: {
                Text(folder.map { "\u{201C}\($0)\u{201D} is empty." } ?? "Your folders are empty.")
            } actions: {
                Button("New Login…") { model.sheet = .addLogin(folder: folder) }
            }
        }
    }
}

private struct LoginDetail: View {
    let model: AppModel
    let item: ItemSummary
    @State private var revealed: String?
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                LabeledContent("Username") {
                    HStack {
                        Text(item.username.isEmpty ? "—" : item.username)
                            .textSelection(.enabled)
                        if !item.username.isEmpty {
                            Button {
                                model.copy(item.username)
                            } label: {
                                Image(systemName: "doc.on.doc")
                            }
                            .buttonStyle(.borderless)
                            .help("Copy username")
                        }
                    }
                }
                LabeledContent("Password") {
                    HStack {
                        Text(revealed ?? "••••••••••••")
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                        Button {
                            Task { await toggleReveal() }
                        } label: {
                            Image(systemName: revealed == nil ? "eye" : "eye.slash")
                        }
                        .buttonStyle(.borderless)
                        .help(revealed == nil ? "Show password" : "Hide password")
                        Button {
                            Task { await model.copyPassword(of: item) }
                        } label: {
                            Image(systemName: "doc.on.doc")
                        }
                        .buttonStyle(.borderless)
                        .help("Copy password (cleared after 30 seconds)")
                    }
                }
                if !item.url.isEmpty {
                    LabeledContent("Website") {
                        HStack {
                            Text(item.url)
                                .textSelection(.enabled)
                            if let url = URL(string: item.url), url.scheme != nil {
                                Link(destination: url) {
                                    Image(systemName: "arrow.up.forward.square")
                                }
                                .help("Open in your browser")
                            }
                        }
                    }
                }
                LabeledContent("Folder", value: item.folder)
            } header: {
                Text(item.name)
                    .font(.title2.weight(.semibold))
                    .padding(.bottom, 4)
            }
            Section {
                Button("Change Password…") { model.sheet = .changePassword(item) }
            }
            if let error {
                Text(error)
                    .foregroundStyle(.red)
            }
        }
        .formStyle(.grouped)
        .onChange(of: model.items) {
            // The password may have changed; don't keep showing the old one.
            revealed = nil
        }
    }

    private func toggleReveal() async {
        if revealed != nil {
            revealed = nil
            return
        }
        do {
            revealed = try await model.password(of: item)
            error = nil
        } catch let failure {
            error = describe(failure)
        }
    }
}

// MARK: - People

private struct PeopleList: View {
    let model: AppModel
    @Binding var selection: User.ID?

    var body: some View {
        List(selection: $selection) {
            ForEach(model.users) { user in
                HStack(spacing: 8) {
                    Image(systemName: "person.crop.circle")
                        .font(.title2)
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(user.userId == model.identity?.userId ? "\(user.name) (you)" : user.name)
                        Text(status(of: user))
                            .font(.caption)
                            .foregroundStyle(user.approved ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
                    }
                }
                .padding(.vertical, 2)
            }
            if model.isOwner && model.users.count <= 1 {
                // An ordinary row, not a bottom inset: wrapping text in a List's inset
                // breaks the split view's layout, blanking the sidebar too.
                VStack(alignment: .leading, spacing: 8) {
                    Text("It's just you so far. Invite your team; they'll show up here once "
                        + "they've joined, ready for you to approve.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Button("Invite Someone…") { model.sheet = .invite }
                }
                .padding(.vertical, 8)
            }
        }
        .navigationTitle("People")
        .toolbar {
            if model.isOwner {
                ToolbarItem {
                    Button {
                        model.sheet = .invite
                    } label: {
                        Label("Invite", systemImage: "person.badge.plus")
                    }
                    .help("Invite someone to your team")
                }
            }
        }
    }
}

private struct PersonDetail: View {
    let model: AppModel
    let user: User

    private var isMe: Bool { user.userId == model.identity?.userId }

    var body: some View {
        Form {
            Section {
                LabeledContent("Status", value: status(of: user))
            } header: {
                Text(user.name)
                    .font(.title2.weight(.semibold))
                    .padding(.bottom, 4)
            }
            if isMe, let identity = model.identity {
                Section("Your fingerprint") {
                    Text(identity.fingerprint)
                        .font(.system(.title3, design: .monospaced))
                        .textSelection(.enabled)
                    if !user.approved {
                        Text("Read it to the owner, in person or on a call, so they can approve you.")
                            .foregroundStyle(.secondary)
                    }
                }
            } else if !user.approved {
                Section {
                    if model.isOwner {
                        Text("\(user.name) has joined and is waiting for you. Ask them to read out "
                            + "the fingerprint their Keystead shows, in person or on a call, and "
                            + "type it in. That proves the keys on the server are really theirs.")
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Approve \(user.name)…") { model.sheet = .approve(user) }
                    } else {
                        Text("Waiting for the owner to approve \(user.name).")
                            .foregroundStyle(.secondary)
                    }
                }
            } else {
                Section {
                    Text("Share a folder to give \(user.name) its logins: everything in it now, "
                        + "and anything added later.")
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Share a Folder…") { model.sheet = .share(folder: nil, user: user) }
                        .disabled(model.folders.isEmpty)
                }
            }
        }
        .formStyle(.grouped)
    }
}

/// Copy confirmations and problems, floating at the bottom of the window.
private struct Notices: View {
    let model: AppModel

    var body: some View {
        VStack(spacing: 8) {
            if let message = model.message {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text(message)
                        .fixedSize(horizontal: false, vertical: true)
                    Button {
                        model.dismissMessage()
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .buttonStyle(.borderless)
                }
                .notice()
            }
            if let copied = model.copiedName {
                Label("Copied the password for \(copied). It clears in 30 seconds.",
                      systemImage: "checkmark.circle.fill")
                    .notice()
            }
        }
        .frame(maxWidth: 520)
        .padding(.bottom, 16)
        .animation(.default, value: model.copiedName)
        .animation(.default, value: model.message)
    }
}

private extension View {
    func notice() -> some View {
        padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
            .shadow(radius: 4, y: 1)
            .transition(.move(edge: .bottom).combined(with: .opacity))
    }
}

func status(of user: User) -> String {
    if user.isOwner { return "Owner" }
    return user.approved ? "Approved" : "Waiting for approval"
}

/// "keys.example.com" from "https://keys.example.com".
func host(_ server: String) -> String {
    guard let url = URL(string: server), let host = url.host() else { return server }
    if let port = url.port { return "\(host):\(port)" }
    return host
}

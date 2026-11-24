import SwiftUI

/// The unlocked vault: folders, people and groups on the left, then a list, then the details.
struct VaultView: View {
    @Bindable var model: AppModel
    @State private var search = ""

    var body: some View {
        NavigationSplitView {
            Sidebar(model: model, selection: $model.section)
                .navigationSplitViewColumnWidth(min: 180, ideal: 210)
        } content: {
            switch model.section ?? .allLogins {
            case .people:
                PeopleList(model: model, selection: $model.selectedUserID)
            case .groups:
                GroupList(model: model, selection: $model.selectedGroupID)
            case .recentlyDeleted:
                DeletedList(model: model, selection: $model.selectedDeletedID)
            case let section:
                LoginList(model: model, section: section, search: $search, selection: $model.selectedItemID)
            }
        } detail: {
            if model.section == .people {
                if let user = model.users.first(where: { $0.id == model.selectedUserID }) {
                    PersonDetail(model: model, user: user)
                } else {
                    Text("Select a person")
                        .foregroundStyle(.secondary)
                }
            } else if model.section == .recentlyDeleted {
                if let login = model.recentlyDeleted.first(where: { $0.id == model.selectedDeletedID }) {
                    DeletedDetail(model: model, login: login)
                        .id(login.id)
                } else {
                    Text(model.recentlyDeleted.isEmpty ? "" : "Select a login")
                        .foregroundStyle(.secondary)
                }
            } else if model.section == .groups {
                if let group = model.groups.first(where: { $0.id == model.selectedGroupID }) {
                    GroupDetail(model: model, group: group)
                        .id(group.id)
                } else {
                    Text(model.groups.isEmpty ? "" : "Select a group")
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
        .onChange(of: model.hasSharedWithMe) {
            if !model.hasSharedWithMe && model.section == .sharedWithMe {
                model.section = .allLogins
            }
        }
        .onChange(of: model.recentlyDeleted.isEmpty) {
            if model.recentlyDeleted.isEmpty && model.section == .recentlyDeleted {
                model.section = .allLogins
            }
        }
        .onChange(of: model.toChange.isEmpty) {
            // The last one was changed or dismissed; the login stays selected.
            if model.toChange.isEmpty && model.section == .toChange {
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
            if model.hasSharedWithMe {
                Label("Shared with Me", systemImage: "shared.with.you")
                    .tag(AppModel.Section.sharedWithMe)
            }
            if !model.toChange.isEmpty {
                Label("To Change", systemImage: "exclamationmark.triangle")
                    .badge(model.toChangeCount)
                    .tag(AppModel.Section.toChange)
                    .help("Passwords that people who lost access may still know")
            }
            if !model.recentlyDeleted.isEmpty {
                Label("Recently Deleted", systemImage: "trash")
                    .tag(AppModel.Section.recentlyDeleted)
                    .help("Logins deleted in the last 30 days, which can be brought back")
            }
            Section("Folders") {
                ForEach(model.folders, id: \.self) { folder in
                    Label(folder, systemImage: "folder")
                        .tag(AppModel.Section.folder(folder))
                        .contextMenu {
                            Button("New Login in \u{201C}\(folder)\u{201D}…") {
                                model.sheet = .addLogin(folder: folder)
                            }
                            .disabled(model.folderRoles[folder] == .view)
                            if model.manages(folder: folder) {
                                Button("Share \u{201C}\(folder)\u{201D}…") {
                                    model.sheet = .share(folder: folder, user: nil)
                                }
                            }
                            Button("Access…") { model.sheet = .manageFolder(folder) }
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
                Label("Groups", systemImage: "person.3")
                    .tag(AppModel.Section.groups)
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
    let section: AppModel.Section
    @Binding var search: String
    @Binding var selection: ItemSummary.ID?

    private var folder: String? {
        if case .folder(let folder) = section { return folder }
        return nil
    }

    private var title: String {
        switch section {
        case .folder(let folder): folder
        case .sharedWithMe: "Shared with Me"
        case .toChange: "To Change"
        case .allLogins, .people, .groups, .recentlyDeleted: "All Logins"
        }
    }

    var body: some View {
        let items = model.items(matching: search, in: section)
        Group {
            if items.isEmpty {
                emptyState
            } else {
                List(selection: $selection) {
                    if section == .toChange {
                        Text("People who lost access may still know these passwords. Change "
                            + "each one at its website, then save the new one here.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .padding(.bottom, 4)
                            .selectionDisabled()
                    }
                    rows(items)
                }
                .contextMenu(forSelectionType: ItemSummary.ID.self) { ids in
                    if let item = items.first(where: { ids.contains($0.id) }) {
                        Button("Copy Password") { Task { await model.copyPassword(of: item) } }
                        Button("Copy Username") { model.copy(item.username) }
                            .disabled(item.username.isEmpty)
                        if item.hasOneTimeCode {
                            Button("Copy One-Time Code") { Task { await model.copyOneTimeCode(of: item) } }
                        }
                        Divider()
                        Button("Edit…") { model.sheet = .editLogin(item) }
                            .disabled(item.role == .view)
                        Button(item.role == .manage ? "Share…" : "Access…") {
                            model.sheet = .shareLogin(item)
                        }
                        Divider()
                        Button("Delete…", role: .destructive) { model.sheet = .deleteLogin(item) }
                            .disabled(item.role == .view)
                    }
                } primaryAction: { ids in
                    // Double-click or Return copies the password.
                    if let item = items.first(where: { ids.contains($0.id) }) {
                        Task { await model.copyPassword(of: item) }
                    }
                }
            }
        }
        .navigationTitle(title)
        .searchable(text: $search, prompt: "Search logins")
        .toolbar {
            ToolbarItem {
                Button {
                    model.sheet = .addLogin(folder: folder)
                } label: {
                    Label("New Login", systemImage: "plus")
                }
                .help("Add a login")
                .disabled(folder.map { model.folderRoles[$0] == .view } ?? false)
            }
            if let folder {
                ToolbarItem {
                    Button {
                        model.sheet = .manageFolder(folder)
                    } label: {
                        Label("Access", systemImage: "person.2")
                    }
                    .help("Who has access to \u{201C}\(folder)\u{201D}")
                }
            }
        }
    }

    private func rows(_ items: [ItemSummary]) -> some View {
        ForEach(items) { item in
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name)
                Text(subtitle(for: item))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 2)
        }
    }

    /// The username, and outside a folder's own list, where the login lives. On To Change,
    /// who lost access instead.
    private func subtitle(for item: ItemSummary) -> String {
        if section == .toChange {
            let entries = model.toChange(for: item)
            let names = ListFormatter.localizedString(byJoining: entries.map(\.userName))
            return "\(names) lost access \(day(entries.first?.since ?? 0))"
        }
        let parts = [item.username, folder == nil ? item.place : ""].filter { !$0.isEmpty }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder
    private var emptyState: some View {
        if !search.trimmed.isEmpty {
            ContentUnavailableView.search(text: search)
        } else if section == .toChange {
            ContentUnavailableView(
                "Nothing to change", systemImage: "checkmark.shield",
                description: Text("When someone loses access, the passwords they could see show "
                    + "up here."))
        } else if section == .sharedWithMe {
            ContentUnavailableView(
                "Nothing shared with you", systemImage: "shared.with.you",
                description: Text("Logins people share with you one by one show up here."))
        } else if model.items.isEmpty && model.folders.isEmpty {
            ContentUnavailableView {
                Label("No logins yet", systemImage: "key")
            } description: {
                Text(
                    model.isOwner
                        ? "Add a login; only you can see it until you share it. For logins your "
                            + "team needs, create a folder, for example \u{201C}Production\u{201D}, "
                            + "and share it."
                        : "Logins shared with you show up here once the owner approves you. You "
                            + "can also add your own.")
            } actions: {
                Button("New Login…") { model.sheet = .addLogin(folder: nil) }
                Button("New Folder…") { model.sheet = .newFolder }
            }
        } else {
            ContentUnavailableView {
                Label("No logins yet", systemImage: "key")
            } description: {
                Text(folder.map { "\u{201C}\($0)\u{201D} is empty." } ?? "You have no logins yet.")
            } actions: {
                Button("New Login…") { model.sheet = .addLogin(folder: folder) }
            }
        }
    }
}

private struct LoginDetail: View {
    let model: AppModel
    let item: ItemSummary
    /// The password and notes, decrypted only once asked for.
    @State private var details: LoginDetails?
    @State private var showsPassword = false
    @State private var showsNotes = false
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
                        Text(showsPassword ? details?.password ?? "" : "••••••••••••")
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                        Button {
                            Task { await reveal(\.showsPassword) }
                        } label: {
                            Image(systemName: showsPassword ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.borderless)
                        .help(showsPassword ? "Hide password" : "Show password")
                        Button {
                            Task { await model.copyPassword(of: item) }
                        } label: {
                            Image(systemName: "doc.on.doc")
                        }
                        .buttonStyle(.borderless)
                        .help("Copy password (cleared after 30 seconds)")
                    }
                }
                if item.hasOneTimeCode {
                    OneTimeCodeRow(model: model, item: item)
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
                LabeledContent("Notes") {
                    HStack(alignment: .firstTextBaseline) {
                        if showsNotes {
                            let notes = details?.notes ?? ""
                            Text(notes.isEmpty ? "None" : notes)
                                .foregroundStyle(notes.isEmpty ? .secondary : .primary)
                                .textSelection(.enabled)
                                .multilineTextAlignment(.trailing)
                        } else {
                            Text("Hidden")
                                .foregroundStyle(.secondary)
                        }
                        Button {
                            Task { await reveal(\.showsNotes) }
                        } label: {
                            Image(systemName: showsNotes ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.borderless)
                        .help(showsNotes ? "Hide notes" : "Show notes")
                    }
                }
                // A login shared with you may sit in a folder of theirs you can't see.
                if item.folder != nil || !item.sharedWithMe {
                    LabeledContent("Folder", value: item.folder ?? "None")
                }
                if let owner = item.owner {
                    LabeledContent("Shared by", value: owner)
                }
                if item.folder == nil && item.owner == nil && !item.sharedWithMe {
                    LabeledContent(
                        "Shared with",
                        value: item.sharedWithAll.isEmpty ? "No one yet" : sharedWith)
                } else if !item.sharedWithAll.isEmpty {
                    LabeledContent("Also shared with", value: sharedWith)
                }
                if item.role != .manage {
                    LabeledContent("Your access", value: item.role.label)
                }
            } header: {
                Text(item.name)
                    .font(.title2.weight(.semibold))
                    .padding(.bottom, 4)
            }
            let exposures = model.toChange(for: item)
            if !exposures.isEmpty {
                Section {
                    Label {
                        Text("\(ListFormatter.localizedString(byJoining: exposures.map(\.userName))) "
                            + "could see this password until losing access \(day(exposures[0].since)), "
                            + "and may still know it. Change it at the website, then save the new "
                            + "one here.")
                            .fixedSize(horizontal: false, vertical: true)
                    } icon: {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    }
                    HStack {
                        Button("Change Password…") { model.sheet = .editLogin(item) }
                        Spacer()
                        Button("Keep It") {
                            Task {
                                do {
                                    try await model.dismissToChange(of: item)
                                } catch let failure {
                                    error = describe(failure)
                                }
                            }
                        }
                        .help("Take it off To Change without changing the password")
                    }
                }
            }
            Section {
                HStack {
                    Button("Edit…") { model.sheet = .editLogin(item) }
                        .disabled(item.role == .view)
                    Button(item.role == .manage ? "Share…" : "Access…") {
                        model.sheet = .shareLogin(item)
                    }
                    Button("History…") { model.sheet = .history(item) }
                        .disabled(item.role == .view)
                        .help("Earlier versions of this login, and bringing one back")
                    Spacer()
                    Button("Delete…", role: .destructive) { model.sheet = .deleteLogin(item) }
                        .disabled(item.role == .view)
                }
            }
            if let error {
                Text(error)
                    .foregroundStyle(.red)
            }
        }
        .formStyle(.grouped)
        .onChange(of: model.items) {
            // The login may have changed; don't keep showing the old password or notes.
            details = nil
            showsPassword = false
            showsNotes = false
        }
    }

    /// People by name, then groups, marked as groups.
    private var sharedWith: String {
        ListFormatter.localizedString(
            byJoining: item.sharedWith + item.sharedWithGroups.map { "\($0) (group)" })
    }

    /// Shows or hides the password or the notes, decrypting both the first time.
    private func reveal(_ shown: ReferenceWritableKeyPath<LoginDetail, Bool>) async {
        if self[keyPath: shown] {
            self[keyPath: shown] = false
            return
        }
        do {
            if details == nil {
                details = try await model.details(of: item)
            }
            self[keyPath: shown] = true
            error = nil
        } catch let failure {
            error = describe(failure)
        }
    }
}

/// A login's current one-time code and the seconds it has left, fetched again as each one
/// runs out.
private struct OneTimeCodeRow: View {
    let model: AppModel
    let item: ItemSummary
    @State private var code: OneTimeCode?
    @State private var expires = Date.distantPast
    @State private var error: String?

    var body: some View {
        LabeledContent("One-time code") {
            HStack {
                if let code {
                    Text(grouped(code.code))
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let left = max(0, Int(expires.timeIntervalSince(context.date).rounded(.up)))
                        Text("\(left)s")
                            .monospacedDigit()
                            .foregroundStyle(left <= 5 ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                            .help("Seconds until the next code")
                    }
                    Button {
                        Task { await model.copyOneTimeCode(of: item) }
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .help("Copy one-time code (cleared after 30 seconds)")
                } else if let error {
                    Text(error)
                        .foregroundStyle(.red)
                } else {
                    ProgressView()
                        .controlSize(.small)
                }
            }
        }
        .task(id: "\(item.id)-\(model.localRevision)") {
            while !Task.isCancelled {
                do {
                    guard let next = try await model.oneTimeCode(of: item) else { return }
                    code = next
                    error = nil
                    expires = Date().addingTimeInterval(TimeInterval(next.remaining))
                    try await Task.sleep(for: .seconds(Double(next.remaining)))
                } catch is CancellationError {
                    return
                } catch let failure {
                    error = describe(failure)
                    return
                }
            }
        }
    }

    /// "492 039", "4920 3912": easier to read and type.
    private func grouped(_ code: String) -> String {
        let middle = code.index(code.startIndex, offsetBy: code.count / 2)
        return "\(code[..<middle]) \(code[middle...])"
    }
}

// MARK: - Recently deleted

private struct DeletedList: View {
    let model: AppModel
    @Binding var selection: DeletedLogin.ID?

    var body: some View {
        List(model.recentlyDeleted, selection: $selection) { login in
            VStack(alignment: .leading, spacing: 2) {
                Text(login.name)
                Text(["Deleted by \(login.deletedBy) \(day(login.deletedAt))", login.folder ?? ""]
                    .filter { !$0.isEmpty }
                    .joined(separator: " · "))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 2)
        }
        .navigationTitle("Recently Deleted")
    }
}

/// A deleted login: what it was, who deleted it, and bringing it back or deleting it for
/// good.
private struct DeletedDetail: View {
    let model: AppModel
    let login: DeletedLogin
    @State private var confirmingPurge = false
    @State private var busy = false
    @State private var note: String?

    var body: some View {
        Form {
            Section {
                if !login.username.isEmpty {
                    LabeledContent("Username", value: login.username)
                }
                LabeledContent("Folder", value: login.folder ?? "None")
                LabeledContent("Deleted", value: "By \(login.deletedBy) \(day(login.deletedAt))")
                LabeledContent("Kept until", value: String(day(login.keptUntil).dropFirst(3)))
            } header: {
                Text(login.name)
                    .font(.title2.weight(.semibold))
                    .padding(.bottom, 4)
            }
            Section {
                Text("Bringing it back gives it to everyone who had it before it was deleted, as "
                    + "it was then. After the date above it's gone for good.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Bring Back") { run { note = try await model.undelete(login) } }
                    Spacer()
                    Button("Delete Now…", role: .destructive) { confirmingPurge = true }
                }
                .disabled(busy)
                if let note {
                    Text(note)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .formStyle(.grouped)
        .confirmationDialog(
            "Delete \u{201C}\(login.name)\u{201D} for good?", isPresented: $confirmingPurge
        ) {
            Button("Delete for Good", role: .destructive) { run { try await model.purge(login) } }
        } message: {
            Text("It can't be brought back afterwards, by you or anyone it was shared with.")
        }
    }

    private func run(_ action: @escaping () async throws -> Void) {
        busy = true
        Task {
            do {
                try await action()
            } catch {
                note = describe(error)
            }
            busy = false
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
                Section("Recovery Kit") {
                    Text("If this Mac is lost, broken or wiped, your Recovery Kit brings your "
                        + "account back on a new one.")
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Show Recovery Kit…") { model.sheet = .recoveryKit(afterSetup: false) }
                }
                Section("Your devices") {
                    if let problem = model.devicesProblem {
                        Text("Couldn't load your devices: \(problem).")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    ForEach(model.devices, id: \.deviceId) { device in
                        DeviceRow(model: model, device: device)
                    }
                    Button("Add a Device…") { model.sheet = .addDevice }
                        .help("Use your account on another Mac or computer too")
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
            } else if user.removed {
                Section {
                    Text("\(user.name) was removed from the team. Their devices no longer work, "
                        + "and nobody can share with them.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                PasswordsToChange(model: model, user: user)
            } else {
                Section {
                    Text("Share a folder to give \(user.name) its logins: everything in it now, "
                        + "and anything added later.")
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Share a Folder…") { model.sheet = .share(folder: nil, user: user) }
                        .disabled(!model.folders.contains { model.manages(folder: $0) })
                }
                PasswordsToChange(model: model, user: user)
                if model.isOwner && !user.isOwner {
                    Section {
                        Text("Removing \(user.name) stops their devices and takes away every "
                            + "folder and login, for example when they leave the company.")
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Remove from Team…", role: .destructive) {
                            model.sheet = .removeUser(user)
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
    }
}

/// The passwords someone could see before losing access that you can change, if any.
private struct PasswordsToChange: View {
    let model: AppModel
    let user: User
    @State private var confirming = false
    @State private var error: String?

    var body: some View {
        let entries = model.toChange.filter { $0.userId == user.userId }
        if !entries.isEmpty {
            Section("Passwords to change") {
                Text("\(user.name) could see \(entries.count == 1 ? "1 password" : "\(entries.count) passwords") "
                    + "you can change, until losing access \(day(entries[0].since)).")
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Show") { model.section = .toChange }
                    Spacer()
                    Button("Keep All…") { confirming = true }
                }
                if let error {
                    Text(error)
                        .foregroundStyle(.red)
                }
            }
            .confirmationDialog(
                "Keep every password \(user.name) could see?", isPresented: $confirming
            ) {
                Button("Keep All") {
                    Task {
                        do {
                            try await model.dismissAllToChange(for: user.userId)
                        } catch let failure {
                            error = describe(failure)
                        }
                    }
                }
            } message: {
                Text("They come off To Change without new passwords. Do this when \(user.name) "
                    + "only moved to another team; after someone leaves, change them instead.")
            }
        }
    }
}

// MARK: - Groups

private struct GroupList: View {
    let model: AppModel
    @Binding var selection: GroupSummary.ID?

    var body: some View {
        List(selection: $selection) {
            ForEach(model.groups) { group in
                HStack(spacing: 8) {
                    Image(systemName: "person.3")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(group.name)
                        Text(summary(of: group))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 2)
            }
            if model.groups.isEmpty {
                // An ordinary row, not a bottom inset, as in People.
                VStack(alignment: .leading, spacing: 8) {
                    Text(model.isOwner
                        ? "Make a group for a team or a role, like Engineering or Support, then "
                            + "share folders and logins with everyone in it at once. People added "
                            + "to the group later get them too."
                        : "No groups yet. The owner makes them.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    if model.isOwner {
                        Button("New Group…") { model.sheet = .newGroup }
                    }
                }
                .padding(.vertical, 8)
            }
        }
        .navigationTitle("Groups")
        .toolbar {
            if model.isOwner {
                ToolbarItem {
                    Button {
                        model.sheet = .newGroup
                    } label: {
                        Label("New Group", systemImage: "plus")
                    }
                    .help("Make a group")
                }
            }
        }
    }

    private func summary(of group: GroupSummary) -> String {
        let count = group.members.count == 1 ? "1 person" : "\(group.members.count) people"
        if group.members.contains(where: { $0.isMe && $0.isManager }) {
            return "\(count) · you manage it"
        }
        return group.isMember ? "\(count) · you're in it" : count
    }
}

private struct GroupDetail: View {
    let model: AppModel
    let group: GroupSummary
    @State private var leaving = false
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        Form {
            Section {
                ForEach(group.members) { member in
                    HStack {
                        Text(member.isMe ? "\(member.name) (you)" : member.name)
                        if member.isManager {
                            Text("Manager")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if group.canManage {
                            Menu {
                                Button(member.isManager ? "Stop Managing the Group" : "Make Manager") {
                                    run { try await model.setManager(member, of: group, to: !member.isManager) }
                                }
                                if !member.isMe {
                                    Button("Remove from Group") {
                                        run { try await model.remove(member, from: group) }
                                    }
                                }
                            } label: {
                                Image(systemName: "ellipsis.circle")
                            }
                            .menuStyle(.borderlessButton)
                            .fixedSize()
                            .help("Manage \(member.name)")
                        }
                    }
                }
                if group.members.isEmpty {
                    Text("No one is in this group.")
                        .foregroundStyle(.secondary)
                }
            } header: {
                VStack(alignment: .leading, spacing: 2) {
                    Text(group.name)
                        .font(.title2.weight(.semibold))
                    Text(group.members.count == 1 ? "1 person" : "\(group.members.count) people")
                        .foregroundStyle(.secondary)
                }
                .padding(.bottom, 4)
            }
            Section {
                Text("Folders and logins shared with \(group.name) reach everyone in it, "
                    + "including people added later. Taking someone out gives the group, and the "
                    + "folders shared with it, new keys, so they can't read what's saved afterwards.")
                    .fixedSize(horizontal: false, vertical: true)
                if group.canManage && !group.canAdd {
                    Text("Only managers who are in the group can add people, as that hands them "
                        + "its key.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    if group.canAdd {
                        Button("Add Person…") { model.sheet = .addToGroup(group) }
                    }
                    Button("Share a Folder…") { model.sheet = .shareWithGroup(group) }
                        .disabled(!model.folders.contains { model.manages(folder: $0) })
                    if group.canManage {
                        Button("Rename…") { model.sheet = .renameGroup(group) }
                    }
                    Spacer()
                    if busy {
                        ProgressView().controlSize(.small)
                    }
                    if group.isMember {
                        Button("Leave…") { leaving = true }
                    }
                }
            }
            if let error {
                Text(error)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
        .disabled(busy)
        .confirmationDialog("Leave \u{201C}\(group.name)\u{201D}?", isPresented: $leaving) {
            Button("Leave", role: .destructive) {
                if let me = group.members.first(where: \.isMe) {
                    run { try await model.remove(me, from: group) }
                }
            }
        } message: {
            Text("You'll lose the folders and logins shared with it, unless you have them "
                + "another way.")
        }
    }

    private func run(_ action: @escaping () async throws -> Void) {
        busy = true
        Task {
            do {
                try await action()
                error = nil
            } catch let failure {
                error = describe(failure)
            }
            busy = false
        }
    }
}

/// One of the account's devices, with a way to remove the others.
private struct DeviceRow: View {
    let model: AppModel
    let device: AccountDevice
    @State private var confirming = false
    @State private var error: String?

    private var title: String { device.name.isEmpty ? "Unnamed device" : device.name }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "laptopcomputer")
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                if let added = device.addedAt {
                    Text("Added " + Date(timeIntervalSince1970: TimeInterval(added))
                        .formatted(date: .abbreviated, time: .omitted))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if let error {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
            Spacer()
            if device.current {
                Text("This Mac")
                    .foregroundStyle(.secondary)
                Button("Sign Out…") { model.sheet = .signOut }
            } else {
                Button("Remove…") { confirming = true }
            }
        }
        .confirmationDialog("Remove \u{201C}\(title)\u{201D}?", isPresented: $confirming) {
            Button("Remove", role: .destructive) {
                Task {
                    do {
                        try await model.removeDevice(device)
                    } catch let failure {
                        error = describe(failure)
                    }
                }
            }
        } message: {
            Text("It won't be able to sign in any more. Do this for a lost or retired device. "
                + "To use it again, recover your account on it with your Recovery Kit.")
        }
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
                Label("Copied the \(model.copiedWhat) for \(copied). It clears in 30 seconds.",
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
    if user.removed { return "Removed" }
    return user.approved ? "Approved" : "Waiting for approval"
}

/// "on Nov 24, 2026" from seconds since 1970.
func day(_ seconds: Int64) -> String {
    "on " + Date(timeIntervalSince1970: TimeInterval(seconds)).formatted(date: .abbreviated, time: .omitted)
}

/// "keys.example.com" from "https://keys.example.com".
func host(_ server: String) -> String {
    guard let url = URL(string: server), let host = url.host() else { return server }
    if let port = url.port { return "\(host):\(port)" }
    return host
}

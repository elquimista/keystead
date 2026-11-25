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
                ContentUnavailableView("No Login Selected", systemImage: "key.horizontal")
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
        .onChange(of: model.section) {
            if model.section == .health {
                Task { await model.checkHealth() }
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
            Label("Password Health", systemImage: "heart.text.square")
                .badge(model.health?.logins.count ?? 0)
                .tag(AppModel.Section.health)
                .help("Weak, reused and old passwords among the logins you can change")
            Section("Folders") {
                FolderTree(model: model, nodes: FolderNode.tree(model.folders))
                Button {
                    model.sheet = .newFolder(inside: nil)
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
                            .lineLimit(1)
                        Text(identity.isOwner ? "Owner · \(host(identity.server))" : host(identity.server))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    // Syncing happens on its own; this shows it, and syncs now on a click. Out
                    // of the toolbar, which stays for what's selected; also in the Vault menu.
                    if model.isSyncing {
                        ProgressView()
                            .controlSize(.small)
                            .frame(width: 16, height: 16)
                            .help("Syncing…")
                    } else {
                        Button {
                            Task { await model.refresh() }
                        } label: {
                            Image(systemName: "arrow.triangle.2.circlepath")
                        }
                        .buttonStyle(.borderless)
                        .help("Syncs on its own every few minutes. Sync now (⌘R)")
                    }
                    Button {
                        model.lock()
                    } label: {
                        Image(systemName: "lock")
                    }
                    .buttonStyle(.borderless)
                    .help("Lock \(appName) (⇧⌘L)")
                }
                .padding(10)
            }
        }
    }
}

/// A folder in the sidebar's tree. Folders nest by name ("Engineering / Databases"); a step
/// that's no folder itself, only holds folders, can't be selected.
struct FolderNode: Identifiable {
    /// The full name, "Engineering / Databases".
    let id: String
    /// The last part, "Databases".
    let name: String
    let isFolder: Bool
    let children: [FolderNode]

    static let separator = " / "

    static func tree(_ folders: [String]) -> [FolderNode] {
        build(folders.map { $0.components(separatedBy: separator) }, under: [])
    }

    private static func build(_ paths: [[String]], under prefix: [String]) -> [FolderNode] {
        var rests: [String: [[String]]] = [:]
        for path in paths where !path.isEmpty {
            rests[path[0], default: []].append(Array(path.dropFirst()))
        }
        return rests.keys
            .sorted { $0.localizedStandardCompare($1) == .orderedAscending }
            .map { head in
                let below = rests[head] ?? []
                return FolderNode(
                    id: (prefix + [head]).joined(separator: separator), name: head,
                    isFolder: below.contains(where: \.isEmpty),
                    children: build(below.filter { !$0.isEmpty }, under: prefix + [head]))
            }
    }
}

/// Folders in the sidebar, nested, open unless collapsed.
private struct FolderTree: View {
    let model: AppModel
    let nodes: [FolderNode]

    var body: some View {
        ForEach(nodes) { node in
            if node.children.isEmpty {
                FolderRow(model: model, node: node)
            } else {
                DisclosureGroup(isExpanded: Binding(
                    get: { !model.collapsedFolders.contains(node.id) },
                    set: { open in
                        if open {
                            model.collapsedFolders.remove(node.id)
                        } else {
                            model.collapsedFolders.insert(node.id)
                        }
                    }
                )) {
                    FolderTree(model: model, nodes: node.children)
                } label: {
                    FolderRow(model: model, node: node)
                }
            }
        }
    }
}

private struct FolderRow: View {
    let model: AppModel
    let node: FolderNode

    var body: some View {
        if node.isFolder {
            let folder = node.id
            Label(node.name, systemImage: "folder")
                .tag(AppModel.Section.folder(folder))
                .contextMenu {
                    Button("New Login in \u{201C}\(node.name)\u{201D}…") {
                        model.sheet = .addLogin(folder: folder)
                    }
                    .disabled(model.folderRoles[folder] == .view)
                    Button("New Folder Inside…") { model.sheet = .newFolder(inside: folder) }
                    if model.manages(folder: folder) {
                        Button("Share \u{201C}\(node.name)\u{201D}…") {
                            model.sheet = .share(folder: folder, user: nil)
                        }
                    }
                    Button("Access…") { model.sheet = .manageFolder(folder) }
                    if model.manages(folder: folder) {
                        Divider()
                        Button("Rename…") { model.sheet = .renameFolder(folder) }
                        Button("Delete Folder…", role: .destructive) {
                            model.sheet = .deleteFolder(folder)
                        }
                    }
                }
        } else {
            // Only folders inside it are yours, not this one.
            Label(node.name, systemImage: "folder")
                .foregroundStyle(.secondary)
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
        case .health: "Password Health"
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
                    if section == .health {
                        Text("These logins you can change have a password that's easy to "
                            + "guess, used for other logins too, or unchanged for over a year. "
                            + "Change each one at its website, then save the new one here."
                            + (model.health?.agesKnown == false
                                ? " Old ones show once your server is on 0.13.0." : ""))
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
                        Button("Move To…") { model.sheet = .moveLogin(item) }
                            .disabled(!model.canMove(item))
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
                // ⌘C and Delete while the list has focus; text fields keep their own.
                .onCommand(#selector(NSText.copy(_:))) {
                    if let item = model.selectedItem {
                        Task { await model.copyPassword(of: item) }
                    }
                }
                .onDeleteCommand {
                    if let item = model.selectedItem, item.role != .view {
                        model.sheet = .deleteLogin(item)
                    }
                }
                // Logins added or deleted slide in and out; typing a search doesn't animate.
                .animation(.snappy(duration: 0.25), value: model.items.count)
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
            HStack(spacing: 10) {
                LoginTile(name: item.name, url: item.url, size: 28)
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.name)
                        .lineLimit(1)
                    let subtitle = subtitle(for: item)
                    if !subtitle.isEmpty {
                        Text(subtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
            }
            .padding(.vertical, 3)
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
        if section == .health, let entry = model.health(for: item) {
            var problems: [String] = []
            if entry.weak { problems.append("Weak") }
            if !entry.reusedWith.isEmpty {
                problems.append("Same as " + ListFormatter.localizedString(byJoining: entry.reusedWith))
            }
            if let since = entry.oldSince { problems.append("Set \(day(since))") }
            return problems.joined(separator: " · ")
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
        } else if section == .health {
            if let health = model.health {
                ContentUnavailableView(
                    "No weak, reused or old passwords", systemImage: "checkmark.shield",
                    description: Text("Checked \(health.checked) logins you can change."))
            } else {
                ProgressView("Checking passwords…")
            }
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
                Button("New Folder…") { model.sheet = .newFolder(inside: nil) }
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
                if !item.username.isEmpty {
                    FieldRow("Username", copyHelp: "Copy username") {
                        model.copy(item.username)
                    } value: {
                        Text(item.username)
                    }
                }
                FieldRow(
                    "Password", copyHelp: "Copy password (cleared after 30 seconds)"
                ) {
                    Task { await model.copyPassword(of: item) }
                } value: {
                    Text(showsPassword ? details?.password ?? "" : "••••••••••••")
                        .font(.system(.body, design: .monospaced))
                } accessory: { hovering in
                    RevealButton(what: "password", shown: showsPassword, hovering: hovering) {
                        await reveal(\.showsPassword)
                    }
                }
                if item.hasOneTimeCode {
                    OneTimeCodeRow(model: model, item: item)
                }
                if !item.url.isEmpty {
                    FieldRow("Website", copyHelp: "Copy website address", valueCopies: false) {
                        model.copy(item.url)
                    } value: {
                        if let url = URL(string: item.url), url.scheme != nil {
                            Link(item.url, destination: url)
                                .help("Open in your browser")
                        } else {
                            Text(item.url)
                        }
                    }
                }
                FieldRow("Notes", copy: nil) {
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
                } accessory: { hovering in
                    RevealButton(what: "notes", shown: showsNotes, hovering: hovering) {
                        await reveal(\.showsNotes)
                    }
                }
            } header: {
                LoginHeader(item: item)
            }
            Section {
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
            }
            let exposures = model.toChange(for: item)
            if !exposures.isEmpty {
                Section {
                    Label {
                        Text("\(ListFormatter.localizedString(byJoining: exposures.map(\.userName))) "
                            + "could see this password until losing access \(day(exposures[0].since)), "
                            + "and may still know it. Change it at the website, then save it here.")
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
            if let error {
                Text(error)
                    .foregroundStyle(.red)
            }
        }
        .formStyle(.grouped)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    model.sheet = .editLogin(item)
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                .help("Edit this login")
                .disabled(item.role == .view)
                Button {
                    model.sheet = .shareLogin(item)
                } label: {
                    Label(
                        item.role == .manage ? "Share" : "Access",
                        systemImage: item.role == .manage ? "person.crop.circle.badge.plus" : "person.2")
                }
                .help(item.role == .manage ? "Share this login" : "Who can open this login")
                Menu {
                    Button("History…") { model.sheet = .history(item) }
                        .disabled(item.role == .view)
                    Button("Move To…") { model.sheet = .moveLogin(item) }
                        .disabled(!model.canMove(item))
                    Divider()
                    Button("Delete…", role: .destructive) { model.sheet = .deleteLogin(item) }
                        .disabled(item.role == .view)
                } label: {
                    Label("More", systemImage: "ellipsis.circle")
                }
                .help("History, Move To and Delete")
            }
        }
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

/// A login's tile, name, and website or where it lives, above its fields.
private struct LoginHeader: View {
    let item: ItemSummary

    var body: some View {
        PageHeader(title: item.name, subtitle: item.url.isEmpty ? item.place : host(item.url)) {
            LoginTile(name: item.name, url: item.url, size: 52)
        }
    }
}

/// One field of a login: its label and value and, while the pointer is over it, a button
/// that copies it, which turns into a check mark for a moment. Clicking the value copies it
/// too, unless it's a link. `accessory` adds buttons of its own, told when the pointer is
/// over the row.
private struct FieldRow<Value: View, Accessory: View>: View {
    let label: String
    let copyHelp: String
    let valueCopies: Bool
    let copy: (() -> Void)?
    let value: Value
    let accessory: (Bool) -> Accessory

    @State private var hovering = false
    @State private var copied = false

    init(
        _ label: String, copyHelp: String = "Copy", valueCopies: Bool = true,
        copy: (() -> Void)?, @ViewBuilder value: () -> Value,
        @ViewBuilder accessory: @escaping (Bool) -> Accessory
    ) {
        self.label = label
        self.copyHelp = copyHelp
        self.valueCopies = valueCopies
        self.copy = copy
        self.value = value()
        self.accessory = accessory
    }

    var body: some View {
        LabeledContent(label) {
            HStack(spacing: 8) {
                if let copy, valueCopies {
                    Button {
                        copied(copy)
                    } label: {
                        value
                    }
                    .buttonStyle(.plain)
                    .help(copyHelp)
                } else {
                    value
                }
                accessory(hovering)
                if let copy {
                    Button {
                        copied(copy)
                    } label: {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                            .contentTransition(.symbolEffect(.replace))
                    }
                    .buttonStyle(.borderless)
                    .help(copyHelp)
                    .opacity(hovering || copied ? 1 : 0)
                }
            }
        }
        .onHover { hovering = $0 }
        .animation(.easeOut(duration: 0.15), value: hovering)
    }

    private func copied(_ copy: () -> Void) {
        copy()
        copied = true
        Task {
            try? await Task.sleep(for: .seconds(1.5))
            copied = false
        }
    }
}

extension FieldRow where Accessory == EmptyView {
    init(
        _ label: String, copyHelp: String = "Copy", valueCopies: Bool = true,
        copy: (() -> Void)?, @ViewBuilder value: () -> Value
    ) {
        self.init(
            label, copyHelp: copyHelp, valueCopies: valueCopies, copy: copy, value: value,
            accessory: { _ in EmptyView() })
    }
}

/// Shows or hides a field: there while the pointer is over its row, or while it's shown.
struct RevealButton: View {
    let what: String
    let shown: Bool
    let hovering: Bool
    let toggle: () async -> Void

    var body: some View {
        Button {
            Task { await toggle() }
        } label: {
            Image(systemName: shown ? "eye.slash" : "eye")
                .contentTransition(.symbolEffect(.replace))
        }
        .buttonStyle(.borderless)
        .help(shown ? "Hide \(what)" : "Show \(what)")
        .opacity(hovering || shown ? 1 : 0)
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
        FieldRow(
            "One-time code", copyHelp: "Copy one-time code (cleared after 30 seconds)",
            copy: code == nil ? nil : { Task { await model.copyOneTimeCode(of: item) } }
        ) {
            HStack(spacing: 8) {
                if let code {
                    Text(grouped(code.code))
                        .font(.system(.body, design: .monospaced))
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let left = max(0, Int(expires.timeIntervalSince(context.date).rounded(.up)))
                        Text("\(left)s")
                            .monospacedDigit()
                            .foregroundStyle(left <= 5 ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                            .help("Seconds until the next code")
                    }
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
            HStack(spacing: 10) {
                LoginTile(name: login.name, url: "", size: 28, muted: true)
                VStack(alignment: .leading, spacing: 1) {
                    Text(login.name)
                        .lineLimit(1)
                    Text(["Deleted by \(login.deletedBy) \(day(login.deletedAt))", login.folder ?? ""]
                        .filter { !$0.isEmpty }
                        .joined(separator: " · "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            .padding(.vertical, 3)
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
                LabeledContent("Kept until", value: String(day(login.keptUntil).dropFirst(3)))
                if let note {
                    Text(note)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } header: {
                PageHeader(
                    title: login.name,
                    subtitle: "Deleted by \(login.deletedBy) \(day(login.deletedAt))"
                ) {
                    LoginTile(name: login.name, url: "", size: 52, muted: true)
                }
            } footer: {
                Text("Bringing it back gives it to everyone who had it before it was deleted, as "
                    + "it was then. After the date above it's gone for good.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .multilineTextAlignment(.leading)
            }
        }
        .formStyle(.grouped)
        .disabled(busy)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    run { note = try await model.undelete(login) }
                } label: {
                    Label("Bring Back", systemImage: "arrow.uturn.backward")
                }
                .help("Bring it back for everyone who had it")
                Button {
                    confirmingPurge = true
                } label: {
                    Label("Delete Now", systemImage: "trash")
                }
                .help("Delete it for good now")
            }
        }
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
                HStack(spacing: 10) {
                    Avatar(name: user.name, size: 28)
                        .opacity(user.removed ? 0.5 : 1)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(user.userId == model.identity?.userId ? "\(user.name) (you)" : user.name)
                            .lineLimit(1)
                        Text(status(of: user))
                            .font(.caption)
                            .foregroundStyle(user.approved ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
                    }
                }
                .padding(.vertical, 3)
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
    @State private var problem: String?

    private var isMe: Bool { user.userId == model.identity?.userId }

    /// Turns escrow on or off from the toggle, saying why if it can't.
    private func escrow(_ identity: Identity) -> Binding<Bool> {
        Binding(
            get: { identity.escrow },
            set: { on in
                Task {
                    do {
                        try await model.setEscrow(on)
                        problem = nil
                    } catch {
                        problem = describe(error)
                    }
                }
            })
    }

    private var header: some View {
        PageHeader(title: user.name, subtitle: isMe ? "You · \(status(of: user))" : status(of: user)) {
            Avatar(name: user.name, size: 52)
        }
    }

    var body: some View {
        Form {
            if isMe, let identity = model.identity {
                Section {
                    LabeledContent("Fingerprint") {
                        Text(identity.fingerprint)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    ActionRow(title: "Recovery Kit", button: "Show…") {
                        model.sheet = .recoveryKit(afterSetup: false)
                    }
                } header: {
                    header
                } footer: {
                    Text(user.approved
                        ? "If this Mac is lost, broken or wiped, your Recovery Kit brings your "
                            + "account back on a new one."
                        : "Read your fingerprint to the owner, in person or on a call, so they "
                            + "can approve you.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .multilineTextAlignment(.leading)
                }
                if identity.recovering {
                    Section {
                        Label("The owner has started a recovery for your account.",
                              systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                        ActionRow(
                            title: "If you didn't ask for one, cancel it.",
                            button: "Cancel Recovery", role: .destructive
                        ) {
                            Task {
                                do {
                                    try await model.cancelRecovery(for: identity.userId)
                                } catch {
                                    problem = describe(error)
                                }
                            }
                        }
                    }
                }
                if !identity.isOwner {
                    Section {
                        Toggle("Let the owner recover my own logins and folders", isOn: escrow(identity))
                        if let problem {
                            Text(problem)
                                .foregroundStyle(.red)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    } header: {
                        Text("If you lose everything")
                    } footer: {
                        Text("If you lose every device and your Recovery Kit, the owner can help "
                            + "you back in, and what's shared with you comes back. With this on, "
                            + "your own logins and the folders only you are in come back too, but "
                            + "the owner can open them at any time.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .multilineTextAlignment(.leading)
                    }
                }
                Section("Devices") {
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
                // Fetched here, where they're shown, rather than on every sync.
                .task { await model.reloadDevices() }
            } else if !user.approved {
                Section {
                    if model.isOwner {
                        ActionRow(title: "Their fingerprint", button: "Approve…") {
                            model.sheet = .approve(user)
                        }
                    } else {
                        Text("Waiting for the owner to approve them.")
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    header
                } footer: {
                    if model.isOwner {
                        Text("\(user.name) has joined. Ask them to read out the fingerprint "
                            + "their Keystead shows, in person or on a call, to prove the keys on "
                            + "the server are really theirs.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .multilineTextAlignment(.leading)
                    }
                }
            } else if user.removed {
                Section {
                    Text("Their devices no longer work, and nobody can share with them.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } header: {
                    header
                }
                PasswordsToChange(model: model, user: user)
            } else {
                Section {
                    ActionRow(
                        title: "Folders", button: "Share a Folder…",
                        disabled: !model.folders.contains { model.manages(folder: $0) }
                    ) {
                        model.sheet = .share(folder: nil, user: user)
                    }
                } header: {
                    header
                } footer: {
                    Text("Sharing a folder gives \(user.name) everything in it, now and later.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .multilineTextAlignment(.leading)
                }
                PasswordsToChange(model: model, user: user)
                if model.isOwner && !user.isOwner {
                    Section {
                        ActionRow(
                            title: user.recovering ? "A recovery is waiting for you" : "Recovery",
                            button: user.recovering ? "Continue…" : "Help Recover…"
                        ) {
                            model.sheet = .helpRecover(user)
                        }
                    } header: {
                        Text("If \(user.name) loses everything")
                    } footer: {
                        Text(user.escrow
                            ? "With new keys, what's shared with them comes back, and their own "
                                + "logins and folders too: they keep them in escrow with you."
                            : "With new keys, what's shared with them comes back. Their own "
                                + "logins and the folders only they're in don't: escrow is off.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .multilineTextAlignment(.leading)
                    }
                    Section {
                        ActionRow(
                            title: "Remove from the team", button: "Remove…", role: .destructive
                        ) {
                            model.sheet = .removeUser(user)
                        }
                    } footer: {
                        Text("Their devices stop working and they lose every folder and login, "
                            + "for example when they leave the company.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .multilineTextAlignment(.leading)
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
            Section {
                LabeledContent(entries.count == 1 ? "1 password to change" : "\(entries.count) passwords to change") {
                    HStack {
                        Button("Keep All…") { confirming = true }
                        Button("Show") { model.section = .toChange }
                    }
                }
                if let error {
                    Text(error)
                        .foregroundStyle(.red)
                }
            } footer: {
                Text("\(user.name) could see them until losing access \(day(entries[0].since)).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .multilineTextAlignment(.leading)
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
                HStack(spacing: 10) {
                    GroupTile(size: 28)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(group.name)
                            .lineLimit(1)
                        Text(summary(of: group))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                .padding(.vertical, 3)
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
    @State private var deleting = false
    @State private var busy = false
    @State private var error: String?

    private var memberCount: String {
        let count = group.members.count == 1 ? "1 person" : "\(group.members.count) people"
        if group.members.contains(where: { $0.isMe && $0.isManager }) { return "\(count) · you manage it" }
        return group.isMember ? "\(count) · you're in it" : count
    }

    var body: some View {
        Form {
            Section {
                ForEach(group.members) { member in
                    HStack(spacing: 10) {
                        Avatar(name: member.name, size: 24)
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
                PageHeader(title: group.name, subtitle: memberCount) {
                    GroupTile(size: 52)
                }
            } footer: {
                Text("Folders and logins shared with \(group.name) reach everyone in it, including "
                    + "people added later. Taking someone out gives it new keys."
                    + (group.canManage && !group.canAdd
                        ? " Only managers who are in the group can add people, as that hands them its key."
                        : ""))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .multilineTextAlignment(.leading)
            }
            if let error {
                Text(error)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
        .disabled(busy)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if busy {
                    ProgressView().controlSize(.small)
                }
                if group.canAdd {
                    Button {
                        model.sheet = .addToGroup(group)
                    } label: {
                        Label("Add Person", systemImage: "person.badge.plus")
                    }
                    .help("Add someone to \(group.name)")
                }
                Button {
                    model.sheet = .shareWithGroup(group)
                } label: {
                    Label("Share a Folder", systemImage: "folder.badge.plus")
                }
                .help("Share a folder with everyone in \(group.name)")
                .disabled(!model.folders.contains { model.manages(folder: $0) })
                if group.canManage || group.isMember {
                    Menu {
                        if group.canManage {
                            Button("Rename…") { model.sheet = .renameGroup(group) }
                        }
                        if group.isMember {
                            Button("Leave…") { leaving = true }
                        }
                        if group.canManage {
                            Divider()
                            Button("Delete Group…", role: .destructive) { deleting = true }
                        }
                    } label: {
                        Label("More", systemImage: "ellipsis.circle")
                    }
                    .help("Rename, Leave and Delete")
                }
            }
        }
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
        .confirmationDialog("Delete \u{201C}\(group.name)\u{201D}?", isPresented: $deleting) {
            Button("Delete Group", role: .destructive) {
                run { try await model.delete(group) }
            }
        } message: {
            Text("Everyone in it loses the folders and logins shared with it, unless they have "
                + "them another way, and those folders get new keys. The passwords they could "
                + "see go on To Change.")
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
            // On every page, not just yours under People: the owner could approve within
            // minutes.
            if model.identity?.recovering == true {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("The owner started a recovery of your account. If you didn't ask for "
                        + "one, cancel it: someone may be trying to get new keys for it.")
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Cancel Recovery", role: .destructive) {
                        Task { await model.cancelOwnRecovery() }
                    }
                }
                .notice()
            }
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
    if user.recovering { return "Recovering" }
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

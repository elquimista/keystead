import SwiftUI

/// The unlocked vault: folders, people and groups on the left, then a list, then the details.
struct VaultView: View {
    @Bindable var model: AppModel
    @State private var search = ""

    /// What To Change and Password Health are for, under "No Login Selected" while their
    /// list has logins. Each row already says what's wrong with its login.
    private var sectionAbout: String? {
        switch model.section {
        case .toChange where !model.toChangeByItem.isEmpty:
            "People who lost access may still know these passwords. Change each one at its "
                + "website, then save the new one here."
        case .health where !model.healthByItem.isEmpty:
            "These logins you can change have a password that's easy to guess, used for "
                + "other logins too, or unchanged for over a year. Change each one at its "
                + "website, then save the new one here."
                + (model.health?.agesKnown == false
                    ? " Old ones show once your server is on 0.13.0." : "")
        default: nil
        }
    }

    var body: some View {
        NavigationSplitView {
            Sidebar(model: model, selection: $model.section)
                .navigationSplitViewColumnWidth(min: 180, ideal: 210)
        } content: {
            Group {
                switch model.section ?? .allLogins {
                case .people:
                    PeopleList(model: model)
                case .groups:
                    GroupList(model: model, selection: $model.selectedGroupID)
                case .recentlyDeleted:
                    DeletedList(model: model, selection: $model.selectedDeletedID)
                case let section:
                    LoginList(model: model, section: section, search: $search, selection: $model.selectedItemID)
                }
            }
            // Room for a folder's name and its two buttons, so they stay on the list's side
            // of the toolbar like every other section's.
            .navigationSplitViewColumnWidth(min: 260, ideal: 260)
        } detail: {
            if model.section == .people {
                if let user = model.users.first(where: { $0.id == model.selectedUserID }) {
                    PersonDetail(model: model, user: user)
                } else if let invite = model.invites.first(where: { $0.id == model.selectedInviteID }) {
                    InviteDetail(model: model, invite: invite)
                        .id(invite.id)
                } else {
                    NothingSelected {
                        Text("Select a person")
                            .foregroundStyle(.secondary)
                    }
                    .toolbar { PersonActions(model: model, user: nil) }
                }
            } else if model.section == .recentlyDeleted {
                if let login = model.recentlyDeleted.first(where: { $0.id == model.selectedDeletedID }) {
                    DeletedDetail(model: model, login: login)
                        .id(login.id)
                } else {
                    NothingSelected {
                        Text(model.recentlyDeleted.isEmpty ? "" : "Select a login")
                            .foregroundStyle(.secondary)
                    }
                    .toolbar { DeletedActions(login: nil) }
                }
            } else if model.section == .groups {
                if let group = model.groups.first(where: { $0.id == model.selectedGroupID }) {
                    GroupDetail(model: model, group: group)
                        .id(group.id)
                } else {
                    NothingSelected {
                        Text(model.groups.isEmpty ? "" : "Select a group")
                            .foregroundStyle(.secondary)
                    }
                    .toolbar { GroupActions(model: model, group: nil) }
                }
            } else if let item = model.items.first(where: { $0.id == model.selectedItemID }) {
                LoginDetail(model: model, item: item)
                    .id(item.id)
            } else {
                NothingSelected {
                    ContentUnavailableView {
                        Label("No Login Selected", systemImage: "key.horizontal")
                    } description: {
                        if let about = sectionAbout {
                            Text(about)
                        }
                    }
                }
                .toolbar { LoginActions(model: model, item: nil) }
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
        .onChange(of: model.section) {
            if model.section == .health {
                Task {
                    await model.checkHealth()
                    // Its list comes from the check; with none yet, nothing to compare.
                    if model.health != nil { keepSelectionIfListed() }
                }
            } else if model.section == .recentlyDeleted {
                // Fetched when shown, rather than with every sync.
                Task { await model.reloadDeleted() }
            } else {
                keepSelectionIfListed()
            }
        }
    }
}

extension VaultView {
    /// After switching sections, a login stays selected only if the list now shown has it,
    /// so the details never show a login the list doesn't. One that drops out of a list
    /// while you're on it, because you just changed it, stays.
    fileprivate func keepSelectionIfListed() {
        guard let id = model.selectedItemID else { return }
        let section = model.section ?? .allLogins
        switch section {
        case .people, .groups, .recentlyDeleted: return
        default: break
        }
        if !model.items(matching: search, in: section).contains(where: { $0.id == id }) {
            model.selectedItemID = nil
        }
    }
}

/// The detail pane with nothing picked: its message over an empty page like the ones shown
/// when something is, so the pane and its toolbar look the same either way. Over a column
/// with no scrolling page, macOS gives the toolbar a background and a line.
private struct NothingSelected<Message: View>: View {
    @ViewBuilder let message: Message

    var body: some View {
        Form {}
            .formStyle(.grouped)
            .overlay { message }
    }
}

private struct Sidebar: View {
    let model: AppModel
    @Binding var selection: AppModel.Section?

    var body: some View {
        List(selection: $selection) {
            // Every row always, empty or not, so none moves and each keeps its place (and
            // its ⌘ number); an empty one says so in its list.
            Label("All Logins", systemImage: "key")
                .tag(AppModel.Section.allLogins)
            Label("Shared with Me", systemImage: "shared.with.you")
                .tag(AppModel.Section.sharedWithMe)
            Label("To Change", systemImage: "exclamationmark.triangle")
                .badge(model.toChangeCount)
                .tag(AppModel.Section.toChange)
                .help("Passwords that people who lost access may still know")
            Label("Recently Deleted", systemImage: "trash")
                .tag(AppModel.Section.recentlyDeleted)
                .help("Logins deleted in the last 30 days, which can be brought back")
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
                // Circled, so both fit the sidebar's icon column: person.2 and person.3 are wider
                // than it and crowd their text.
                Label("People", systemImage: "person.circle")
                    .badge(model.isOwner ? model.users.filter { !$0.approved }.count : 0)
                    .tag(AppModel.Section.people)
                Label("Groups", systemImage: "person.2.circle")
                    .tag(AppModel.Section.groups)
            }
        }
        .safeAreaInset(edge: .bottom) {
            if let identity = model.identity {
                HStack(spacing: 8) {
                    // You, as People shows you; a click opens your page there. The server is
                    // in the tooltip and Settings › Account, not cut off here.
                    Button {
                        model.section = .people
                        model.selectedUserID = identity.userId
                    } label: {
                        HStack(spacing: 8) {
                            Avatar(name: identity.name, size: 28)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(identity.name)
                                    .lineLimit(1)
                                Text(identity.isOwner ? "Owner" : "Member")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                            Spacer(minLength: 0)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help("Signed in to \(host(identity.server)). Show your page in People")
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
                            Image(systemName: "arrow.clockwise")
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
        // Its own name: the sidebar shows where it sits, and the whole path leaves no room
        // for the folder's buttons.
        case .folder(let folder):
            folder.components(separatedBy: FolderNode.separator).last ?? folder
        case .sharedWithMe: "Shared with Me"
        case .toChange: "To Change"
        case .health: "Password Health"
        case .allLogins, .people, .groups, .recentlyDeleted: "All Logins"
        }
    }

    var body: some View {
        let items = model.items(matching: search, in: section)
        // Rows only, like every other list; what a section is for shows in the login pane
        // until one is picked. The list stays when it's empty, under the empty state: a
        // column without one gets a toolbar background and a line the others don't have.
        List(selection: $selection) {
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
        .overlay {
            if items.isEmpty {
                emptyState
            }
        }
        .navigationTitle(title)
        .searchable(text: $search, prompt: "Search logins")
        .toolbar {
            // Always there, so the toolbar keeps one layout in every section; greyed out
            // where a new login wouldn't show up in the list (Password Health, To Change,
            // Shared with Me) or the folder is view only.
            ToolbarItem {
                let addsHere = section == .allLogins || folder != nil
                Button {
                    model.sheet = .addLogin(folder: folder)
                } label: {
                    Label("New Login", systemImage: "plus")
                }
                .help(addsHere ? "Add a login" : "New logins go in All Logins or a folder")
                .disabled(!addsHere || folder.map { model.folderRoles[$0] == .view } ?? false)
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

    /// What Password Health checked, when it found nothing.
    private static func checked(_ count: UInt32) -> String {
        switch count {
        case 0: "You have no logins you can change yet."
        case 1: "Checked the login you can change: its password isn't weak, reused or old."
        default:
            "Checked the \(count) logins you can change: none has a weak, reused or old "
                + "password."
        }
    }

    @ViewBuilder
    private var emptyState: some View {
        if !search.trimmed.isEmpty {
            ContentUnavailableView.search(text: search)
        // Titles short enough for one line in the list's 260 points.
        } else if section == .toChange {
            ContentUnavailableView(
                "All clear", systemImage: "checkmark.shield",
                description: Text("When someone loses access, the passwords they could see show "
                    + "up here."))
        } else if section == .health {
            if let health = model.health {
                ContentUnavailableView(
                    "All healthy", systemImage: "checkmark.shield",
                    description: Text(Self.checked(health.checked)))
            } else {
                ProgressView("Checking passwords…")
            }
        } else if section == .sharedWithMe {
            ContentUnavailableView(
                "Nothing shared", systemImage: "shared.with.you",
                description: Text("Logins people share with you one by one show up here."))
        } else if model.items.isEmpty && model.folders.isEmpty && !model.hasSynced {
            // On a new Mac, until the first sync brings them.
            ProgressView("Getting your logins\u{2026}")
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
    @State private var hiding: Task<Void, Never>?
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
                    RevealButton(what: "password", shown: showsPassword, emphasized: hovering) {
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
                        if let url = webURL(item.url) {
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
                    RevealButton(what: "notes", shown: showsNotes, emphasized: hovering) {
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
        .toolbar { LoginActions(model: model, item: item) }
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
            hideLater()
        } catch let failure {
            error = describe(failure)
        }
    }

    /// A password or notes shown stay up for a minute after the last one was shown, then
    /// hide, and what was decrypted for them goes.
    private func hideLater() {
        hiding?.cancel()
        hiding = Task {
            try? await Task.sleep(for: .seconds(60))
            guard !Task.isCancelled else { return }
            showsPassword = false
            showsNotes = false
            details = nil
        }
    }
}

/// A login's buttons in the toolbar: Edit, Share (or Access) and More. With no login
/// selected they're there all the same, greyed out, so the toolbar keeps one layout and
/// the list's New Login button stays put.
private struct LoginActions: ToolbarContent {
    let model: AppModel
    let item: ItemSummary?

    /// Shares it, rather than only seeing who can open it. With none selected, Share.
    private var manages: Bool { (item?.role ?? .manage) == .manage }
    private var canEdit: Bool { item.map { $0.role != .view } ?? false }

    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            Button {
                if let item { model.sheet = .editLogin(item) }
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            .help("Edit this login")
            .disabled(!canEdit)
            Button {
                if let item { model.sheet = .shareLogin(item) }
            } label: {
                Label(
                    manages ? "Share" : "Access",
                    systemImage: manages ? "person.crop.circle.badge.plus" : "person.2")
            }
            .help(manages ? "Share this login" : "Who can open this login")
            .disabled(item == nil)
            Menu {
                if let item {
                    Button("History…") { model.sheet = .history(item) }
                        .disabled(item.role == .view)
                    Button("Move To…") { model.sheet = .moveLogin(item) }
                        .disabled(!model.canMove(item))
                    Divider()
                    Button("Delete…", role: .destructive) { model.sheet = .deleteLogin(item) }
                        .disabled(item.role == .view)
                }
            } label: {
                Label("More", systemImage: "ellipsis.circle")
            }
            .help("History, Move To and Delete")
            .disabled(item == nil)
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

/// One field of a login: its label and value and a button that copies it, which turns into
/// a check mark for a moment. Clicking the value copies it too, unless it's a link.
/// `accessory` adds a button of its own (showing the field) between them, told when the
/// pointer is over the row so it can stand out with the copy button. Each row ends flush
/// right with whatever buttons it has.
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
                        FieldIcon(copied ? "checkmark" : "doc.on.doc", emphasized: hovering || copied)
                    }
                    .buttonStyle(.borderless)
                    .help(copyHelp)
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

/// Shows or hides a field.
struct RevealButton: View {
    let what: String
    let shown: Bool
    /// Drawn in full, as while the pointer is over its row, rather than quietly.
    var emphasized = false
    let toggle: () async -> Void

    var body: some View {
        Button {
            Task { await toggle() }
        } label: {
            FieldIcon(shown ? "eye.slash" : "eye", emphasized: emphasized || shown)
        }
        .buttonStyle(.borderless)
        .help(shown ? "Hide \(what)" : "Show \(what)")
    }
}

/// A field button's symbol: always there so it's clear what can be copied or shown, quiet
/// until it matters, and as wide whichever symbol it shows so the value beside it stays put.
private struct FieldIcon: View {
    let name: String
    let emphasized: Bool

    init(_ name: String, emphasized: Bool) {
        self.name = name
        self.emphasized = emphasized
    }

    var body: some View {
        Image(systemName: name)
            .contentTransition(.symbolEffect(.replace))
            .foregroundStyle(emphasized ? AnyShapeStyle(.primary) : AnyShapeStyle(.secondary))
            .frame(width: 18)
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
    @State private var confirmingPurgeAll = false
    @State private var busy = false
    @State private var search = ""

    private var shown: [DeletedLogin] {
        model.recentlyDeleted.filter {
            matches(search, $0.name, $0.username, $0.folder ?? "", $0.deletedBy)
        }
    }

    var body: some View {
        List(shown, selection: $selection) { login in
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
        .overlay {
            if !search.trimmed.isEmpty && shown.isEmpty {
                ContentUnavailableView.search(text: search)
            } else if model.recentlyDeleted.isEmpty {
                if model.keepsDeleted == false {
                    ContentUnavailableView(
                        "Server too old", systemImage: "trash",
                        description: Text("Your server keeps no deleted logins. Once it's on "
                            + "0.9.0 or later, logins deleted from then on stay here for 30 "
                            + "days, ready to bring back."))
                } else {
                    ContentUnavailableView(
                        "Nothing deleted", systemImage: "trash",
                        description: Text("Logins deleted in the last 30 days show up here, "
                            + "ready to bring back."))
                }
            }
        }
        .navigationTitle("Recently Deleted")
        .searchable(text: $search, prompt: "Search deleted logins")
        .toolbar {
            ToolbarItem {
                Button {
                    confirmingPurgeAll = true
                } label: {
                    Label("Delete All\u{2026}", systemImage: "xmark.bin")
                }
                .help("Delete everything here for good now")
                .disabled(busy || model.recentlyDeleted.isEmpty)
            }
        }
        .confirmationDialog(purgeAllQuestion, isPresented: $confirmingPurgeAll) {
            Button(model.recentlyDeleted.count == 1 ? "Delete for Good" : "Delete All for Good",
                   role: .destructive) {
                busy = true
                Task {
                    await model.purgeAll()
                    busy = false
                }
            }
        } message: {
            Text(model.recentlyDeleted.count == 1
                ? "It can't be brought back afterwards, by you or anyone it was shared with."
                : "They can't be brought back afterwards, by you or anyone they were shared with.")
        }
    }

    private var purgeAllQuestion: String {
        let logins = model.recentlyDeleted
        return logins.count == 1
            ? "Delete \u{201C}\(logins[0].name)\u{201D} for good?"
            : "Delete all \(logins.count) logins for good?"
    }
}

/// A deleted login's buttons in the toolbar: Bring Back and Delete Now. With none selected
/// they're there all the same, greyed out, so the toolbar keeps one layout.
private struct DeletedActions: ToolbarContent {
    let login: DeletedLogin?
    var bringBack: () -> Void = {}
    var deleteNow: () -> Void = {}

    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            Button(action: bringBack) {
                Label("Bring Back", systemImage: "arrow.uturn.backward")
            }
            .help("Bring it back for everyone who had it")
            .disabled(login == nil)
            Button(action: deleteNow) {
                Label("Delete Now", systemImage: "trash")
            }
            .help("Delete it for good now")
            .disabled(login == nil)
        }
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
            DeletedActions(
                login: login,
                bringBack: { run { note = try await model.undelete(login) } },
                deleteNow: { confirmingPurge = true })
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

/// A row under People: someone on the team, or an invite nobody has used yet.
private enum PeopleSelection: Hashable {
    case user(User.ID)
    case invite(PendingInvitation.ID)
}

private struct PeopleList: View {
    let model: AppModel
    @State private var search = ""

    private var shown: [User] {
        model.users.filter { matches(search, $0.name, status(of: $0)) }
    }

    private var shownInvites: [PendingInvitation] {
        model.invites.filter { matches(search, $0.name, "Invited") }
    }

    private var selection: Binding<PeopleSelection?> {
        Binding(
            get: {
                model.selectedUserID.map(PeopleSelection.user)
                    ?? model.selectedInviteID.map(PeopleSelection.invite)
            },
            set: { row in
                switch row {
                case .user(let id):
                    model.selectedUserID = id
                    model.selectedInviteID = nil
                case .invite(let id):
                    model.selectedUserID = nil
                    model.selectedInviteID = id
                case nil:
                    model.selectedUserID = nil
                    model.selectedInviteID = nil
                }
            })
    }

    var body: some View {
        List(selection: selection) {
            ForEach(shown) { user in
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
                .tag(PeopleSelection.user(user.id))
            }
            ForEach(shownInvites) { invite in
                HStack(spacing: 10) {
                    Avatar(name: invite.name, size: 28)
                        .opacity(0.5)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(invite.name)
                            .lineLimit(1)
                        Text("Invited · hasn't joined yet")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 3)
                .tag(PeopleSelection.invite(invite.id))
            }
        }
        // Over the list, like an empty login list's: a bottom inset with wrapping text
        // breaks the split view's layout, blanking the sidebar too.
        .overlay {
            if !search.trimmed.isEmpty && shown.isEmpty && shownInvites.isEmpty {
                ContentUnavailableView.search(text: search)
            } else if model.isOwner && model.users.count <= 1 && model.invites.isEmpty
                && search.trimmed.isEmpty
            {
                ContentUnavailableView {
                    Label("Just you so far", systemImage: "person.circle")
                } description: {
                    Text("Invite your team; they'll show up here once they've joined.")
                } actions: {
                    Button("Invite Someone…") { model.sheet = .invite }
                }
            }
        }
        .navigationTitle("People")
        .searchable(text: $search, prompt: "Search people")
        .toolbar {
            ToolbarItem {
                Button {
                    model.sheet = .invite
                } label: {
                    Label("Invite", systemImage: "person.badge.plus")
                }
                .help(model.isOwner ? "Invite someone to your team" : "Only the owner invites people")
                .disabled(!model.isOwner)
            }
        }
    }
}

/// A person's buttons in the toolbar: Approve, Share a Folder and More. Always there,
/// greyed out where they don't apply or with nobody selected, like a login's and a group's.
private struct PersonActions: ToolbarContent {
    let model: AppModel
    let user: User?

    private var isMe: Bool { user != nil && user?.userId == model.identity?.userId }
    /// Approved and still on the team.
    private var active: Bool { user.map { $0.approved && !$0.removed } ?? false }
    /// Joined, and waiting for the owner to check their fingerprint.
    private var canApprove: Bool { model.isOwner && (user.map { !$0.approved && !$0.removed } ?? false) }
    private var canShare: Bool {
        active && !isMe && model.folders.contains { model.manages(folder: $0) }
    }
    /// Helping someone recover and removing them are the owner's to do, for anyone else.
    private var canManage: Bool { model.isOwner && active && !(user?.isOwner ?? true) }

    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            Button {
                if let user { model.sheet = .approve(user) }
            } label: {
                Label("Approve", systemImage: "checkmark.seal")
            }
            .help(canApprove
                ? "Approve \(user?.name ?? "them") once they've read out their fingerprint"
                : "Approve someone waiting to join; only the owner can")
            .disabled(!canApprove)
            Button {
                if let user { model.sheet = .share(folder: nil, user: user) }
            } label: {
                Label("Share a Folder", systemImage: "folder.badge.plus")
            }
            .help(user.map { "Share a folder with \($0.name)" } ?? "Share a folder with someone")
            .disabled(!canShare)
            Menu {
                if let user {
                    Button(user.recovering ? "Continue Recovery…" : "Help Recover…") {
                        model.sheet = .helpRecover(user)
                    }
                    Divider()
                    Button("Remove from Team…", role: .destructive) {
                        model.sheet = .removeUser(user)
                    }
                }
            } label: {
                Label("More", systemImage: "ellipsis.circle")
            }
            .help("Help Recover and Remove from Team")
            .disabled(!canManage)
        }
    }
}

/// An invite nobody has used yet: when it stops working, and the button to revoke it.
private struct InviteDetail: View {
    let model: AppModel
    let invite: PendingInvitation
    @State private var confirming = false
    @State private var problem: String?

    var body: some View {
        Form {
            Section {
                LabeledContent("Invited", value: date(invite.createdAt))
                LabeledContent("Works until", value: date(invite.expiresAt))
                ActionRow(title: "Stop this invite working", button: "Revoke Invite…", role: .destructive) {
                    confirming = true
                }
                if let problem {
                    Text(problem)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } header: {
                PageHeader(title: invite.name, subtitle: "Invited · hasn't joined yet") {
                    Avatar(name: invite.name, size: 52)
                        .opacity(0.5)
                }
            } footer: {
                Text("\(invite.name) joins by pasting the invite you sent into Keystead. Keystead "
                    + "doesn't keep the invite itself: if it's lost or went to the wrong person, "
                    + "revoke it and invite them again.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .multilineTextAlignment(.leading)
            }
        }
        .formStyle(.grouped)
        .toolbar { PersonActions(model: model, user: nil) }
        .confirmationDialog("Revoke the invite for \(invite.name)?", isPresented: $confirming) {
            Button("Revoke Invite", role: .destructive) {
                Task {
                    do {
                        try await model.revokeInvite(invite)
                    } catch {
                        problem = describe(error)
                    }
                }
            }
        } message: {
            Text("The invite you sent stops working at once. You can invite them again at any time.")
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
                        : "The owner's Keystead approves you the next time it syncs, if you "
                            + "joined with an invite from Keystead 0.18.0 or later. If not, read "
                            + "them your fingerprint, in person or on a call.")
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
                    if model.isOwner && user.inviteMismatch {
                        Label("The keys on the server for \(user.name) don't match the invite you "
                            + "sent them. The server may have swapped them.",
                              systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
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
                        Text((user.inviteMismatch
                            ? "Approve \(user.name) only if the fingerprint they read out matches. "
                            : "\(user.name) has joined. ")
                            + "Ask them to read out the fingerprint their Keystead shows, in person "
                            + "or on a call, to prove the keys on the server are really theirs.")
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
                } header: {
                    header
                }
                PasswordsToChange(model: model, user: user)
                if model.isOwner && !user.isOwner {
                    Section {
                        if user.recovering {
                            ActionRow(title: "A recovery is waiting for you", button: "Continue…") {
                                model.sheet = .helpRecover(user)
                            }
                        } else {
                            LabeledContent("Escrow", value: user.escrow ? "On" : "Off")
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
                }
            }
        }
        .formStyle(.grouped)
        .toolbar { PersonActions(model: model, user: user) }
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
    @State private var search = ""

    private var shown: [GroupSummary] {
        model.groups.filter { matches(search, $0.name) }
    }

    var body: some View {
        List(selection: $selection) {
            ForEach(shown) { group in
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
        }
        // Over the list, as in People.
        .overlay {
            if !search.trimmed.isEmpty && shown.isEmpty {
                ContentUnavailableView.search(text: search)
            } else if model.groups.isEmpty {
                ContentUnavailableView {
                    Label("No groups yet", systemImage: "person.2.circle")
                } description: {
                    Text(model.isOwner
                        ? "Make a group for a team or a role, like Engineering or Support, then "
                            + "share folders and logins with everyone in it at once. People added "
                            + "to the group later get them too."
                        : "The owner makes them.")
                } actions: {
                    if model.isOwner {
                        Button("New Group…") { model.sheet = .newGroup }
                    }
                }
            }
        }
        .navigationTitle("Groups")
        .searchable(text: $search, prompt: "Search groups")
        .toolbar {
            ToolbarItem {
                Button {
                    model.sheet = .newGroup
                } label: {
                    Label("New Group", systemImage: "plus")
                }
                .help(model.isOwner ? "Make a group" : "Only the owner makes groups")
                .disabled(!model.isOwner)
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

/// A group's buttons in the toolbar: Add Person, Share a Folder and More. They're always
/// there, greyed out where they don't apply or with no group selected, so the toolbar keeps
/// one layout and the list's New Group button stays put.
private struct GroupActions: ToolbarContent {
    let model: AppModel
    let group: GroupSummary?
    var busy = false
    var leave: () -> Void = {}
    var delete: () -> Void = {}

    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            if busy {
                ProgressView().controlSize(.small)
            }
            Button {
                if let group { model.sheet = .addToGroup(group) }
            } label: {
                Label("Add Person", systemImage: "person.badge.plus")
            }
            .help(addHelp)
            .disabled(!(group?.canAdd ?? false))
            Button {
                if let group { model.sheet = .shareWithGroup(group) }
            } label: {
                Label("Share a Folder", systemImage: "folder.badge.plus")
            }
            .help(group.map { "Share a folder with everyone in \($0.name)" } ?? "Share a folder with a group")
            .disabled(group == nil || !model.folders.contains { model.manages(folder: $0) })
            Menu {
                if let group {
                    if group.canManage {
                        Button("Rename…") { model.sheet = .renameGroup(group) }
                    }
                    if group.isMember {
                        Button("Leave…", action: leave)
                    }
                    if group.canManage {
                        Divider()
                        Button("Delete Group…", role: .destructive, action: delete)
                    }
                }
            } label: {
                Label("More", systemImage: "ellipsis.circle")
            }
            .help("Rename, Leave and Delete")
            .disabled(!(group.map { $0.canManage || $0.isMember } ?? false))
        }
    }

    /// Adding someone hands them the group's key, so only a manager in the group can.
    private var addHelp: String {
        guard let group else { return "Add someone to a group" }
        return group.canAdd
            ? "Add someone to \(group.name)"
            : "Only someone in \(group.name) who manages it can add people"
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
            GroupActions(
                model: model, group: group, busy: busy,
                leave: { leaving = true }, delete: { deleting = true })
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
            if let identity = model.identity, !identity.privateConnection, !model.hidesPlainHTTPNotice {
                HStack(spacing: 8) {
                    Image(systemName: "lock.open.fill")
                        .foregroundStyle(.orange)
                    Text("\(host(identity.server)) is an http:// address: anyone on your network "
                        + "can read and change what \(appName) sends to it. "
                        + (identity.isOwner
                            ? "Give your server an https:// address."
                            : "Ask your team's owner to give the server an https:// address."))
                        .fixedSize(horizontal: false, vertical: true)
                    Button {
                        model.dismissPlainHTTPNotice()
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .buttonStyle(.borderless)
                    .help("Hide until you next unlock")
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
            if !model.approvedNames.isEmpty {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                    Text("Approved \(ListFormatter.localizedString(byJoining: model.approvedNames)), "
                        + "who joined with your " + (model.approvedNames.count == 1 ? "invite." : "invites."))
                        .fixedSize(horizontal: false, vertical: true)
                    Button {
                        model.dismissApproved()
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .buttonStyle(.borderless)
                }
                .notice()
            }
            if model.updates.showsNotice, let update = model.updates.available {
                HStack(spacing: 8) {
                    Image(systemName: "arrow.down.circle.fill")
                        .foregroundStyle(.tint)
                    Text("\(appName) \(update.version) is available.")
                    Button("Download\u{2026}") { model.updates.openPage() }
                        .help("Open its page, with the app and what changed")
                    Button {
                        model.updates.dismiss()
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .buttonStyle(.borderless)
                    .help("Hide until a newer version is out")
                }
                .notice()
            }
        }
        .frame(maxWidth: 520)
        .padding(.bottom, 16)
        .animation(.default, value: model.copiedName)
        .animation(.default, value: model.message)
        .animation(.default, value: model.approvedNames)
        .animation(.default, value: model.hidesPlainHTTPNotice)
        .animation(.default, value: model.updates.showsNotice)
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

/// Whether any of `fields` contains every word of a search, ignoring case and accents; an
/// empty search matches everything. For the short lists (people, groups, deleted logins);
/// logins have their own faster search in `AppModel`.
func matches(_ search: String, _ fields: String...) -> Bool {
    search.split(whereSeparator: \.isWhitespace).allSatisfy { word in
        fields.contains { $0.localizedStandardContains(word) }
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
    "on " + date(seconds)
}

/// "Nov 24, 2026" from seconds since 1970.
func date(_ seconds: Int64) -> String {
    Date(timeIntervalSince1970: TimeInterval(seconds)).formatted(date: .abbreviated, time: .omitted)
}

/// A login's website as a link to open, if it's a web address. Anyone who can edit a shared
/// login sets this text, so nothing else becomes a link: other schemes (smb, ssh,
/// shortcuts, an app's own) would open whatever handles them on this Mac.
func webURL(_ text: String) -> URL? {
    guard let url = URL(string: text.trimmed), let scheme = url.scheme?.lowercased(),
        scheme == "https" || scheme == "http", url.host() != nil
    else { return nil }
    return url
}

/// "keys.example.com" from "https://keys.example.com".
func host(_ server: String) -> String {
    guard let url = URL(string: server), let host = url.host() else { return server }
    if let port = url.port { return "\(host):\(port)" }
    return host
}

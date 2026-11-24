import SwiftUI

struct SheetContent: View {
    let sheet: AppModel.Sheet
    let model: AppModel

    var body: some View {
        switch sheet {
        case .addLogin(let folder):
            AddLoginSheet(model: model, folder: folder)
        case .editLogin(let item):
            EditLoginSheet(model: model, item: item)
        case .deleteLogin(let item):
            DeleteLoginSheet(model: model, item: item)
        case .shareLogin(let item):
            ShareLoginSheet(model: model, item: item)
        case .newFolder:
            NewFolderSheet(model: model)
        case .share(let folder, let user):
            ShareSheet(model: model, folder: folder, user: user)
        case .manageFolder(let folder):
            ManageFolderSheet(model: model, folder: folder)
        case .removeUser(let user):
            RemoveUserSheet(model: model, user: user)
        case .invite:
            InviteSheet(model: model)
        case .approve(let user):
            ApproveSheet(model: model, user: user)
        case .fingerprint:
            FingerprintSheet(model: model)
        case .recoveryKit(let afterSetup):
            RecoveryKitSheet(model: model, afterSetup: afterSetup)
        case .signOut:
            SignOutSheet(model: model) { model.sheet = .recoveryKit(afterSetup: false) }
        }
    }
}

/// What every sheet shares: a title, the content, an error line and the buttons. `action`
/// runs when the main button is pressed and returns whether the sheet should close.
private struct SheetScaffold<Content: View>: View {
    let title: String
    let actionTitle: String
    var canAct = true
    var showsCancel = true
    let action: () async throws -> Bool
    @ViewBuilder let content: Content

    @Environment(\.dismiss) private var dismiss
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(title)
                .font(.title3.weight(.semibold))
            content
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if busy {
                    ProgressView()
                        .controlSize(.small)
                }
                Spacer()
                if showsCancel {
                    Button("Cancel", role: .cancel) { dismiss() }
                        .keyboardShortcut(.cancelAction)
                }
                Button(actionTitle) {
                    Task { await run() }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!canAct || busy)
            }
        }
        .padding(20)
        .frame(width: 460)
    }

    private func run() async {
        busy = true
        error = nil
        do {
            if try await action() {
                dismiss()
            }
        } catch let failure {
            error = describe(failure)
        }
        busy = false
    }
}

/// A password field with show/hide and a generator.
private struct PasswordField: View {
    let title: String
    @Binding var password: String
    @State private var visible = false

    var body: some View {
        LabeledContent(title) {
            HStack {
                Group {
                    if visible {
                        TextField(title, text: $password)
                            .font(.system(.body, design: .monospaced))
                    } else {
                        SecureField(title, text: $password)
                    }
                }
                .labelsHidden()
                Button {
                    visible.toggle()
                } label: {
                    Image(systemName: visible ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .help(visible ? "Hide password" : "Show password")
                Button("Generate") {
                    password = generatePassword()
                    visible = true
                }
                .help("Make a random 24-character password")
            }
        }
    }
}

// MARK: - Logins

private struct AddLoginSheet: View {
    let model: AppModel
    /// None: the login is yours alone until you share it.
    @State var folder: String?
    @State private var name = ""
    @State private var username = ""
    @State private var url = ""
    @State private var password = ""
    @State private var notes = ""

    var body: some View {
        SheetScaffold(
            title: "New Login", actionTitle: "Add",
            canAct: !name.trimmed.isEmpty && !password.isEmpty
        ) {
            try await model.addLogin(
                folder: folder, name: name.trimmed, username: username.trimmed, url: url.trimmed,
                password: password, notes: notes)
            return true
        } content: {
            Form {
                Picker("Folder", selection: $folder) {
                    Text("None").tag(String?.none)
                    if !model.folders.isEmpty {
                        Divider()
                    }
                    ForEach(model.folders, id: \.self) { Text($0).tag(String?.some($0)) }
                }
                TextField("Name", text: $name, prompt: Text("AWS root account"))
                TextField("Username", text: $username, prompt: Text("Optional"))
                TextField("Website", text: $url, prompt: Text("Optional, https://…"))
                PasswordField(title: "Password", password: $password)
                NotesField(notes: $notes)
            }
            Text(folder.map { "Everyone \u{201C}\($0)\u{201D} is shared with will see this login." }
                ?? "Only you can see this login until you share it.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

/// Notes on a login: a few lines, kept secret like the password.
private struct NotesField: View {
    @Binding var notes: String

    var body: some View {
        TextField("Notes", text: $notes, prompt: Text("Optional"), axis: .vertical)
            .lineLimit(3...8)
    }
}

/// Changes any of a login's fields. Its folder and who can open it stay as they are.
private struct EditLoginSheet: View {
    let model: AppModel
    let item: ItemSummary
    @State private var name: String
    @State private var username: String
    @State private var url: String
    @State private var password = ""
    @State private var notes = ""
    /// The password and notes as they were, once decrypted; until then there's nothing to
    /// edit or save.
    @State private var original: LoginDetails?
    @State private var loadError: String?
    /// Set when someone else changed it first; the sheet then only offers to close.
    @State private var conflict: String?

    init(model: AppModel, item: ItemSummary) {
        self.model = model
        self.item = item
        _name = State(initialValue: item.name)
        _username = State(initialValue: item.username)
        _url = State(initialValue: item.url)
    }

    private var changed: Bool {
        name.trimmed != item.name || username.trimmed != item.username || url.trimmed != item.url
            || password != original?.password || notes != original?.notes
    }

    var body: some View {
        SheetScaffold(
            title: "Edit \u{201C}\(item.name)\u{201D}",
            actionTitle: conflict == nil ? "Save" : "Close",
            canAct: conflict != nil
                || (original != nil && changed && !name.trimmed.isEmpty && !password.isEmpty),
            showsCancel: conflict == nil
        ) {
            if conflict != nil { return true }
            conflict = try await model.update(
                item, name: name.trimmed, username: username.trimmed, url: url.trimmed,
                password: password, notes: notes)
            return conflict == nil
        } content: {
            if let conflict {
                Text(conflict)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let loadError {
                Label(loadError, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
            } else if original == nil {
                ProgressView()
                    .frame(maxWidth: .infinity)
            } else {
                Form {
                    LabeledContent("Folder", value: item.folder ?? "None")
                    TextField("Name", text: $name)
                    TextField("Username", text: $username, prompt: Text("Optional"))
                    TextField("Website", text: $url, prompt: Text("Optional, https://…"))
                    PasswordField(title: "Password", password: $password)
                    NotesField(notes: $notes)
                }
                if password != original?.password {
                    Text("Change it on the website or service too, if you haven't already.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .task {
            do {
                let details = try await model.details(of: item)
                password = details.password
                notes = details.notes
                original = details
            } catch {
                loadError = describe(error)
            }
        }
    }
}

/// Asks before deleting a login, and says who loses it.
private struct DeleteLoginSheet: View {
    let model: AppModel
    let item: ItemSummary
    @Environment(\.dismiss) private var dismiss
    @State private var busy = false
    @State private var note: String?

    /// Who loses the login, and that it's for good, in a sentence.
    private var consequence: String {
        let people = ListFormatter.localizedString(byJoining: item.sharedWith)
        if let folder = item.folder {
            let who = item.sharedWith.isEmpty
                ? "everyone in \u{201C}\(folder)\u{201D}"
                : "everyone in \u{201C}\(folder)\u{201D} and for \(people)"
            return "It's deleted for \(who), and can't be brought back."
        }
        if item.sharedWithMe {
            let others = ([item.owner].compactMap { $0 } + item.sharedWith)
            let who = others.isEmpty
                ? "everyone it's shared with"
                : ListFormatter.localizedString(byJoining: others)
            return "It's deleted for \(who) as well as for you, and can't be brought back."
        }
        if item.sharedWith.isEmpty {
            return "Only you have this login. Once deleted, it can't be brought back."
        }
        return "It's deleted for you and for \(people), and can't be brought back."
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Delete \u{201C}\(item.name)\u{201D}?")
                .font(.title3.weight(.semibold))
            if let note {
                Text(note)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button("Close") { dismiss() }
                        .keyboardShortcut(.defaultAction)
                }
            } else {
                Text(consequence)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    if busy {
                        ProgressView().controlSize(.small)
                    }
                    // Return cancels; deleting takes a deliberate click.
                    Button("Cancel") { dismiss() }
                        .keyboardShortcut(.defaultAction)
                    Button("Delete", role: .destructive) {
                        Task { await delete() }
                    }
                    .disabled(busy)
                }
            }
        }
        .padding(20)
        .frame(width: 460)
    }

    private func delete() async {
        busy = true
        do {
            note = try await model.delete(item)
            if note == nil { dismiss() }
        } catch {
            note = describe(error)
        }
        busy = false
    }
}

/// Shares one login with an approved person, and shows who already has it directly.
private struct ShareLoginSheet: View {
    let model: AppModel
    let item: ItemSummary
    @State private var userId: Int64
    @State private var role: Role = .edit
    @State private var people: [Person] = []
    @State private var problem: String?

    init(model: AppModel, item: ItemSummary) {
        self.model = model
        self.item = item
        _userId = State(initialValue: Self.candidates(for: item, in: model).first?.userId ?? 0)
    }

    /// Approved people other than you who don't have this login directly yet.
    private static func candidates(for item: ItemSummary, in model: AppModel) -> [User] {
        model.users.filter { user in
            user.approved && !user.removed && user.userId != model.identity?.userId
                && user.name != item.owner && !item.sharedWith.contains(user.name)
        }
    }

    private var candidates: [User] { Self.candidates(for: item, in: model) }
    private var recipient: User? { candidates.first { $0.userId == userId } }
    private var manages: Bool { item.role == .manage }

    var body: some View {
        SheetScaffold(
            title: manages ? "Share \u{201C}\(item.name)\u{201D}" : "Access to \u{201C}\(item.name)\u{201D}",
            actionTitle: manages ? "Share" : "Done",
            canAct: !manages || recipient != nil,
            showsCancel: manages
        ) {
            guard manages, let recipient else { return true }
            try await model.share(login: item, with: recipient, role: role)
            return true
        } content: {
            if manages {
                if candidates.isEmpty {
                    Text(model.users.contains { $0.approved && !$0.removed && $0.userId != model.identity?.userId }
                        ? "Everyone approved can already open this login."
                        : "There's no one approved to share with yet. "
                            + (model.isOwner
                                ? "Invite people from People, then approve them once they've joined."
                                : "The owner approves people as they join."))
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Form {
                        Picker("With", selection: $userId) {
                            ForEach(candidates) { Text($0.name).tag($0.userId) }
                        }
                        Picker("Access", selection: $role) {
                            ForEach(Role.all, id: \.self) { Text($0.label).tag($0) }
                        }
                    }
                    if let recipient {
                        Text("\(recipient.name) will see this login"
                            + (item.folder.map { ", not the rest of \u{201C}\($0)\u{201D}" } ?? "")
                            + ".")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            } else {
                Text("Only people who manage this login can share it.")
                    .foregroundStyle(.secondary)
            }
            if !people.isEmpty {
                PeopleWithAccess(
                    title: "Has it directly", people: people, canManage: manages, canLeave: false,
                    isOwner: { $0.name == (item.owner ?? model.identity?.name) && $0.role == .manage && item.folder == nil },
                    setRole: { person, role in
                        try await model.setRole(role, for: person, on: item)
                        await reload()
                    },
                    remove: { person in
                        try await model.unshare(item, from: person)
                        await reload()
                    })
            }
            if let problem {
                Label(problem, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .task { await reload() }
    }

    private func reload() async {
        do {
            people = try await model.people(of: item)
            problem = nil
        } catch {
            problem = describe(error)
        }
    }
}

/// A list of people with access and their roles. Managers change roles and remove people
/// here; everyone else just reads it.
private struct PeopleWithAccess: View {
    let title: String
    let people: [Person]
    let canManage: Bool
    /// Whether people who don't manage can take themselves off, as members leave a folder.
    var canLeave = true
    /// Rows that can't be changed, like a login's owner.
    var isOwner: (Person) -> Bool = { _ in false }
    var setRole: (Person, Role) async throws -> Void
    var remove: (Person) async throws -> Void
    var removeTitle: (Person) -> String = { $0.isMe ? "Leave" : "Remove" }
    @State private var busy: Int64?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.headline)
            ForEach(people) { person in
                HStack {
                    Text(person.isMe ? "\(person.name) (you)" : person.name)
                    Spacer()
                    if isOwner(person) {
                        Text("Owner")
                            .foregroundStyle(.secondary)
                    } else if canManage {
                        Picker("", selection: Binding(
                            get: { person.role },
                            set: { role in run(person) { try await setRole(person, role) } }
                        )) {
                            ForEach(Role.all, id: \.self) { Text($0.label).tag($0) }
                        }
                        .labelsHidden()
                        .fixedSize()
                        Button(removeTitle(person)) { run(person) { try await remove(person) } }
                    } else {
                        Text(person.role.label)
                            .foregroundStyle(.secondary)
                        if person.isMe && canLeave {
                            Button(removeTitle(person)) { run(person) { try await remove(person) } }
                        }
                    }
                }
                .disabled(busy != nil)
            }
            if let error {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
    }

    private func run(_ person: Person, _ action: @escaping () async throws -> Void) {
        busy = person.userId
        Task {
            do {
                try await action()
                error = nil
            } catch let failure {
                error = describe(failure)
            }
            busy = nil
        }
    }
}

/// Who is in a folder, with their roles. Managers change roles and remove people; anyone
/// can leave. Removing someone gives the folder a new key.
private struct ManageFolderSheet: View {
    let model: AppModel
    let folder: String
    @Environment(\.dismiss) private var dismiss
    @State private var members: [Person] = []
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Access to \u{201C}\(folder)\u{201D}")
                .font(.title3.weight(.semibold))
            if !members.isEmpty {
                PeopleWithAccess(
                    title: "\(members.count) \(members.count == 1 ? "person" : "people")",
                    people: members, canManage: model.manages(folder: folder),
                    setRole: { person, role in
                        try await model.setRole(role, for: person, in: folder)
                        await reload()
                    },
                    remove: { person in
                        try await model.remove(person, from: folder)
                        if person.isMe { dismiss() } else { await reload() }
                    })
            } else if problem == nil {
                ProgressView().frame(maxWidth: .infinity)
            }
            Text(model.manages(folder: folder)
                ? "Viewers can open and copy, editors can also change logins, and managers can "
                    + "also share and remove people. Removing someone gives the folder a new key, "
                    + "so they can't read what's saved afterwards."
                : "Only the folder's managers change who has access.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let problem {
                Label(problem, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if model.manages(folder: folder) {
                    Button("Share…") { model.sheet = .share(folder: folder, user: nil) }
                }
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 480)
        .task { await reload() }
    }

    private func reload() async {
        do {
            members = try await model.members(of: folder)
            problem = nil
        } catch {
            problem = describe(error)
        }
    }
}

/// The owner removes someone from the team, after saying what that does.
private struct RemoveUserSheet: View {
    let model: AppModel
    let user: User
    @Environment(\.dismiss) private var dismiss
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Remove \(user.name) from the Team?")
                .font(.title3.weight(.semibold))
            Text("Their devices stop working right away, and they lose every folder and login. "
                + "Folders they were in get new keys, so they can't read what's saved afterwards.")
                .fixedSize(horizontal: false, vertical: true)
            Text("Passwords they've already seen can't be taken back. Change the important ones.")
                .fixedSize(horizontal: false, vertical: true)
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                if busy {
                    ProgressView().controlSize(.small)
                }
                // Return cancels; removing someone takes a deliberate click.
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                Button("Remove", role: .destructive) {
                    Task {
                        busy = true
                        do {
                            try await model.remove(user: user)
                            dismiss()
                        } catch let failure {
                            error = describe(failure)
                        }
                        busy = false
                    }
                }
                .disabled(busy)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}

// MARK: - Folders

private struct NewFolderSheet: View {
    let model: AppModel
    @State private var name = ""

    private var exists: Bool { model.folders.contains(name.trimmed) }

    var body: some View {
        SheetScaffold(title: "New Folder", actionTitle: "Create", canAct: !name.trimmed.isEmpty && !exists) {
            try await model.createFolder(named: name)
            return true
        } content: {
            Form {
                TextField("Name", text: $name, prompt: Text("Production"))
            }
            Text(exists
                ? "There's already a folder with that name."
                : "Only you can see a new folder until you share it.")
                .font(.caption)
                .foregroundStyle(exists ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
        }
    }
}

private struct ShareSheet: View {
    let model: AppModel
    @State private var folder: String
    @State private var userId: Int64
    @State private var role: Role = .edit

    init(model: AppModel, folder: String?, user: User?) {
        self.model = model
        _folder = State(initialValue: folder ?? Self.folders(in: model).first ?? "")
        _userId = State(initialValue: user?.userId ?? Self.candidates(in: model).first?.userId ?? 0)
    }

    /// Approved people other than you who are still on the team.
    private static func candidates(in model: AppModel) -> [User] {
        model.users.filter { $0.approved && !$0.removed && $0.userId != model.identity?.userId }
    }

    /// The folders you manage, which are the ones you can share.
    private static func folders(in model: AppModel) -> [String] {
        model.folders.filter { model.manages(folder: $0) }
    }

    private var recipient: User? { Self.candidates(in: model).first { $0.userId == userId } }

    var body: some View {
        SheetScaffold(title: "Share a Folder", actionTitle: "Share", canAct: recipient != nil && !folder.isEmpty) {
            guard let recipient else { return false }
            try await model.share(folder: folder, with: recipient, role: role)
            return true
        } content: {
            if Self.folders(in: model).isEmpty {
                Text("You don't manage any folders, so you can't share one. A folder's managers "
                    + "can share it with \(Self.candidates(in: model).first { $0.userId == userId }?.name ?? "people").")
                    .fixedSize(horizontal: false, vertical: true)
            } else if Self.candidates(in: model).isEmpty {
                Text("There's no one approved to share with yet. "
                    + (model.isOwner
                        ? "Invite people from People, then approve them once they've joined."
                        : "The owner approves people as they join."))
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Form {
                    Picker("Folder", selection: $folder) {
                        ForEach(Self.folders(in: model), id: \.self) { Text($0).tag($0) }
                    }
                    Picker("With", selection: $userId) {
                        ForEach(Self.candidates(in: model)) { Text($0.name).tag($0.userId) }
                    }
                    Picker("Access", selection: $role) {
                        ForEach(Role.all, id: \.self) { Text($0.label).tag($0) }
                    }
                }
                if let recipient {
                    Text("\(recipient.name) will see every login in \u{201C}\(folder)\u{201D}, "
                        + "including ones added later.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

// MARK: - People

private struct InviteSheet: View {
    let model: AppModel
    @State private var name = ""
    @State private var invitation: Invitation?

    var body: some View {
        SheetScaffold(
            title: invitation == nil ? "Invite Someone" : "Send \(name.trimmed) This Invite",
            actionTitle: invitation == nil ? "Create Invite" : "Done",
            canAct: invitation != nil || !name.trimmed.isEmpty,
            showsCancel: invitation == nil
        ) {
            if invitation != nil { return true }
            invitation = try await model.invite(name: name)
            return false
        } content: {
            if let invitation {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Send it to \(name.trimmed) directly, for example in a private message. "
                        + "It works once.")
                    Text(invitation.command)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                    Button {
                        model.copy(invitation.command)
                    } label: {
                        Label("Copy Invite", systemImage: "doc.on.doc")
                    }
                    Text("They paste it into Keystead's welcome screen. Once they've joined, they "
                        + "show up under People: approve them after they read you their fingerprint.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                Form {
                    TextField("Name", text: $name, prompt: Text("As your team will see them"))
                }
            }
        }
    }
}

private struct ApproveSheet: View {
    let model: AppModel
    let user: User
    @State private var fingerprint = ""

    var body: some View {
        SheetScaffold(
            title: "Approve \(user.name)", actionTitle: "Approve", canAct: !fingerprint.trimmed.isEmpty
        ) {
            try await model.approve(user, fingerprint: fingerprint)
            return true
        } content: {
            Text("Ask \(user.name) to read out the fingerprint their Keystead shows, in person or "
                + "on a call, not by message. Keystead checks it against the keys they joined with.")
                .fixedSize(horizontal: false, vertical: true)
            Form {
                TextField("Fingerprint", text: $fingerprint, prompt: Text("1a2b-3c4d-5e6f-7a8b-9c0d"))
                    .font(.system(.body, design: .monospaced))
            }
            Text("Once approved, \(user.name) can see the folders and logins you share with them.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

/// Asks before signing out, and says what it costs: coming back takes the Recovery Kit.
struct SignOutSheet: View {
    let model: AppModel
    /// Shows the Recovery Kit instead, wherever this sheet was opened.
    let showKit: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var busy = false

    /// Whether this Mac is the account's only device, as far as the device list shows.
    private var onlyDevice: Bool { !model.devices.contains { !$0.current } }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Sign Out of \(appName)?")
                .font(.title3.weight(.semibold))
            Text("This Mac forgets your account: your logins and the keys that open them. "
                + "Your team and the server keep everything else, and the server forgets this Mac.")
                .fixedSize(horizontal: false, vertical: true)
            Text("To use your account again, on this Mac or another, you'll need your Recovery Kit.")
                .fixedSize(horizontal: false, vertical: true)
            if model.isOwner && onlyDevice {
                Label("You're the owner, and this is your only device. Without your Recovery Kit, "
                    + "nobody could invite or approve people on "
                    + "\(host(model.identity?.server ?? "your server")) again.",
                      systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button("Show Recovery Kit…", action: showKit)
                Spacer()
                if busy {
                    ProgressView().controlSize(.small)
                }
                // Return cancels; signing out takes a deliberate click.
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                Button("Sign Out", role: .destructive) {
                    Task { await signOut() }
                }
                .disabled(busy)
            }
        }
        .padding(20)
        .frame(width: 460)
    }

    private func signOut() async {
        busy = true
        await model.signOut()
        busy = false
        dismiss()
    }
}

/// Shown right after joining.
private struct FingerprintSheet: View {
    let model: AppModel

    var body: some View {
        SheetScaffold(title: "One More Step", actionTitle: "Done", showsCancel: false) {
            true
        } content: {
            if let identity = model.identity {
                let owner = model.users.first(where: \.isOwner)?.name ?? "the owner"
                VStack(alignment: .leading, spacing: 12) {
                    Text("You've joined \(host(identity.server)). Now \(owner) needs to approve "
                        + "you. Read them this fingerprint, in person or on a call:")
                        .fixedSize(horizontal: false, vertical: true)
                    Text(identity.fingerprint)
                        .font(.system(.title2, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(12)
                        .frame(maxWidth: .infinity)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                    Text("Once they approve you, logins shared with you show up here. You can "
                        + "find your fingerprint again under People.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

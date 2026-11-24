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

/// Shares one login with an approved person.
private struct ShareLoginSheet: View {
    let model: AppModel
    let item: ItemSummary
    @State private var userId: Int64

    init(model: AppModel, item: ItemSummary) {
        self.model = model
        self.item = item
        _userId = State(initialValue: Self.candidates(for: item, in: model).first?.userId ?? 0)
    }

    /// Approved people other than you who don't have this login directly yet.
    private static func candidates(for item: ItemSummary, in model: AppModel) -> [User] {
        model.users.filter { user in
            user.approved && user.userId != model.identity?.userId && user.name != item.owner
                && !item.sharedWith.contains(user.name)
        }
    }

    private var candidates: [User] { Self.candidates(for: item, in: model) }
    private var recipient: User? { candidates.first { $0.userId == userId } }

    var body: some View {
        SheetScaffold(
            title: "Share \u{201C}\(item.name)\u{201D}", actionTitle: "Share", canAct: recipient != nil
        ) {
            guard let recipient else { return false }
            try await model.share(login: item, with: recipient)
            return true
        } content: {
            if candidates.isEmpty {
                Text(model.users.contains { $0.approved && $0.userId != model.identity?.userId }
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
                }
                if let recipient {
                    Text("\(recipient.name) will see this login"
                        + (item.folder.map { ", not the rest of \u{201C}\($0)\u{201D}" } ?? "")
                        + ". They can change it and share it too.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
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

    init(model: AppModel, folder: String?, user: User?) {
        self.model = model
        _folder = State(initialValue: folder ?? model.folders.first ?? "")
        _userId = State(initialValue: user?.userId ?? Self.candidates(in: model).first?.userId ?? 0)
    }

    /// Approved people other than you.
    private static func candidates(in model: AppModel) -> [User] {
        model.users.filter { $0.approved && $0.userId != model.identity?.userId }
    }

    private var recipient: User? { Self.candidates(in: model).first { $0.userId == userId } }

    var body: some View {
        SheetScaffold(title: "Share a Folder", actionTitle: "Share", canAct: recipient != nil && !folder.isEmpty) {
            guard let recipient else { return false }
            try await model.share(folder: folder, with: recipient)
            return true
        } content: {
            if Self.candidates(in: model).isEmpty {
                Text("There's no one approved to share with yet. "
                    + (model.isOwner
                        ? "Invite people from People, then approve them once they've joined."
                        : "The owner approves people as they join."))
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Form {
                    Picker("Folder", selection: $folder) {
                        ForEach(model.folders, id: \.self) { Text($0).tag($0) }
                    }
                    Picker("With", selection: $userId) {
                        ForEach(Self.candidates(in: model)) { Text($0.name).tag($0.userId) }
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

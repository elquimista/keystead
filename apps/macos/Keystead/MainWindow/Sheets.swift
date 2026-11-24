import SwiftUI

struct SheetContent: View {
    let sheet: AppModel.Sheet
    let model: AppModel

    var body: some View {
        switch sheet {
        case .addLogin(let folder):
            AddLoginSheet(model: model, folder: folder)
        case .changePassword(let item):
            ChangePasswordSheet(model: model, item: item)
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

    var body: some View {
        SheetScaffold(
            title: "New Login", actionTitle: "Add",
            canAct: !name.trimmed.isEmpty && !password.isEmpty
        ) {
            try await model.addLogin(
                folder: folder, name: name.trimmed, username: username.trimmed, url: url.trimmed,
                password: password)
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
            }
            Text(folder.map { "Everyone \u{201C}\($0)\u{201D} is shared with will see this login." }
                ?? "Only you can see this login until you share it.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

private struct ChangePasswordSheet: View {
    let model: AppModel
    let item: ItemSummary
    @State private var password = ""
    /// Set when someone else changed it first; the sheet then only offers to close.
    @State private var conflict: String?

    var body: some View {
        SheetScaffold(
            title: "Change Password for \u{201C}\(item.name)\u{201D}",
            actionTitle: conflict == nil ? "Save" : "Close",
            canAct: conflict != nil || !password.isEmpty,
            showsCancel: conflict == nil
        ) {
            if conflict != nil { return true }
            conflict = try await model.changePassword(of: item, to: password)
            return conflict == nil
        } content: {
            if let conflict {
                Text(conflict)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Form {
                    PasswordField(title: "New password", password: $password)
                }
                Text("Change it on the website or service too, if you haven't already.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
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

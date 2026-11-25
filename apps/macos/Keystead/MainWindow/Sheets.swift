import CoreImage
import SwiftUI
import UniformTypeIdentifiers

struct SheetContent: View {
    let sheet: AppModel.Sheet
    let model: AppModel

    var body: some View {
        switch sheet {
        case .addLogin(let folder):
            AddLoginSheet(model: model, folder: folder)
        case .editLogin(let item):
            EditLoginSheet(model: model, item: item)
        case .history(let item):
            HistorySheet(model: model, item: item)
        case .deleteLogin(let item):
            DeleteLoginSheet(model: model, item: item)
        case .shareLogin(let item):
            ShareLoginSheet(model: model, item: item)
        case .newFolder:
            NewFolderSheet(model: model)
        case .share(let folder, let user):
            ShareSheet(model: model, folder: folder, user: user)
        case .shareWithGroup(let group):
            ShareSheet(model: model, folder: nil, user: nil, group: group)
        case .manageFolder(let folder):
            ManageFolderSheet(model: model, folder: folder)
        case .removeUser(let user):
            RemoveUserSheet(model: model, user: user)
        case .addDevice:
            AddDeviceSheet(model: model)
        case .importLogins:
            ImportSheet(model: model)
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
        case .newGroup:
            NewGroupSheet(model: model)
        case .addToGroup(let group):
            AddToGroupSheet(model: model, group: group)
        case .renameGroup(let group):
            RenameGroupSheet(model: model, group: group)
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
    @State private var oneTimeCode = ""

    var body: some View {
        SheetScaffold(
            title: "New Login", actionTitle: "Add",
            canAct: !name.trimmed.isEmpty && !password.isEmpty
        ) {
            try await model.addLogin(
                folder: folder,
                LoginFields(
                    name: name.trimmed, username: username.trimmed, url: url.trimmed,
                    password: password, notes: notes, oneTimeCode: oneTimeCode.trimmed))
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
                OneTimeCodeField(setup: $oneTimeCode)
                NotesField(notes: $notes)
            }
            Text(folder.map { "Everyone \u{201C}\($0)\u{201D} is shared with will see this login." }
                ?? "Only you can see this login until you share it.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

/// Sets up one-time codes for a login: the otpauth:// link from a site's QR code (pasted, or
/// read from a screenshot of it) or the setup key the site shows for typing in. Kept secret
/// like the password.
private struct OneTimeCodeField: View {
    @Binding var setup: String
    @State private var visible = false
    /// Who the codes are for, once the setup checks out.
    @State private var label: String?
    @State private var problem: String?

    var body: some View {
        LabeledContent("One-time code") {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Group {
                        if visible {
                            TextField("One-time code", text: $setup, prompt: Text("Optional: setup key or link"))
                                .font(.system(.body, design: .monospaced))
                        } else {
                            SecureField("One-time code", text: $setup, prompt: Text("Optional: setup key or link"))
                        }
                    }
                    .labelsHidden()
                    Button {
                        visible.toggle()
                    } label: {
                        Image(systemName: visible ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.borderless)
                    .help(visible ? "Hide the setup key" : "Show the setup key")
                    Button("From QR Code…") { readQRCode() }
                        .help("Read the site's QR code from a screenshot or image")
                }
                if let problem {
                    Text(problem)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                } else if let label {
                    Text(label.isEmpty ? "Makes one-time codes." : "Makes one-time codes for \(label).")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .onChange(of: setup, initial: true) { check() }
    }

    private func check() {
        guard !setup.trimmed.isEmpty else {
            label = nil
            problem = nil
            return
        }
        do {
            label = try describeOneTimeCode(text: setup)
            problem = nil
        } catch {
            label = nil
            problem = describe(error)
        }
    }

    private func readQRCode() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.message = "Choose a screenshot or image of the site's QR code."
        guard panel.runModal() == .OK, let url = panel.url, let image = CIImage(contentsOf: url) else {
            return
        }
        let detector = CIDetector(
            ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        let messages = detector?.features(in: image).compactMap { ($0 as? CIQRCodeFeature)?.messageString } ?? []
        if let link = messages.first(where: { $0.lowercased().hasPrefix("otpauth://") }) {
            setup = link
        } else {
            label = nil
            problem = "There's no one-time code QR code in that image."
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
    @State private var oneTimeCode = ""
    /// The password, notes and one-time code setup as they were, once decrypted; until then
    /// there's nothing to edit or save.
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
            || oneTimeCode.trimmed != original?.oneTimeCode
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
                item,
                LoginFields(
                    name: name.trimmed, username: username.trimmed, url: url.trimmed,
                    password: password, notes: notes, oneTimeCode: oneTimeCode.trimmed))
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
                    OneTimeCodeField(setup: $oneTimeCode)
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
                oneTimeCode = details.oneTimeCode
                original = details
            } catch {
                loadError = describe(error)
            }
        }
    }
}

/// A login's earlier versions: who saved each, when, and what it changed, with their
/// passwords and a way to bring one back.
private struct HistorySheet: View {
    let model: AppModel
    let item: ItemSummary
    @State private var entries: [HistoryEntry]?
    @State private var loadError: String?
    /// Passwords shown so far, by version.
    @State private var shown: [UInt64: String] = [:]
    @State private var restoring: HistoryEntry?
    @State private var note: String?
    @State private var error: String?

    var body: some View {
        SheetScaffold(
            title: "History of \u{201C}\(item.name)\u{201D}", actionTitle: "Done", showsCancel: false
        ) {
            true
        } content: {
            if let loadError {
                Label(loadError, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let entries {
                List(entries, id: \.version) { entry in
                    row(entry)
                }
                .frame(minHeight: 280)
                Text("The server keeps the last 10 earlier versions. Bringing one back saves it "
                    + "as a new version; if its password differs, change it at the website too.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ProgressView()
                    .frame(maxWidth: .infinity)
            }
            if let note {
                Text(note)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error {
                Text(error)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(width: 540)
        .task { await load() }
        .confirmationDialog(
            "Bring back version \(restoring?.version ?? 0)?",
            isPresented: Binding(get: { restoring != nil }, set: { if !$0 { restoring = nil } })
        ) {
            Button("Bring Back") {
                if let entry = restoring { Task { await restore(entry) } }
            }
        } message: {
            Text("Its name, username, website, password, notes and one-time code become the "
                + "login's current ones, as a new version. Who has the login stays the same.")
        }
    }

    private func row(_ entry: HistoryEntry) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(entry.current ? "Version \(entry.version) · now" : "Version \(entry.version)")
                    .fontWeight(.semibold)
                Spacer()
                Text(saved(entry))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(changes(entry))
                .font(.caption)
                .foregroundStyle(.secondary)
            if entry.readable && !entry.current {
                HStack {
                    Text(shown[entry.version] ?? "••••••••••••")
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                    Button {
                        Task { await reveal(entry) }
                    } label: {
                        Image(systemName: shown[entry.version] == nil ? "eye" : "eye.slash")
                    }
                    .buttonStyle(.borderless)
                    .help(shown[entry.version] == nil ? "Show this version's password" : "Hide it")
                    Button {
                        Task { await model.copyHistoryPassword(of: item, version: entry.version) }
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                    .buttonStyle(.borderless)
                    .help("Copy this version's password (cleared after 30 seconds)")
                    Spacer()
                    Button("Bring Back…") { restoring = entry }
                }
            }
        }
        .padding(.vertical, 4)
    }

    /// "Nov 20, 2026 · Mo".
    private func saved(_ entry: HistoryEntry) -> String {
        let date = entry.savedAt.map {
            Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated, time: .shortened)
        }
        return [date, entry.author].compactMap { $0 }.joined(separator: " · ")
    }

    private func changes(_ entry: HistoryEntry) -> String {
        if !entry.readable {
            return "Can't be opened here: it's from before this login was shared with you."
        }
        if entry.changes == ["created"] { return "Created" }
        if entry.changes.isEmpty { return "No change to its fields, for example sharing it." }
        return "Changed the " + ListFormatter.localizedString(byJoining: entry.changes)
    }

    private func load() async {
        do {
            entries = try await model.history(of: item)
            loadError = nil
        } catch {
            loadError = describe(error)
        }
    }

    private func reveal(_ entry: HistoryEntry) async {
        if shown[entry.version] != nil {
            shown[entry.version] = nil
            return
        }
        do {
            shown[entry.version] = try await model.historyPassword(of: item, version: entry.version)
        } catch let failure {
            error = describe(failure)
        }
    }

    private func restore(_ entry: HistoryEntry) async {
        do {
            if let conflict = try await model.restore(item, version: entry.version) {
                note = conflict
            } else {
                note = "Brought back version \(entry.version) as a new version."
            }
            shown = [:]
            await load()
        } catch let failure {
            error = describe(failure)
        }
    }
}

/// Adds another device to this account: shows the line to paste into it, waits for it,
/// then takes the code it shows and sends it the account, sealed so only it can open it.
private struct AddDeviceSheet: View {
    let model: AppModel
    @State private var line: String?
    @State private var newDevice: String?
    @State private var code = ""
    @State private var loadError: String?
    @State private var sent = false

    var body: some View {
        SheetScaffold(
            title: "Add a Device", actionTitle: "Send",
            canAct: newDevice != nil && !code.trimmed.isEmpty
        ) {
            let name = try await model.sendAccount(toNewDevice: code)
            model.noteAddedDevice(name)
            sent = true
            return true
        } content: {
            if let loadError {
                Label(loadError, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let line {
                Text("On the new device, open Keystead, choose Add this Mac, and paste this line. "
                    + "On the command line, run it.")
                    .fixedSize(horizontal: false, vertical: true)
                HStack(alignment: .top) {
                    Text(line)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Copy") { model.copy(line) }
                }
                .padding(10)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
                if let newDevice {
                    Text("\u{201C}\(newDevice)\u{201D} is ready. Type the code it shows:")
                    TextField("Code", text: $code, prompt: Text("1a2b-3c4d-5e6f-7a8b-9c0d"))
                        .font(.system(.body, design: .monospaced))
                    Text("Typing it checks that your account goes to that device and nowhere else. "
                        + "Then Touch ID confirms sending it.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    HStack(spacing: 8) {
                        ProgressView()
                            .controlSize(.small)
                        Text("Waiting for the new device, for up to ten minutes…")
                            .foregroundStyle(.secondary)
                    }
                }
            } else {
                ProgressView()
                    .frame(maxWidth: .infinity)
            }
        }
        .frame(width: 520)
        .task { await run() }
        .onDisappear {
            if !sent { Task { await model.cancelAddingDevice() } }
        }
    }

    /// Starts, then asks every two seconds whether the new device has joined.
    private func run() async {
        do {
            line = try await model.startAddingDevice()
            while newDevice == nil && !Task.isCancelled {
                newDevice = try await model.newDevice()
                if newDevice == nil { try await Task.sleep(for: .seconds(2)) }
            }
        } catch is CancellationError {
            return
        } catch {
            loadError = describe(error)
        }
    }
}

/// Imports logins from a Passbolt export, or a KeePass or KeePassXC file: choose the file,
/// open it with its passphrase, look at what would happen, then import.
private struct ImportSheet: View {
    let model: AppModel
    @State private var file: URL?
    @State private var passphrase = ""
    @State private var export: LoginExport?
    @State private var preview: ImportPreview?
    /// Where logins in no folder go: nowhere (they stay yours), or this folder.
    @State private var intoFolder = false
    @State private var unfiledFolder = "Imported"
    @State private var result: ImportResult?

    private var unfiled: String? { intoFolder && !unfiledFolder.trimmed.isEmpty ? unfiledFolder.trimmed : nil }

    var body: some View {
        SheetScaffold(
            title: "Import Logins",
            actionTitle: result != nil ? "Done" : preview != nil ? "Import \(toImport) Logins" : "Open",
            canAct: result != nil || (preview != nil && toImport > 0)
                || (preview == nil && file != nil && !passphrase.isEmpty),
            showsCancel: result == nil
        ) {
            if result != nil { return true }
            if let export {
                result = try await model.runImport(export, unfiled: unfiled)
                passphrase = ""
                return false
            }
            guard let file else { return false }
            let data = try Data(contentsOf: file)
            let export = try await model.readExport(data, passphrase: passphrase)
            preview = try await model.planImport(export, unfiled: unfiled)
            self.export = export
            return false
        } content: {
            if let result {
                Text("Imported \(result.added) \(result.added == 1 ? "login" : "logins")"
                    + (result.foldersCreated > 0 ? " into \(result.foldersCreated) new folders." : "."))
                Text("New folders are yours alone until you share them, for example with a group.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let preview {
                Text("\(file?.lastPathComponent ?? "The file") has these logins:")
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(preview.folders, id: \.name) { folder in
                        HStack {
                            Label(folder.name, systemImage: "folder")
                            if folder.new {
                                Text("new")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text("\(folder.logins)")
                                .monospacedDigit()
                        }
                    }
                    if preview.own > 0 {
                        HStack {
                            Label("In no folder", systemImage: "person")
                            Spacer()
                            Text("\(preview.own)")
                                .monospacedDigit()
                        }
                    }
                }
                .padding(10)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
                if preview.own > 0 || intoFolder {
                    Toggle("Put logins in no folder into a folder named", isOn: $intoFolder)
                    if intoFolder {
                        TextField("Folder", text: $unfiledFolder)
                    }
                }
                ForEach(notes(preview), id: \.self) { note in
                    Text(note)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                Text("In Passbolt, choose Export and the KDBX format (KeePass or KeePassXC both "
                    + "work), then choose the file here. A KeePass or KeePassXC file works too. "
                    + "Nothing is saved until you've seen what would be imported.")
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Text(file?.lastPathComponent ?? "No file chosen")
                        .foregroundStyle(file == nil ? .secondary : .primary)
                    Spacer()
                    Button("Choose File…") { chooseFile() }
                }
                SecureField("Passphrase", text: $passphrase, prompt: Text("The passphrase it was exported with"))
            }
        }
        .frame(width: 500)
        .onChange(of: intoFolder) { Task { await replan() } }
        .onChange(of: unfiledFolder) { Task { await replan() } }
        #if DEBUG
        .task {
            if model.isDemo {
                file = URL(fileURLWithPath: "/passbolt-export.kdbx")
                preview = AppModel.demoImportPreview
            }
        }
        #endif
    }

    private var toImport: UInt32 {
        guard let preview else { return 0 }
        return preview.folders.reduce(preview.own) { $0 + $1.logins }
    }

    private func notes(_ preview: ImportPreview) -> [String] {
        var notes: [String] = []
        if preview.duplicates > 0 {
            notes.append("\(preview.duplicates) already here (same folder, name and username) are left out.")
        }
        for folder in preview.viewOnly {
            notes.append("\(folder.logins) in \u{201C}\(folder.name)\u{201D} are left out: you can only view it.")
        }
        if preview.oneTimeCodes > 0 {
            notes.append("\(preview.oneTimeCodes) come with one-time codes.")
        }
        return notes
    }

    private func replan() async {
        guard let export, result == nil else { return }
        preview = try? await model.planImport(export, unfiled: unfiled)
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "kdbx") ?? .data]
        panel.message = "Choose a Passbolt export, or a KeePass or KeePassXC file (.kdbx)."
        if panel.runModal() == .OK {
            file = panel.url
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

    /// Everyone and every group it's shared with directly, as they read in a sentence.
    private var sharedWith: [String] {
        item.sharedWith + item.sharedWithGroups.map { "everyone in \($0)" }
    }

    /// Who loses the login, and whether it can come back, in a sentence or two.
    private var consequence: String {
        let people = ListFormatter.localizedString(byJoining: sharedWith)
        let whoLoses: String
        if let folder = item.folder {
            whoLoses = sharedWith.isEmpty
                ? "everyone in \u{201C}\(folder)\u{201D}"
                : "everyone in \u{201C}\(folder)\u{201D} and for \(people)"
        } else if item.sharedWithMe {
            let others = ([item.owner].compactMap { $0 } + sharedWith)
            whoLoses = (others.isEmpty
                ? "everyone it's shared with"
                : ListFormatter.localizedString(byJoining: others)) + " as well as for you"
        } else if sharedWith.isEmpty {
            return model.keepsDeleted
                ? "Only you have this login. Recently Deleted can bring it back for 30 days."
                : "Only you have this login. Once deleted, it can't be brought back."
        } else {
            whoLoses = "you and for \(people)"
        }
        return model.keepsDeleted
            ? "It's deleted for \(whoLoses). Recently Deleted can bring it back for 30 days."
            : "It's deleted for \(whoLoses), and can't be brought back."
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

/// Who or what a folder or login is shared with: a person or a group.
private enum Recipient: Hashable {
    case person(Int64)
    case group(String)
}

/// The people, then the groups, to pick from in a "With" picker.
private struct RecipientOptions: View {
    let people: [User]
    let groups: [GroupSummary]

    var body: some View {
        if !people.isEmpty {
            Section("People") {
                ForEach(people) { Text($0.name).tag(Recipient?.some(.person($0.userId))) }
            }
        }
        if !groups.isEmpty {
            Section("Groups") {
                ForEach(groups) { Text($0.name).tag(Recipient?.some(.group($0.id))) }
            }
        }
    }
}

/// Shares one login with an approved person or a group, and shows who already has it
/// directly.
private struct ShareLoginSheet: View {
    let model: AppModel
    let item: ItemSummary
    @State private var recipient: Recipient?
    @State private var role: Role = .edit
    @State private var sharing = Sharing(people: [], groups: [])
    @State private var problem: String?

    init(model: AppModel, item: ItemSummary) {
        self.model = model
        self.item = item
        let people = Self.people(for: item, in: model)
        let groups = Self.groups(for: item, in: model)
        _recipient = State(initialValue: people.first.map { .person($0.userId) }
            ?? groups.first.map { .group($0.id) })
    }

    /// Approved people other than you who don't have this login directly yet.
    private static func people(for item: ItemSummary, in model: AppModel) -> [User] {
        model.users.filter { user in
            user.approved && !user.removed && user.userId != model.identity?.userId
                && user.name != item.owner && !item.sharedWith.contains(user.name)
        }
    }

    /// Groups this login isn't shared with yet.
    private static func groups(for item: ItemSummary, in model: AppModel) -> [GroupSummary] {
        model.groups.filter { !item.sharedWithGroups.contains($0.name) }
    }

    private var people: [User] { Self.people(for: item, in: model) }
    private var groups: [GroupSummary] { Self.groups(for: item, in: model) }
    private var manages: Bool { item.role == .manage }

    /// Whom the login would go to, by name, and whether it's a group.
    private var chosen: (name: String, isGroup: Bool)? {
        switch recipient {
        case .person(let id): people.first { $0.userId == id }.map { ($0.name, false) }
        case .group(let id): groups.first { $0.id == id }.map { ($0.name, true) }
        case nil: nil
        }
    }

    var body: some View {
        SheetScaffold(
            title: manages ? "Share \u{201C}\(item.name)\u{201D}" : "Access to \u{201C}\(item.name)\u{201D}",
            actionTitle: manages ? "Share" : "Done",
            canAct: !manages || chosen != nil,
            showsCancel: manages
        ) {
            guard manages else { return true }
            switch recipient {
            case .person(let id):
                guard let user = people.first(where: { $0.userId == id }) else { return false }
                try await model.share(login: item, with: user, role: role)
            case .group(let id):
                guard let group = groups.first(where: { $0.id == id }) else { return false }
                try await model.share(login: item, with: group, role: role)
            case nil:
                return false
            }
            return true
        } content: {
            if manages {
                if people.isEmpty && groups.isEmpty {
                    Text(model.users.contains { $0.approved && !$0.removed && $0.userId != model.identity?.userId }
                        ? "Everyone approved, and every group, can already open this login."
                        : "There's no one approved to share with yet. "
                            + (model.isOwner
                                ? "Invite people from People, then approve them once they've joined."
                                : "The owner approves people as they join."))
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Form {
                        Picker("With", selection: $recipient) {
                            RecipientOptions(people: people, groups: groups)
                        }
                        Picker("Access", selection: $role) {
                            ForEach(Role.all, id: \.self) { Text($0.label).tag($0) }
                        }
                    }
                    if let chosen {
                        Text((chosen.isGroup ? "Everyone in \(chosen.name)" : chosen.name)
                            + " will see this login"
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
            if !sharing.people.isEmpty {
                PeopleWithAccess(
                    title: "Has it directly", people: sharing.people, canManage: manages, canLeave: false,
                    isMaker: { $0.name == (item.owner ?? model.identity?.name) && $0.role == .manage && item.folder == nil },
                    setRole: { person, role in
                        try await model.setRole(role, for: person, on: item)
                        await reload()
                    },
                    remove: { person in
                        try await model.unshare(item, from: person)
                        await reload()
                    })
            }
            if !sharing.groups.isEmpty {
                GroupsWithAccess(
                    groups: sharing.groups, canManage: manages,
                    setRole: { share, role in
                        try await model.setRole(role, for: share, on: item)
                        await reload()
                    },
                    remove: { share in
                        try await model.unshare(item, from: share)
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
            sharing = try await model.sharing(of: item)
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
    /// Who made a login outside folders: they always manage it, so their row can't change.
    var isMaker: (Person) -> Bool = { _ in false }
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
                    if isMaker(person) {
                        Text("Made it")
                            .foregroundStyle(.secondary)
                            .help(person.isMe
                                ? "It's your login, so you always manage it."
                                : "It's \(person.name)'s login, so they always manage it.")
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

/// The groups a folder or login is shared with and their roles. Managers change roles and
/// remove groups here; everyone else just reads it.
private struct GroupsWithAccess: View {
    let groups: [GroupShare]
    let canManage: Bool
    var setRole: (GroupShare, Role) async throws -> Void
    var remove: (GroupShare) async throws -> Void
    @State private var busy: String?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(groups.count == 1 ? "1 group" : "\(groups.count) groups")
                .font(.headline)
            ForEach(groups) { share in
                HStack {
                    Label(share.isMine ? "\(share.name) (you're in it)" : share.name,
                          systemImage: "person.3")
                    Spacer()
                    if canManage {
                        Picker("", selection: Binding(
                            get: { share.role },
                            set: { role in run(share) { try await setRole(share, role) } }
                        )) {
                            ForEach(Role.all, id: \.self) { Text($0.label).tag($0) }
                        }
                        .labelsHidden()
                        .fixedSize()
                        Button("Remove") { run(share) { try await remove(share) } }
                    } else {
                        Text(share.role.label)
                            .foregroundStyle(.secondary)
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

    private func run(_ share: GroupShare, _ action: @escaping () async throws -> Void) {
        busy = share.groupId
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

/// Who is in a folder and the groups it's shared with, with their roles. Managers change
/// roles and remove people and groups; anyone can leave. Removing someone gives the folder
/// a new key.
private struct ManageFolderSheet: View {
    let model: AppModel
    let folder: String
    @Environment(\.dismiss) private var dismiss
    @State private var sharing: Sharing?
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Access to \u{201C}\(folder)\u{201D}")
                .font(.title3.weight(.semibold))
            if let sharing {
                if !sharing.people.isEmpty {
                    PeopleWithAccess(
                        title: "\(sharing.people.count) \(sharing.people.count == 1 ? "person" : "people")",
                        people: sharing.people, canManage: model.manages(folder: folder),
                        setRole: { person, role in
                            try await model.setRole(role, for: person, in: folder)
                            await reload()
                        },
                        remove: { person in
                            try await model.remove(person, from: folder)
                            if person.isMe { dismiss() } else { await reload() }
                        })
                }
                if !sharing.groups.isEmpty {
                    GroupsWithAccess(
                        groups: sharing.groups, canManage: model.manages(folder: folder),
                        setRole: { share, role in
                            try await model.setRole(role, for: share, in: folder)
                            await reload()
                        },
                        remove: { share in
                            try await model.remove(share, from: folder)
                            await reload()
                        })
                }
            } else if problem == nil {
                ProgressView().frame(maxWidth: .infinity)
            }
            Text(model.manages(folder: folder)
                ? "Viewers can open and copy, editors can also change logins, and managers can "
                    + "also share and remove people. A group's role is everyone's in it. Removing "
                    + "someone gives the folder a new key, so they can't read what's saved afterwards."
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
            sharing = try await model.sharing(of: folder)
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
    @State private var recipient: Recipient?
    @State private var role: Role = .edit

    init(model: AppModel, folder: String?, user: User?, group: GroupSummary? = nil) {
        self.model = model
        _folder = State(initialValue: folder ?? Self.folders(in: model).first ?? "")
        let first: Recipient? = Self.people(in: model).first.map { .person($0.userId) }
            ?? model.groups.first.map { .group($0.id) }
        _recipient = State(initialValue: group.map { .group($0.id) } ?? user.map { .person($0.userId) } ?? first)
    }

    /// Approved people other than you who are still on the team.
    private static func people(in model: AppModel) -> [User] {
        model.users.filter { $0.approved && !$0.removed && $0.userId != model.identity?.userId }
    }

    /// The folders you manage, which are the ones you can share.
    private static func folders(in model: AppModel) -> [String] {
        model.folders.filter { model.manages(folder: $0) }
    }

    /// Whom the folder would go to, by name, and whether it's a group.
    private var chosen: (name: String, isGroup: Bool)? {
        switch recipient {
        case .person(let id): Self.people(in: model).first { $0.userId == id }.map { ($0.name, false) }
        case .group(let id): model.groups.first { $0.id == id }.map { ($0.name, true) }
        case nil: nil
        }
    }

    var body: some View {
        SheetScaffold(title: "Share a Folder", actionTitle: "Share", canAct: chosen != nil && !folder.isEmpty) {
            switch recipient {
            case .person(let id):
                guard let user = Self.people(in: model).first(where: { $0.userId == id }) else { return false }
                try await model.share(folder: folder, with: user, role: role)
            case .group(let id):
                guard let group = model.groups.first(where: { $0.id == id }) else { return false }
                try await model.share(folder: folder, with: group, role: role)
            case nil:
                return false
            }
            return true
        } content: {
            if Self.folders(in: model).isEmpty {
                Text("You don't manage any folders, so you can't share one. A folder's managers "
                    + "can share it with \(chosen?.name ?? "people").")
                    .fixedSize(horizontal: false, vertical: true)
            } else if Self.people(in: model).isEmpty && model.groups.isEmpty {
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
                    Picker("With", selection: $recipient) {
                        RecipientOptions(people: Self.people(in: model), groups: model.groups)
                    }
                    Picker("Access", selection: $role) {
                        ForEach(Role.all, id: \.self) { Text($0.label).tag($0) }
                    }
                }
                if let chosen {
                    Text(chosen.isGroup
                        ? "Everyone in \(chosen.name) will see every login in \u{201C}\(folder)\u{201D}, "
                            + "including ones added later, and so will anyone who joins the group."
                        : "\(chosen.name) will see every login in \u{201C}\(folder)\u{201D}, "
                            + "including ones added later.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

// MARK: - Groups

private struct NewGroupSheet: View {
    let model: AppModel
    @State private var name = ""
    @State private var chosen: Set<Int64> = []

    private var exists: Bool { model.groups.contains { $0.name == name.trimmed } }

    /// Approved people other than you who are still on the team.
    private var people: [User] {
        model.users.filter { $0.approved && !$0.removed && $0.userId != model.identity?.userId }
    }

    var body: some View {
        SheetScaffold(title: "New Group", actionTitle: "Create", canAct: !name.trimmed.isEmpty && !exists) {
            try await model.createGroup(named: name, with: people.map(\.userId).filter(chosen.contains))
            return true
        } content: {
            Form {
                TextField("Name", text: $name, prompt: Text("Engineering"))
            }
            if !people.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("In the group")
                        .font(.headline)
                    ScrollView {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(people) { user in
                                Toggle(user.name, isOn: Binding(
                                    get: { chosen.contains(user.userId) },
                                    set: { on in
                                        if on { chosen.insert(user.userId) } else { chosen.remove(user.userId) }
                                    }))
                                .toggleStyle(.checkbox)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(maxHeight: 160)
                }
            }
            Text(exists
                ? "There's already a group with that name."
                : "You're in it too, as its manager. Share folders and logins with the group, "
                    + "and everyone in it gets them, including people added later.")
                .font(.caption)
                .foregroundStyle(exists ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct AddToGroupSheet: View {
    let model: AppModel
    let group: GroupSummary
    @State private var userId: Int64

    init(model: AppModel, group: GroupSummary) {
        self.model = model
        self.group = group
        _userId = State(initialValue: Self.candidates(for: group, in: model).first?.userId ?? 0)
    }

    /// Approved people on the team who aren't in the group yet.
    private static func candidates(for group: GroupSummary, in model: AppModel) -> [User] {
        model.users.filter { user in
            user.approved && !user.removed && !group.members.contains { $0.userId == user.userId }
        }
    }

    private var candidates: [User] { Self.candidates(for: group, in: model) }
    private var person: User? { candidates.first { $0.userId == userId } }

    var body: some View {
        SheetScaffold(title: "Add to \u{201C}\(group.name)\u{201D}", actionTitle: "Add", canAct: person != nil) {
            guard let person else { return false }
            try await model.add(person, to: group)
            return true
        } content: {
            if candidates.isEmpty {
                Text("Everyone approved is already in \(group.name).")
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Form {
                    Picker("Person", selection: $userId) {
                        ForEach(candidates) { Text($0.name).tag($0.userId) }
                    }
                }
                if let person {
                    Text("\(person.name) will get every folder and login shared with \(group.name).")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

private struct RenameGroupSheet: View {
    let model: AppModel
    let group: GroupSummary
    @State private var name: String

    init(model: AppModel, group: GroupSummary) {
        self.model = model
        self.group = group
        _name = State(initialValue: group.name)
    }

    private var exists: Bool { model.groups.contains { $0.name == name.trimmed && $0.id != group.id } }

    var body: some View {
        SheetScaffold(
            title: "Rename \u{201C}\(group.name)\u{201D}", actionTitle: "Rename",
            canAct: !name.trimmed.isEmpty && !exists && name.trimmed != group.name
        ) {
            try await model.rename(group, to: name)
            return true
        } content: {
            Form {
                TextField("Name", text: $name)
            }
            if exists {
                Text("There's already a group with that name.")
                    .font(.caption)
                    .foregroundStyle(.orange)
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

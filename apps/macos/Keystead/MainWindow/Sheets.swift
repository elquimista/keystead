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
        case .moveLogin(let item):
            MoveLoginSheet(model: model, item: item)
        case .deleteLogin(let item):
            DeleteLoginSheet(model: model, item: item)
        case .shareLogin(let item):
            ShareLoginSheet(model: model, item: item)
        case .newFolder(let parent):
            NewFolderSheet(model: model, parent: parent)
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
        case .helpRecover(let user):
            HelpRecoverSheet(model: model, user: user)
        case .exportLogins:
            ExportLoginsSheet(model: model)
        case .renameFolder(let folder):
            RenameFolderSheet(model: model, folder: folder)
        case .deleteFolder(let folder):
            DeleteFolderSheet(model: model, folder: folder)
        }
    }
}

extension View {
    /// A sheet's form in the grouped style, as in System Settings, edge to edge with the
    /// sheet's other content. Sheets grow to fit it, so it doesn't scroll, unless it's given
    /// a height for lists that can get long.
    func sheetForm(height: CGFloat? = nil) -> some View {
        formStyle(.grouped)
            .scrollDisabled(height == nil)
            .frame(height: height)
            .padding(.horizontal, -20)
            .padding(.vertical, -12)
    }
}

/// A grouped form's footer: a caption that reads from the left, as System Settings sets them.
private struct FormFooter: View {
    let text: String
    var color: Color?

    init(_ text: String, color: Color? = nil) {
        self.text = text
        self.color = color
    }

    var body: some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(color.map { AnyShapeStyle($0) } ?? AnyShapeStyle(.secondary))
            .frame(maxWidth: .infinity, alignment: .leading)
            .multilineTextAlignment(.leading)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// A small tinted capsule beside a name, like "New".
struct Badge: View {
    let text: String
    var color: Color = .accentColor

    init(_ text: String, color: Color = .accentColor) {
        self.text = text
        self.color = color
    }

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, 6)
            .padding(.vertical, 1.5)
            .background(color.opacity(0.15), in: Capsule())
    }
}

/// A line to send someone, like an invite, as a form row: monospaced and selectable, with a
/// copy button that says when it has copied.
private struct LineRow: View {
    let line: String
    let copy: () -> Void
    @State private var copied = false

    var body: some View {
        VStack(alignment: .trailing, spacing: 8) {
            CommandText(text: line)
            // A standard text button, like every other button in a form: a small one keeps
            // the form's full-size text, which crowds it.
            Button(copied ? "Copied" : "Copy") {
                copy()
                copied = true
            }
            .help("Copy the line")
        }
        .task(id: copied) {
            guard copied else { return }
            try? await Task.sleep(for: .seconds(2))
            if !Task.isCancelled { copied = false }
        }
    }
}

/// A command line to send someone, monospaced and selectable, that wraps only at its
/// spaces: SwiftUI's text would also break inside a token, after a hyphen or a slash.
/// What's selected and copied is the line exactly as it is.
private struct CommandText: NSViewRepresentable {
    let text: String

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> NSTextView {
        // TextKit 1, for the layout manager's say in where lines break.
        let view = NSTextView(usingTextLayoutManager: false)
        view.isEditable = false
        view.isSelectable = true
        view.drawsBackground = false
        view.isVerticallyResizable = false
        view.isHorizontallyResizable = false
        view.textContainerInset = .zero
        view.textContainer?.lineFragmentPadding = 0
        view.textContainer?.widthTracksTextView = false
        view.layoutManager?.delegate = context.coordinator
        view.setAccessibilityLabel(text)
        update(view)
        return view
    }

    func updateNSView(_ view: NSTextView, context: Context) {
        if view.string != text { update(view) }
    }

    private func update(_ view: NSTextView) {
        let size = NSFont.preferredFont(forTextStyle: .callout).pointSize
        view.textStorage?.setAttributedString(NSAttributedString(string: text, attributes: [
            .font: NSFont.monospacedSystemFont(ofSize: size, weight: .regular),
            .foregroundColor: NSColor.labelColor,
        ]))
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView view: NSTextView, context: Context) -> CGSize? {
        guard let container = view.textContainer, let layout = view.layoutManager else { return nil }
        let width = proposal.width ?? 400
        container.containerSize = NSSize(width: width, height: .greatestFiniteMagnitude)
        layout.ensureLayout(for: container)
        return CGSize(width: width, height: ceil(layout.usedRect(for: container).height))
    }

    final class Coordinator: NSObject, NSLayoutManagerDelegate {
        /// Lines break only after a space. A token longer than a whole line still breaks
        /// by character, as the layout manager falls back to.
        func layoutManager(
            _ layoutManager: NSLayoutManager, shouldBreakLineByWordBeforeCharacterAt index: Int
        ) -> Bool {
            guard index > 0, let string = layoutManager.textStorage?.string as NSString?,
                index <= string.length
            else { return true }
            return string.character(at: index - 1) == 0x20
        }
    }
}

/// A finished step: a big tinted symbol beside what happened.
private struct Outcome: View {
    var symbol = "checkmark.circle.fill"
    var color: Color = .green
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: symbol)
                .font(.system(size: 34))
                .foregroundStyle(.white, color)
                .symbolRenderingMode(.palette)
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.headline)
                Text(detail)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// A code to type, like a fingerprint, as a form row: the label as other labels are, the
/// code monospaced.
private struct CodeField: View {
    let title: String
    @Binding var text: String

    init(_ title: String, text: Binding<String>) {
        self.title = title
        _text = text
    }

    var body: some View {
        LabeledContent(title) {
            TextField(title, text: $text, prompt: Text("1a2b-3c4d-5e6f-7a8b-9c0d"))
                .labelsHidden()
                .font(.system(.body, design: .monospaced))
                .multilineTextAlignment(.trailing)
                .autocorrectionDisabled()
        }
    }
}

/// Waiting on someone else, as a form row.
private struct WaitingRow: View {
    let text: String

    var body: some View {
        HStack(spacing: 8) {
            ProgressView()
                .controlSize(.small)
            Text(text)
                .foregroundStyle(.secondary)
        }
    }
}

/// What every sheet shares: a title, the content, an error line and the buttons. `action`
/// runs when the main button is pressed and returns whether the sheet should close.
private struct SheetScaffold<Content: View>: View {
    var width: CGFloat = 460
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
        .frame(width: width)
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
                        TextField(title, text: $password, prompt: Text("Required"))
                            .font(.system(.body, design: .monospaced))
                    } else {
                        SecureField(title, text: $password, prompt: Text("Required"))
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
                Section {
                    Picker("Folder", selection: $folder) {
                        Text("None").tag(String?.none)
                        if !model.folders.isEmpty {
                            Divider()
                        }
                        ForEach(model.folders, id: \.self) { Text($0).tag(String?.some($0)) }
                    }
                } footer: {
                    Text(folder.map { "Everyone \u{201C}\($0)\u{201D} is shared with will see it." }
                        ?? "Only you can see it until you share it.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .multilineTextAlignment(.leading)
                }
                Section {
                    TextField("Name", text: $name, prompt: Text("AWS root account"))
                    TextField("Username", text: $username, prompt: Text("Optional"))
                    TextField("Website", text: $url, prompt: Text("Optional"))
                }
                Section {
                    PasswordField(title: "Password", password: $password)
                    OneTimeCodeField(setup: $oneTimeCode)
                }
                NotesField(notes: $notes)
            }
            .sheetForm()
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
                            TextField("One-time code", text: $setup, prompt: Text("Optional"))
                                .font(.system(.body, design: .monospaced))
                        } else {
                            SecureField("One-time code", text: $setup, prompt: Text("Optional"))
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
                    Button {
                        readQRCode()
                    } label: {
                        Image(systemName: "qrcode.viewfinder")
                    }
                    .buttonStyle(.borderless)
                    .help("Read the site's QR code from a screenshot or image. Or paste its setup "
                        + "key or otpauth:// link.")
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
        Section("Notes") {
            TextField("Notes", text: $notes, prompt: Text("Optional"), axis: .vertical)
                .labelsHidden()
                .lineLimit(3...8)
        }
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
                    Section {
                        TextField("Name", text: $name)
                        TextField("Username", text: $username, prompt: Text("Optional"))
                        TextField("Website", text: $url, prompt: Text("Optional, https://…"))
                    }
                    Section {
                        PasswordField(title: "Password", password: $password)
                        OneTimeCodeField(setup: $oneTimeCode)
                    } footer: {
                        if password != original?.password {
                            Text("Change it on the website or service too, if you haven't already.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .multilineTextAlignment(.leading)
                        }
                    }
                    NotesField(notes: $notes)
                }
                .sheetForm()
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
            width: 560, title: "History of \u{201C}\(item.name)\u{201D}", actionTitle: "Done",
            showsCancel: false
        ) {
            true
        } content: {
            if let loadError {
                Label(loadError, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let entries {
                Form {
                    Section {
                        ForEach(entries, id: \.version) { entry in
                            row(entry)
                        }
                    } footer: {
                        FormFooter("The server keeps the last 10 earlier versions. Bringing one back "
                            + "saves it as a new version; if its password differs, change it at the "
                            + "website too.")
                    }
                }
                // Six versions fit; more scroll.
                .sheetForm(height: entries.count > 6 ? 500 : nil)
                .animation(.snappy(duration: 0.25), value: entries.map(\.version))
            } else {
                ProgressView()
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, minHeight: 120)
            }
            if let note {
                Label(note, systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
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

    /// Who saved it beside what they changed, when, and its version; then, for earlier
    /// versions you can open, the password and a way to bring it back.
    private func row(_ entry: HistoryEntry) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Avatar(name: entry.author, size: 26)
            VStack(alignment: .leading, spacing: 2) {
                HStack(alignment: .firstTextBaseline) {
                    Text(changes(entry))
                        .fontWeight(.medium)
                        .foregroundStyle(entry.readable ? .primary : .secondary)
                    Spacer(minLength: 8)
                    if entry.current {
                        Badge("Current")
                    } else {
                        Text("Version \(entry.version)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Text(saved(entry))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if !entry.readable {
                    Text("It's from before this login was shared with you.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else if !entry.current {
                    HStack(spacing: 6) {
                        Text(shown[entry.version] ?? "••••••••••••")
                            .font(.system(.callout, design: .monospaced))
                            .foregroundStyle(shown[entry.version] == nil ? .secondary : .primary)
                            .textSelection(.enabled)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        RevealButton(what: "this version's password", shown: shown[entry.version] != nil,
                                     emphasized: true) { await reveal(entry) }
                        Button {
                            Task { await model.copyHistoryPassword(of: item, version: entry.version) }
                        } label: {
                            Image(systemName: "doc.on.doc")
                        }
                        .buttonStyle(.borderless)
                        .help("Copy this version's password (cleared after 30 seconds)")
                        Spacer(minLength: 8)
                        Button("Bring Back…") { restoring = entry }
                    }
                    .padding(.top, 6)
                }
            }
        }
        .padding(.vertical, 2)
    }

    /// "Mo · Nov 20, 2026 at 4:46 PM".
    private func saved(_ entry: HistoryEntry) -> String {
        let date = entry.savedAt.map {
            Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated, time: .shortened)
        }
        return [entry.author, date].compactMap { $0 }.joined(separator: " · ")
    }

    private func changes(_ entry: HistoryEntry) -> String {
        if !entry.readable { return "Can't be opened here" }
        if entry.changes == ["created"] { return "Created" }
        if entry.changes.isEmpty { return "No change to its fields, for example sharing it" }
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
            width: 520, title: "Add a Device", actionTitle: "Send",
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
                Form {
                    Section {
                        LineRow(line: line) { model.copy(line) }
                    } header: {
                        Text("1. Paste this line on the new device")
                    } footer: {
                        FormFooter("In Keystead, choose \u{201C}Add this Mac\u{201D} and paste it. On "
                            + "the command line, run it.")
                    }
                    Section {
                        if newDevice != nil {
                            CodeField("Code", text: $code)
                        } else {
                            WaitingRow(text: "Waiting for the new device, for up to ten minutes…")
                        }
                    } header: {
                        Text(newDevice.map { "2. Type the code \u{201C}\($0)\u{201D} shows" }
                            ?? "2. Type the code it shows")
                    } footer: {
                        FormFooter("Typing it checks that your account goes to that device and "
                            + "nowhere else. Then Touch ID confirms sending it.")
                    }
                }
                .sheetForm()
                .animation(.snappy(duration: 0.25), value: newDevice)
            } else {
                ProgressView()
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, minHeight: 120)
            }
        }
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
            width: 500, title: "Import Logins",
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
                Outcome(
                    title: "Imported \(result.added) \(result.added == 1 ? "login" : "logins")"
                        + (result.foldersCreated > 0 ? " into \(result.foldersCreated) new folders" : ""),
                    detail: "New folders are yours alone until you share them, for example with a group.")
            } else if let preview {
                Form {
                    Section {
                        ForEach(preview.folders, id: \.name) { folder in
                            countRow(folder.name, symbol: "folder.fill", count: folder.logins, new: folder.new)
                        }
                        if preview.own > 0 {
                            countRow("In no folder", symbol: "person.fill", count: preview.own, new: false)
                        }
                    } header: {
                        Text("\(file?.lastPathComponent ?? "The file") has these logins")
                    } footer: {
                        if !notes(preview).isEmpty {
                            FormFooter(notes(preview).joined(separator: "\n"))
                        }
                    }
                    if preview.own > 0 || intoFolder {
                        Section {
                            Toggle("Put logins in no folder into a folder", isOn: $intoFolder)
                            if intoFolder {
                                TextField("Folder name", text: $unfiledFolder)
                            }
                        } footer: {
                            FormFooter(intoFolder
                                ? "If there's no such folder yet, it's made for you, and it's yours "
                                    + "alone until you share it."
                                : "Otherwise each stays yours alone until you share it.")
                        }
                    }
                }
                .sheetForm(height: preview.folders.count > 8 ? 520 : nil)
            } else {
                Text("In Passbolt, choose Export and the KDBX format (KeePass or KeePassXC both "
                    + "work), then choose the file here. A KeePass or KeePassXC file works too.")
                    .fixedSize(horizontal: false, vertical: true)
                Form {
                    Section {
                        LabeledContent("File") {
                            HStack(spacing: 8) {
                                Text(file?.lastPathComponent ?? "None")
                                    .foregroundStyle(file == nil ? .secondary : .primary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                Button("Choose\u{2026}") { chooseFile() }
                            }
                        }
                        SecureField("Passphrase", text: $passphrase, prompt: Text("The one it was exported with"))
                    } footer: {
                        FormFooter("Nothing is saved until you've seen what would be imported.")
                    }
                }
                .sheetForm()
            }
        }
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

    /// A folder, or logins in none, and how many logins would go there.
    private func countRow(_ name: String, symbol: String, count: UInt32, new: Bool) -> some View {
        HStack(spacing: 8) {
            Image(systemName: symbol)
                .foregroundStyle(.secondary)
                .frame(width: 20)
            Text(name)
            if new {
                Badge("New")
            }
            Spacer()
            Text("\(count)")
                .monospacedDigit()
                .foregroundStyle(.secondary)
        }
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

/// The owner helps someone who lost every device and their Recovery Kit: a line to send
/// them, then the fingerprint their new Mac shows, to approve its new keys.
private struct HelpRecoverSheet: View {
    let model: AppModel
    let user: User
    @Environment(\.dismiss) private var dismiss
    /// The line made here; one made earlier isn't shown again.
    @State private var line: String?
    @State private var request: PendingRecovery?
    @State private var loaded = false
    @State private var fingerprint = ""
    @State private var busy = false
    @State private var error: String?
    @State private var approved: RecoveryApproval?
    /// Sign out their devices when making the line.
    @State private var signOut = false
    @State private var signedOut = false

    private var claimed: Bool { request?.claimed == true }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                Avatar(name: user.name, size: 28)
                Text("Help \(user.name) Recover")
                    .font(.title3.weight(.semibold))
            }
            if let approved {
                Outcome(
                    symbol: "checkmark.seal.fill",
                    title: "\(approved.name)'s new keys are approved",
                    detail: "Their old devices no longer work. What's shared with them comes back as "
                        + "everyone's Keystead syncs."
                        + (approved.ownLogins
                            ? ""
                            : " Their own logins and the folders only they were in don't come back: "
                                + "escrow was off."))
            } else if !loaded {
                ProgressView()
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, minHeight: 100)
            } else if let request, claimed {
                Text("\(user.name)'s new Mac is ready. Ask them to read out the fingerprint it "
                    + "shows, in person or on a call, and type it here.")
                    .fixedSize(horizontal: false, vertical: true)
                Form {
                    Section {
                        CodeField("Fingerprint", text: $fingerprint)
                    } footer: {
                        FormFooter("If it doesn't match, don't approve: someone else may have used "
                            + "the line. "
                            + (request.escrow
                                ? "Their own logins and folders come back too: they're in escrow."
                                : "Their own logins and the folders only they're in won't come "
                                    + "back: escrow is off."))
                    }
                }
                .sheetForm()
            } else {
                if line == nil && request == nil {
                    Text("Make \(user.name) a one-time line. With it, their new Mac asks for new "
                        + "keys, and you approve them once they read you its fingerprint.")
                        .fixedSize(horizontal: false, vertical: true)
                }
                Form {
                    if let line {
                        Section {
                            LineRow(line: line) { model.copy(line) }
                        } header: {
                            Text("Send \(user.name) this line, privately")
                        } footer: {
                            FormFooter("For example in a direct message. On a new Mac they choose "
                                + "\u{201C}Recover your account\u{201D}, then \u{201C}Recover with your "
                                + "team owner's help\u{201D}, and paste it. It works once, for a week.")
                        }
                    } else if request != nil {
                        Section {
                            Text("A line was sent earlier. Make a new one if they don't have it; the "
                                + "old one stops working.")
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    if line != nil || request != nil {
                        Section {
                            WaitingRow(text: "Waiting for \(user.name) to use it\u{2026}")
                        }
                    }
                    if signedOut {
                        Section {
                            Label("\(user.name)'s devices are signed out.", systemImage: "checkmark.circle")
                                .foregroundStyle(.secondary)
                        }
                    } else if line == nil {
                        Section {
                            Toggle("Sign out \(user.name)'s devices now", isOn: $signOut)
                        } footer: {
                            FormFooter("A lost device that still works could cancel this recovery. If "
                                + "\(user.name) still has one after all, their Recovery Kit gets them "
                                + "back in.")
                        }
                    }
                }
                .sheetForm()
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if approved == nil && request != nil {
                    Button(role: .destructive) {
                        run { try await cancel() }
                    } label: {
                        Text("Cancel Recovery")
                            .foregroundStyle(.red)
                    }
                    .disabled(busy)
                }
                if busy {
                    ProgressView().controlSize(.small)
                }
                Spacer()
                if approved != nil {
                    Button("Done") { dismiss() }
                        .keyboardShortcut(.defaultAction)
                } else if claimed {
                    Button("Close") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    Button("Approve") { run { try await approve() } }
                        .keyboardShortcut(.defaultAction)
                        .disabled(fingerprint.trimmed.isEmpty || busy)
                } else {
                    Button("Close") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    Button(line == nil && request == nil ? "Create Line" : "New Line") {
                        run { try await start() }
                    }
                    .keyboardShortcut(line == nil ? .defaultAction : nil)
                    .disabled(busy)
                }
            }
        }
        .padding(20)
        .frame(width: 520)
        .animation(.snappy(duration: 0.25), value: claimed)
        .animation(.snappy(duration: 0.25), value: line)
        .task { await watch() }
    }

    /// Where the recovery stands, asked again every few seconds until their new Mac is ready.
    private func watch() async {
        while !Task.isCancelled && approved == nil {
            do {
                request = try await model.recoveryRequest(for: user)
            } catch let failure {
                error = describe(failure)
            }
            loaded = true
            if claimed { return }
            try? await Task.sleep(for: .seconds(3))
        }
    }

    private func start() async throws {
        line = try await model.startRecovery(for: user, signOutDevices: signOut)
        signedOut = signedOut || signOut
        request = try await model.recoveryRequest(for: user)
    }

    private func approve() async throws {
        approved = try await model.approveRecovery(for: user, fingerprint: fingerprint)
    }

    private func cancel() async throws {
        try await model.cancelRecovery(for: user.userId)
        dismiss()
    }

    private func run(_ action: @escaping () async throws -> Void) {
        busy = true
        error = nil
        Task {
            do {
                try await action()
            } catch let failure {
                error = describe(failure)
            }
            busy = false
        }
    }
}

/// Exports every login you can open to a KeePass file encrypted with a passphrase.
private struct ExportLoginsSheet: View {
    let model: AppModel
    @State private var passphrase = ""
    @State private var again = ""
    @State private var result: (logins: UInt32, leftOut: UInt32, file: String)?

    private let minimum = Int(minExportPassphrase())
    private var long: Bool { passphrase.count >= minimum }
    private var matches: Bool { passphrase == again }

    var body: some View {
        SheetScaffold(
            width: 500, title: "Export Logins", actionTitle: result == nil ? "Export…" : "Done",
            canAct: result != nil || (long && matches),
            showsCancel: result == nil
        ) {
            if result != nil { return true }
            guard let url = chooseFile() else { return false }
            let exported = try await model.exportLogins(to: url, passphrase: passphrase)
            passphrase = ""
            again = ""
            result = (exported.logins, exported.leftOut, url.lastPathComponent)
            return false
        } content: {
            if let result {
                Text("Exported \(result.logins) \(result.logins == 1 ? "login" : "logins") to "
                    + "\(result.file).")
                Text("KeePassXC and KeePass open it with the passphrase, and Import reads it back. "
                    + "Keep the file and the passphrase safe, and apart.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if result.leftOut > 0 {
                    Text("\(result.leftOut) couldn't be opened here and were left out; a newer "
                        + "Keystead may have saved them.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                Text("Saves every login you can open, \(model.items.count) in all, to a KeePass "
                    + "file (.kdbx), with folders as groups and one-time codes kept. KeePassXC and "
                    + "KeePass open it, and Import reads it back.")
                    .fixedSize(horizontal: false, vertical: true)
                Text("It's encrypted with the passphrase you choose here: anyone with the file "
                    + "and the passphrase can read every password in it.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Form {
                    SecureField("Passphrase", text: $passphrase,
                                prompt: Text("At least \(minimum) characters"))
                    SecureField("Again", text: $again, prompt: Text("The same passphrase"))
                }
                .sheetForm()
                if !again.isEmpty && !matches {
                    Text("The passphrases don't match.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    private func chooseFile() -> URL? {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "kdbx") ?? .data]
        panel.nameFieldStringValue =
            "Keystead \(Date.now.formatted(.iso8601.year().month().day())).kdbx"
        panel.message = "Choose where to save the export."
        return panel.runModal() == .OK ? panel.url : nil
    }
}

/// Moves a login to another folder you can add to, or out of folders as yours, and says
/// who loses it.
private struct MoveLoginSheet: View {
    let model: AppModel
    let item: ItemSummary
    /// The folder it goes to; nil is no folder (yours).
    @State private var destination: String??

    private var choices: [String] {
        model.folders.filter { $0 != item.folder && model.folderRoles[$0] != .view }
    }

    var body: some View {
        SheetScaffold(
            title: "Move \u{201C}\(item.name)\u{201D}", actionTitle: "Move",
            canAct: destination != nil
        ) {
            guard let destination else { return false }
            _ = try await model.move(item, to: destination)
            return true
        } content: {
            Form {
                Picker("To", selection: $destination) {
                    Text("Choose…").tag(String??.none)
                    if item.folder != nil {
                        Text("No folder (only you)").tag(String??.some(nil))
                        Divider()
                    }
                    ForEach(choices, id: \.self) { Text($0).tag(String??.some($0)) }
                }
            }
            .sheetForm()
            Text(consequence)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var consequence: String {
        let kept = "People and groups it's shared with directly keep it."
        guard let folder = item.folder else {
            return "Everyone in the folder you choose gets it. " + kept
        }
        return "Whoever has it only through \u{201C}\(folder)\u{201D} loses it, and its password "
            + "goes on their To Change list. Everyone in the folder you choose gets it. " + kept
    }
}

/// Renames a folder; the folders inside it that you manage follow.
private struct RenameFolderSheet: View {
    let model: AppModel
    let folder: String
    @State private var name: String

    init(model: AppModel, folder: String) {
        self.model = model
        self.folder = folder
        _name = State(initialValue: folder)
    }

    private var exists: Bool { name.trimmed != folder && model.folders.contains(name.trimmed) }

    var body: some View {
        SheetScaffold(
            title: "Rename \u{201C}\(folder)\u{201D}", actionTitle: "Rename",
            canAct: !name.trimmed.isEmpty && !exists && name.trimmed != folder
        ) {
            try await model.rename(folder: folder, to: name)
            return true
        } content: {
            Form {
                TextField("Name", text: $name)
            }
            .sheetForm()
            if exists {
                Text("There's already a folder with that name.")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            Text(caption)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var caption: String {
        var text = "Everyone in it sees the new name. Name it \u{201C}Parent / Name\u{201D} to "
            + "show it inside another folder; who can open it stays the same."
        let inside = model.folders.filter { $0.hasPrefix(folder + " / ") }.count
        if inside == 1 {
            text += " The folder inside it is renamed too, if you manage it."
        } else if inside > 1 {
            text += " The \(inside) folders inside it are renamed too, where you manage them."
        }
        return text
    }
}

/// Asks before deleting a folder: what goes with it for good, and what stays.
private struct DeleteFolderSheet: View {
    let model: AppModel
    let folder: String
    @Environment(\.dismiss) private var dismiss
    @State private var plan: FolderDeletion?
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Delete \u{201C}\(folder)\u{201D}?")
                .font(.title3.weight(.semibold))
            if let plan {
                ForEach(consequence(plan), id: \.self) { paragraph in
                    Text(paragraph)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else if error == nil {
                ProgressView().controlSize(.small)
            }
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
                // Return cancels; deleting takes a deliberate click.
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                Button(role: .destructive) {
                    Task { await delete() }
                } label: {
                    Text(actionTitle)
                        .foregroundStyle(.red)
                }
                .disabled(plan == nil || busy)
            }
        }
        .padding(20)
        .frame(width: 460)
        .task { await load() }
    }

    private var actionTitle: String {
        switch plan?.logins ?? 0 {
        case 0: "Delete Folder"
        case 1: "Delete Folder and 1 Login"
        case let count: "Delete Folder and \(count) Logins"
        }
    }

    /// What goes and what stays, a paragraph each.
    private func consequence(_ plan: FolderDeletion) -> [String] {
        var parts: [String]
        switch plan.logins {
        case 0:
            parts = ["Everyone in it loses it. It has no logins."]
        case 1:
            parts = ["Everyone in it loses it. Its login is deleted with it for everyone, "
                + "including anyone it's shared with directly. It doesn't go to Recently "
                + "Deleted, so it can't be brought back. To keep it, move it to another folder "
                + "first."]
        default:
            parts = ["Everyone in it loses it. Its \(plan.logins) logins are deleted with it for "
                + "everyone, including anyone they're shared with directly. They don't go to "
                + "Recently Deleted, so they can't be brought back. To keep some, move them to "
                + "another folder first."]
        }
        if plan.toChange == 1 {
            parts.append("One of its passwords is on To Change, which deleting forgets: if the "
                + "account stays, change that password at its website first.")
        } else if plan.toChange > 1 {
            parts.append("\(plan.toChange) of its passwords are on To Change, which deleting "
                + "forgets: if those accounts stay, change their passwords first.")
        }
        if !plan.inside.isEmpty {
            parts.append("Folders inside it stay: "
                + ListFormatter.localizedString(byJoining: plan.inside.map { "\u{201C}\($0)\u{201D}" })
                + ".")
        }
        return parts
    }

    private func load() async {
        do {
            plan = try await model.deletion(of: folder)
        } catch let failure {
            error = describe(failure)
        }
    }

    private func delete() async {
        guard let plan else { return }
        busy = true
        do {
            try await model.delete(folder: folder, logins: plan.logins)
            dismiss()
        } catch let failure {
            error = describe(failure)
            // Someone may have added or deleted a login meanwhile: show the folder as it is.
            self.plan = try? await model.deletion(of: folder)
        }
        busy = false
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
            return model.keepsDeleted == true
                ? "Only you have this login. Recently Deleted can bring it back for 30 days."
                : "Only you have this login. Once deleted, it can't be brought back."
        } else {
            whoLoses = "you and for \(people)"
        }
        return model.keepsDeleted == true
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
                    Button(role: .destructive) {
                        Task { await delete() }
                    } label: {
                        Text("Delete")
                            .foregroundStyle(.red)
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
    /// Whether there's someone, or a group, to pick to share with.
    private var canPick: Bool { manages && !(people.isEmpty && groups.isEmpty) }

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
            if manages && people.isEmpty && groups.isEmpty {
                Text(model.users.contains { $0.approved && !$0.removed && $0.userId != model.identity?.userId }
                    ? "Everyone approved, and every group, can already open this login."
                    : "There's no one approved to share with yet. "
                        + (model.isOwner
                            ? "Invite people from People, then approve them once they've joined."
                            : "The owner approves people as they join."))
                    .fixedSize(horizontal: false, vertical: true)
            } else if !manages {
                Text("Only people who manage this login can share it.")
                    .foregroundStyle(.secondary)
            }
            if canPick || !sharing.people.isEmpty || !sharing.groups.isEmpty {
                Form {
                    if canPick {
                        Section {
                            Picker("With", selection: $recipient) {
                                RecipientOptions(people: people, groups: groups)
                            }
                            Picker("Access", selection: $role) {
                                ForEach(Role.all, id: \.self) { Text($0.label).tag($0) }
                            }
                        } footer: {
                            if let chosen {
                                FormFooter((chosen.isGroup ? "Everyone in \(chosen.name)" : chosen.name)
                                    + " will see this login"
                                    + (item.folder.map { ", not the rest of \u{201C}\($0)\u{201D}" } ?? "")
                                    + ".")
                            }
                        }
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
                }
                .sheetForm(height: sharing.people.count + sharing.groups.count > 8 ? 520 : nil)
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

/// A role as a pop-up menu that also removes: the roles to pick from, then Remove.
private struct RoleMenu: View {
    let role: Role
    let removeTitle: String
    let setRole: (Role) -> Void
    let remove: () -> Void

    var body: some View {
        Menu {
            Picker("Access", selection: Binding(get: { role }, set: setRole)) {
                ForEach(Role.all, id: \.self) { Text($0.label).tag($0) }
            }
            .pickerStyle(.inline)
            .labelsHidden()
            Divider()
            Button(removeTitle, role: .destructive, action: remove)
        } label: {
            Text(role.label)
        }
        .menuStyle(.button)
        .buttonStyle(.borderless)
        .fixedSize()
    }
}

/// A person or group's row: their picture and name, a note in grey, and what's on the right.
private struct AccessRow<Picture: View, Trailing: View>: View {
    let name: String
    var note: String?
    @ViewBuilder let picture: Picture
    @ViewBuilder let trailing: Trailing

    var body: some View {
        HStack(spacing: 10) {
            picture
            HStack(spacing: 4) {
                Text(name)
                if let note {
                    Text(note)
                        .foregroundStyle(.secondary)
                }
            }
            .lineLimit(1)
            Spacer(minLength: 8)
            trailing
        }
    }
}

/// The people with access and their roles, as a form section. Managers change roles and
/// remove people here; everyone else just reads it.
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
    var removeTitle: (Person) -> String = { $0.isMe ? "Leave" : "Remove \($0.name)" }
    @State private var busy: Int64?
    @State private var error: String?

    var body: some View {
        Section {
            ForEach(people) { person in
                AccessRow(name: person.name, note: person.isMe ? "(you)" : nil) {
                    Avatar(name: person.name, size: 24)
                } trailing: {
                    if busy == person.userId {
                        ProgressView().controlSize(.small)
                    }
                    if isMaker(person) {
                        Text("Made it")
                            .foregroundStyle(.secondary)
                            .help(person.isMe
                                ? "It's your login, so you always manage it."
                                : "It's \(person.name)'s login, so they always manage it.")
                    } else if canManage {
                        RoleMenu(
                            role: person.role, removeTitle: removeTitle(person),
                            setRole: { role in
                                guard role != person.role else { return }
                                run(person) { try await setRole(person, role) }
                            },
                            remove: { run(person) { try await remove(person) } })
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
        } header: {
            Text(title)
        } footer: {
            if let error {
                FormFooter(error, color: .red)
            }
        }
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

/// The groups a folder or login is shared with and their roles, as a form section.
/// Managers change roles and remove groups here; everyone else just reads it.
private struct GroupsWithAccess: View {
    let groups: [GroupShare]
    let canManage: Bool
    var setRole: (GroupShare, Role) async throws -> Void
    var remove: (GroupShare) async throws -> Void
    @State private var busy: String?
    @State private var error: String?

    var body: some View {
        Section {
            ForEach(groups) { share in
                AccessRow(name: share.name, note: share.isMine ? "(you're in it)" : nil) {
                    GroupTile(size: 24)
                } trailing: {
                    if busy == share.groupId {
                        ProgressView().controlSize(.small)
                    }
                    if canManage {
                        RoleMenu(
                            role: share.role, removeTitle: "Remove \(share.name)",
                            setRole: { role in
                                guard role != share.role else { return }
                                run(share) { try await setRole(share, role) }
                            },
                            remove: { run(share) { try await remove(share) } })
                    } else {
                        Text(share.role.label)
                            .foregroundStyle(.secondary)
                    }
                }
                .disabled(busy != nil)
            }
        } header: {
            Text(groups.count == 1 ? "1 group" : "\(groups.count) groups")
        } footer: {
            if let error {
                FormFooter(error, color: .red)
            }
        }
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
            if model.folders.contains(where: { $0.hasPrefix(folder + FolderNode.separator) }) {
                Text("Folders inside it have their own access: sharing this one doesn't share them.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let sharing {
                Form {
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
                            },
                            removeTitle: { $0.isMe ? "Leave \u{201C}\(folder)\u{201D}" : "Remove \($0.name)" })
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
                }
                .sheetForm(height: sharing.people.count + sharing.groups.count > 8 ? 480 : nil)
            } else if problem == nil {
                ProgressView()
                    .controlSize(.small)
                    .frame(maxWidth: .infinity, minHeight: 100)
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
        .frame(width: 500)
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
                Button(role: .destructive) {
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
                } label: {
                    Text("Remove")
                        .foregroundStyle(.red)
                }
                .disabled(busy)
            }
        }
        .padding(20)
        .frame(width: 460)
    }
}

// MARK: - Folders

/// A new folder, or one inside another, which starts out shared like its parent unless
/// asked not to. After that, each folder has its own access.
private struct NewFolderSheet: View {
    let model: AppModel
    let parent: String?
    @State private var name = ""
    @State private var shareLikeParent = true
    @State private var parentSharing: Sharing?

    private var fullName: String {
        parent.map { "\($0)\(FolderNode.separator)\(name.trimmed)" } ?? name.trimmed
    }
    private var exists: Bool { model.folders.contains(fullName) }

    var body: some View {
        SheetScaffold(
            title: parent.map { "New Folder in \u{201C}\($0)\u{201D}" } ?? "New Folder",
            actionTitle: "Create", canAct: !name.trimmed.isEmpty && !exists
        ) {
            if let parent {
                try await model.createFolder(named: name, inside: parent, shareLikeParent: shareLikeParent)
            } else {
                try await model.createFolder(named: name)
            }
            return true
        } content: {
            Form {
                TextField("Name", text: $name, prompt: Text(parent == nil ? "Production" : "Databases"))
                if let parent {
                    Toggle("Share it like \u{201C}\(parent)\u{201D}", isOn: $shareLikeParent)
                }
            }
            .sheetForm()
            Text(caption)
                .font(.caption)
                .foregroundStyle(exists ? AnyShapeStyle(.orange) : AnyShapeStyle(.secondary))
                .fixedSize(horizontal: false, vertical: true)
        }
        .task {
            if let parent { parentSharing = try? await model.sharing(of: parent) }
        }
    }

    private var caption: String {
        if exists { return "There's already a folder with that name." }
        guard let parent, shareLikeParent else {
            return "Only you can see a new folder until you share it."
        }
        guard let parentSharing else {
            return "It starts out shared like its parent; after that, each has its own access."
        }
        let others = parentSharing.people.filter { !$0.isMe }
            .map { "\($0.name) (\($0.role.label.lowercased()))" }
            + parentSharing.groups.map { "\($0.name) (group, \($0.role.label.lowercased()))" }
        if others.isEmpty {
            return "\u{201C}\(parent)\u{201D} isn't shared with anyone else, so neither is this."
        }
        return "Shared with " + ListFormatter.localizedString(byJoining: others)
            + ". After that, each folder has its own access: sharing one doesn't share the other."
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
                .sheetForm()
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
            .sheetForm()
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
                        .multilineTextAlignment(.leading)
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
                .sheetForm()
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
            .sheetForm()
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
                Text("Send it to \(name.trimmed) directly, for example in a private message. It "
                    + "works once.")
                    .fixedSize(horizontal: false, vertical: true)
                Form {
                    Section {
                        LineRow(line: invitation.command) { model.copy(invitation.command) }
                    } footer: {
                        FormFooter("They paste it into Keystead's welcome screen. Once they've joined, "
                            + "they show up under People: approve them after they read you their "
                            + "fingerprint.")
                    }
                }
                .sheetForm()
            } else {
                Form {
                    TextField("Name", text: $name, prompt: Text("As your team will see them"))
                }
                .sheetForm()
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
                CodeField("Fingerprint", text: $fingerprint)
            }
            .sheetForm()
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
                Button(role: .destructive) {
                    Task { await signOut() }
                } label: {
                    Text("Sign Out")
                        .foregroundStyle(.red)
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

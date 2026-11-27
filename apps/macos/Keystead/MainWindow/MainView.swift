import AppKit
import SwiftUI

/// The main window. What it shows follows the app's phase.
struct MainView: View {
    @Bindable var model: AppModel

    var body: some View {
        Group {
            switch model.phase {
            case .welcome:
                WelcomeView(model: model)
            case .working(let what):
                VStack(spacing: 18) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable()
                        .frame(width: 64, height: 64)
                    ProgressView(what)
                        .controlSize(.small)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            case .locked:
                LockedView(model: model)
            case .unlocked:
                VaultView(model: model)
            }
        }
        .frame(minWidth: 760, minHeight: 480)
        .sheet(item: $model.sheet) { sheet in
            SheetContent(sheet: sheet, model: model)
                // Each sheet glides to its new height as it loads or moves to its next step.
                .windowFollowsHeight()
        }
    }
}

/// First launch: a choice of how to start, then the form for it.
struct WelcomeView: View {
    @Bindable var model: AppModel
    @State private var invite = ""
    @State private var setupLine = ""
    @State private var ownerFingerprint = ""
    @State private var recoveryWords = Array(repeating: "", count: 24)
    /// The recovery words are masked while typed, unless the user chooses to see them.
    @State private var showsWords = false
    @State private var server = ""
    @State private var setupCode = ""
    @State private var name = ""
    @State private var recoveryLine = ""

    var body: some View {
        ScrollView {
            VStack(spacing: 28) {
                hero
                content
                    .frame(maxWidth: model.welcomePage == .recover ? 560 : 500)
                if let message = model.message {
                    Label(message, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .frame(maxWidth: 500, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if model.welcomePage == .start {
                    Text("\(appName) keeps this Mac's keys in its Secure Enclave. You'll confirm "
                        + "with Touch ID or your Mac password.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 420)
                }
            }
            .padding(.horizontal, 40)
            .padding(.vertical, 44)
            .frame(maxWidth: .infinity)
        }
        .animation(.snappy(duration: 0.22), value: model.welcomePage)
    }

    private var hero: some View {
        VStack(spacing: 8) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: model.welcomePage == .start ? 96 : 64, height: model.welcomePage == .start ? 96 : 64)
            Text(model.welcomePage == .start ? "Welcome to \(appName)" : title(of: model.welcomePage))
                .font(model.welcomePage == .start ? .largeTitle.weight(.semibold) : .title.weight(.semibold))
            if model.welcomePage == .start {
                Text("Your team's passwords, shared safely.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var content: some View {
        if let code = model.joiningCode {
            waitingForOtherDevice(code: code)
        } else if let claim = model.recoveryClaim {
            waitingForOwner(claim: claim)
        } else if model.recoveryNeedsFinishing {
            finishRecovering
        } else {
            switch model.welcomePage {
            case .start: choices
            case .join: joinForm
            case .setUp: setUpForm
            case .addThisMac: addThisMacForm
            case .recover: recoverForm
            case .recoverWithHelp: recoverWithHelpForm
            }
        }
    }

    private func title(of page: AppModel.WelcomePage) -> String {
        switch page {
        case .start: "Welcome to \(appName)"
        case .join: "Join Your Team"
        case .setUp: "Set Up a New Team"
        case .addThisMac: "Add This Mac"
        case .recover: "Recover Your Account"
        case .recoverWithHelp: "Recover with Your Owner's Help"
        }
    }

    // MARK: Choices

    private var choices: some View {
        Card(padded: false) {
            ChoiceRow(
                icon: "person.badge.plus", tint: .blue, title: "Join a team",
                subtitle: "With the invite your team's owner sent you."
            ) { model.welcomePage = .join }
            Divider().padding(.leading, 64)
            ChoiceRow(
                icon: "server.rack", tint: .indigo, title: "Set up a new team",
                subtitle: "For whoever runs your team's server. You become its owner."
            ) { model.welcomePage = .setUp }
            Divider().padding(.leading, 64)
            ChoiceRow(
                icon: "laptopcomputer.and.arrow.down", tint: .teal, title: "Add this Mac",
                subtitle: "Already use \(appName) on another device? Bring your account here."
            ) { model.welcomePage = .addThisMac }
            Divider().padding(.leading, 64)
            ChoiceRow(
                icon: "lifepreserver", tint: .orange, title: "Recover your account",
                subtitle: "With your Recovery Kit, or your team owner's help."
            ) { model.welcomePage = .recover }
        }
    }

    // MARK: Forms

    private var joinForm: some View {
        FormPage(model: model) {
            Card {
                LineField(text: $invite, prompt: "keystead join https://… --owner …")
            }
            Footnote("Paste the whole invite, as your team's owner sent it.")
        } actions: {
            Button("Join") { Task { await model.join(invite: invite) } }
                .disabled(invite.trimmed.isEmpty)
        }
    }

    private var setUpForm: some View {
        FormPage(model: model) {
            Card {
                FieldRow("Server address") {
                    TextField("Server address", text: $server, prompt: Text("https://keys.example.com"))
                }
                Divider()
                FieldRow("Setup code") {
                    TextField("Setup code", text: $setupCode, prompt: Text("From the server's log"))
                        .font(.system(.body, design: .monospaced))
                }
                Divider()
                FieldRow("Your name") {
                    TextField("Your name", text: $name, prompt: Text("As your team will see it"))
                }
            }
            if let serverProblem {
                Footnote(serverProblem)
                    .foregroundStyle(.orange)
            }
            Footnote("The server prints its setup code once, the first time it starts; with "
                + "Docker, `docker compose logs server` shows it. You'll invite people, approve "
                + "them and make groups.")
        } actions: {
            Button("Set Up") {
                Task { await model.setUp(server: server, setupCode: setupCode, name: name) }
            }
            .disabled(!serverUsable || setupCode.trimmed.isEmpty || name.trimmed.isEmpty)
        }
    }

    /// Adds this Mac to an account another device already has: paste the line it shows.
    private var addThisMacForm: some View {
        FormPage(model: model) {
            Card {
                LineField(text: $setupLine, prompt: "keystead add-device https://… --owner …")
            }
            Footnote("On your other device, open your own page under People and choose Add a "
                + "Device, then paste the line it shows here.")
            Button("No other device? Recover with your Recovery Kit.") {
                model.welcomePage = .recover
            }
            .buttonStyle(.link)
            .font(.callout)
        } actions: {
            Button("Continue") { model.startAddingThisMac(line: setupLine) }
                .disabled(setupLine.trimmed.isEmpty)
        }
    }

    private var recoverForm: some View {
        FormPage(model: model) {
            Card {
                FieldRow("Server address") {
                    TextField("Server address", text: $server, prompt: Text("https://keys.example.com"))
                }
                Divider()
                FieldRow("Owner's fingerprint") {
                    TextField("Owner's fingerprint", text: $ownerFingerprint, prompt: Text("From your Recovery Kit"))
                        .font(.system(.body, design: .monospaced))
                        .autocorrectionDisabled()
                }
            }
            if let serverProblem {
                Footnote(serverProblem)
                    .foregroundStyle(.orange)
            }
            Footnote("Leave the fingerprint empty if you're your team's owner.")
            HStack {
                Text("The 24 words")
                    .font(.headline)
                Spacer()
                Button {
                    showsWords.toggle()
                } label: {
                    Label(showsWords ? "Hide" : "Show", systemImage: showsWords ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .help(showsWords ? "Hide the words" : "Show the words")
            }
            .padding(.top, 6)
            Card {
                RecoveryWordsInput(words: $recoveryWords, hidden: !showsWords)
            }
            Footnote("In order, as numbered on your Recovery Kit. Paste all 24 into the first box, "
                + "or type them: a space moves on to the next box.")
            Button("No Recovery Kit? Recover with your team owner's help.") {
                model.welcomePage = .recoverWithHelp
            }
            .buttonStyle(.link)
            .font(.callout)
        } actions: {
            Button("Recover") {
                Task {
                    await model.recover(
                        server: server, ownerFingerprint: ownerFingerprint,
                        words: recoveryWords.joined(separator: " "))
                }
            }
            .disabled(!serverUsable || recoveryWords.contains { $0.trimmed.isEmpty })
        }
    }

    /// Recovering when every device and the Recovery Kit are gone: with a line from the owner.
    private var recoverWithHelpForm: some View {
        FormPage(model: model, back: .recover) {
            Card {
                LineField(text: $recoveryLine, prompt: "keystead recover-with-help https://… --owner …")
            }
            Footnote("Lost every device and your Recovery Kit? Ask your team's owner to help you "
                + "recover, then paste the line they send you. You'll get new keys: what's "
                + "shared with you comes back, and your own logins and folders too if you let "
                + "the owner keep them in escrow.")
        } actions: {
            Button("Continue") { model.startRecoveringWithHelp(line: recoveryLine) }
                .disabled(recoveryLine.trimmed.isEmpty)
        }
    }

    // MARK: Waiting

    /// The code to type on the other device, while this Mac waits for its account.
    private func waitingForOtherDevice(code: String) -> some View {
        WaitingCard(
            lead: "On your other device, type this code:", code: code,
            note: "It checks that your account goes to this Mac and nowhere else. Once you've "
                + "typed it there, this Mac adds itself.",
            status: "Waiting for your other device…"
        ) {
            model.cancelAddingThisMac()
        }
    }

    /// The new fingerprint to read to the owner, while this Mac waits for their approval.
    private func waitingForOwner(claim: RecoveryClaimInfo) -> some View {
        WaitingCard(
            lead: "Read this fingerprint to your team's owner, in person or on a call:",
            code: claim.fingerprint,
            note: "It proves these new keys for \(claim.name) are really yours. Once the owner "
                + "approves them, this Mac signs in, and your old devices stop working.",
            status: model.recoveryUnreachable
                ? "Can't reach the server; still trying…" : "Waiting for the owner…"
        ) {
            model.cancelRecoveringWithHelp()
        }
    }

    /// The owner approved this Mac's new keys, but finishing didn't work out the first time.
    private var finishRecovering: some View {
        Card {
            VStack(spacing: 14) {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 34))
                    .foregroundStyle(.green)
                Text("The owner approved your new keys.")
                    .font(.headline)
                Text("Finish with Touch ID to sign in on this Mac. If you start over, the owner "
                    + "has to send you a new line.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Start Over") { model.forgetApprovedRecovery() }
                    Button("Finish Recovering") {
                        Task { await model.finishRecoveringWithHelp() }
                    }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                }
                .controlSize(.large)
            }
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity)
        }
    }

    /// Why the address typed in can't be used, as the core checks it: https://, or
    /// http:// for a server on this Mac. Nothing until something is typed.
    private var serverProblem: String? {
        guard !server.trimmed.isEmpty, let problem = serverAddressProblem(server: server) else {
            return nil
        }
        return problem.prefix(1).uppercased() + problem.dropFirst() + "."
    }

    private var serverUsable: Bool { !server.trimmed.isEmpty && serverProblem == nil }
}

/// One way to start: an icon, what it is, and a line about it.
private struct ChoiceRow: View {
    let icon: String
    let tint: Color
    let title: String
    let subtitle: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: icon)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 34, height: 34)
                    .background(tint.gradient, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.headline)
                    Text(subtitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Image(systemName: "chevron.right")
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .contentShape(Rectangle())
            .background(hovering ? Color.primary.opacity(0.05) : .clear)
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}

/// A welcome page's form: a way back to the choices, the content, and its main button on
/// the right.
private struct FormPage<Content: View, Actions: View>: View {
    let model: AppModel
    var back: AppModel.WelcomePage = .start
    @ViewBuilder let content: Content
    @ViewBuilder let actions: Actions

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            content
            HStack {
                Button {
                    model.dismissMessage()
                    model.welcomePage = back
                } label: {
                    Label("Back", systemImage: "chevron.left")
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                actions
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
            .controlSize(.large)
            .padding(.top, 12)
        }
    }
}

/// Rows on a rounded card, as a grouped form shows them, for pages that scroll as a whole.
struct Card<Content: View>: View {
    var padded = true
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: padded ? 10 : 0) {
            content
        }
        .padding(padded ? 14 : 0)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(.separator.opacity(0.6), lineWidth: 0.5)
        }
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

/// A labelled field on a card: the label on the left, the field filling the right.
private struct FieldRow<Field: View>: View {
    let label: String
    @ViewBuilder let field: Field

    init(_ label: String, @ViewBuilder field: () -> Field) {
        self.label = label
        self.field = field()
    }

    var body: some View {
        LabeledContent(label) {
            field
                .textFieldStyle(.plain)
                .multilineTextAlignment(.trailing)
                .labelsHidden()
        }
    }
}

/// A line to paste, like an invite: monospaced, a few lines tall.
private struct LineField: View {
    @Binding var text: String
    let prompt: String

    var body: some View {
        TextField("", text: $text, prompt: Text(prompt), axis: .vertical)
            .textFieldStyle(.plain)
            .font(.system(.body, design: .monospaced))
            .lineLimit(3...5)
    }
}

/// A note under a card, as a grouped form's footer.
struct Footnote: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(.init(text))
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 4)
    }
}

/// While this Mac waits on someone: what to tell them, big and monospaced, and a way out.
private struct WaitingCard: View {
    let lead: String
    let code: String
    let note: String
    let status: String
    let cancel: () -> Void

    var body: some View {
        Card {
            VStack(spacing: 16) {
                Text(lead)
                    .multilineTextAlignment(.center)
                Text(code)
                    .font(.system(.title, design: .monospaced).weight(.semibold))
                    .textSelection(.enabled)
                    .padding(.horizontal, 18)
                    .padding(.vertical, 10)
                    .background(.background, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                Text(note)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    ProgressView()
                        .controlSize(.small)
                    Text(status)
                        .foregroundStyle(.secondary)
                }
                Button("Cancel", action: cancel)
                    .keyboardShortcut(.cancelAction)
            }
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity)
        }
    }
}

struct LockedView: View {
    let model: AppModel

    var body: some View {
        VStack(spacing: 14) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 80, height: 80)
                .overlay(alignment: .bottomTrailing) {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundStyle(.white)
                        .frame(width: 30, height: 30)
                        .background(.gray.gradient, in: Circle())
                        .overlay { Circle().strokeBorder(.background, lineWidth: 2.5) }
                        .offset(x: 4, y: 4)
                }
            VStack(spacing: 4) {
                Text("\(appName) Is Locked")
                    .font(.title2.weight(.semibold))
                Text(model.lockNote ?? "Unlock to see your logins.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 380)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Button {
                Task { await model.unlock() }
            } label: {
                Label("Unlock with Touch ID", systemImage: "touchid")
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            .padding(.top, 4)
            // Not when it locked itself: the message is then what that stopped, like a sync.
            if model.lockNote == nil, let message = model.message {
                Text(message)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 380)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}

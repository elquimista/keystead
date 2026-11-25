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
                ProgressView(what)
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
        }
    }
}

/// First launch: join a team with an invite, or set up a new one as its owner.
struct WelcomeView: View {
    private enum Choice: Hashable {
        case join, setUp, addThisMac, recover
    }

    let model: AppModel
    @State private var choice = WelcomeView.initialChoice
    @State private var invite = ""
    @State private var setupLine = ""
    @State private var ownerFingerprint = ""
    @State private var recoveryWords = Array(repeating: "", count: 24)
    /// The recovery words are masked while typed, unless the user chooses to see them.
    @State private var showsWords = false
    @State private var server = ""
    @State private var setupCode = ""
    @State private var name = ""
    /// Recovering with the owner's help instead of a Recovery Kit.
    @State private var withHelp = WelcomeView.initialWithHelp
    @State private var recoveryLine = ""

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                VStack(spacing: 8) {
                    Image(nsImage: NSApp.applicationIconImage)
                        .resizable()
                        .frame(width: 96, height: 96)
                    Text("Welcome to \(appName)")
                        .font(.largeTitle.weight(.semibold))
                    Text("Your team's passwords, shared safely.")
                        .foregroundStyle(.secondary)
                }
                if let code = model.joiningCode {
                    waitingForOtherDevice(code: code)
                        .frame(width: 480)
                } else if let claim = model.recoveryClaim {
                    waitingForOwner(claim: claim)
                        .frame(width: 480)
                } else {
                    Picker("", selection: $choice) {
                        Text("Join a team").tag(Choice.join)
                        Text("Set up a new team").tag(Choice.setUp)
                        Text("Add this Mac").tag(Choice.addThisMac)
                        Text("Recover an account").tag(Choice.recover)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 560)

                    Group {
                        switch choice {
                        case .join: joinForm
                        case .setUp: setUpForm
                        case .addThisMac: addThisMacForm
                        case .recover: withHelp ? recoverWithHelpForm : AnyView(recoverForm)
                        }
                    }
                    // Recovering takes 24 word boxes; give them room.
                    .frame(width: choice == .recover && !withHelp ? 560 : 480)
                }

                if let message = model.message {
                    Label(message, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .frame(width: 480, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text("Keystead keeps this Mac's keys in its Secure Enclave. You'll confirm with "
                    + "Touch ID or your Mac password.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(width: 420)
            }
            .padding(40)
            .frame(maxWidth: .infinity)
        }
    }

    private var joinForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Paste the invite your team's owner sent you.")
            TextField(
                "", text: $invite, prompt: Text("keystead join https://… --owner …"), axis: .vertical
            )
            .textFieldStyle(.roundedBorder)
            .font(.system(.body, design: .monospaced))
            .lineLimit(3...5)
            HStack {
                Spacer()
                Button("Join") {
                    Task { await model.join(invite: invite) }
                }
                .keyboardShortcut(.defaultAction)
                .controlSize(.large)
                .disabled(invite.trimmed.isEmpty)
            }
        }
    }

    /// Adds this Mac to an account another device already has: paste the line it shows.
    private var addThisMacForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Already use Keystead on another Mac or computer? There, choose Add a Device "
                + "(under People, on your own page), then paste the line it shows here.")
                .fixedSize(horizontal: false, vertical: true)
            TextField(
                "", text: $setupLine, prompt: Text("keystead add-device https://… --owner …"),
                axis: .vertical
            )
            .textFieldStyle(.roundedBorder)
            .font(.system(.body, design: .monospaced))
            .lineLimit(3...5)
            HStack {
                Text("No other device? Recover with your Recovery Kit instead.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Continue") { model.startAddingThisMac(line: setupLine) }
                    .keyboardShortcut(.defaultAction)
                    .controlSize(.large)
                    .disabled(setupLine.trimmed.isEmpty)
            }
        }
    }

    /// The code to type on the other device, while this Mac waits for its account.
    private func waitingForOtherDevice(code: String) -> some View {
        VStack(spacing: 14) {
            Text("On your other device, type this code:")
            Text(code)
                .font(.system(.title, design: .monospaced).weight(.semibold))
                .textSelection(.enabled)
            Text("It checks that your account goes to this Mac and nowhere else. Once you've "
                + "typed it there, this Mac adds itself.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                ProgressView()
                    .controlSize(.small)
                Text("Waiting for your other device…")
                    .foregroundStyle(.secondary)
            }
            Button("Cancel") { model.cancelAddingThisMac() }
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }

    private var setUpForm: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("For whoever runs your team's Keystead server. You'll become your team's owner: "
                + "you invite people, approve them and make groups.")
                .fixedSize(horizontal: false, vertical: true)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 12) {
                GridRow {
                    Text("Server address")
                        .gridColumnAlignment(.trailing)
                    VStack(alignment: .leading, spacing: 4) {
                        TextField("", text: $server, prompt: Text("https://keys.example.com"))
                            .textFieldStyle(.roundedBorder)
                        if !server.trimmed.isEmpty && !hasScheme {
                            Text("Start with https://, or http:// for a server on this Mac.")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                    }
                }
                GridRow {
                    Text("Setup code")
                    VStack(alignment: .leading, spacing: 4) {
                        TextField("", text: $setupCode, prompt: Text("From the server's log"))
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                        Text("The server prints it once, the first time it starts. With Docker: "
                            + "docker compose logs server")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
                GridRow {
                    Text("Your name")
                    TextField("", text: $name, prompt: Text("As your team will see it"))
                        .textFieldStyle(.roundedBorder)
                }
            }
            HStack {
                Spacer()
                Button("Set Up") {
                    Task { await model.setUp(server: server, setupCode: setupCode, name: name) }
                }
                .keyboardShortcut(.defaultAction)
                .controlSize(.large)
                .disabled(!hasScheme || setupCode.trimmed.isEmpty || name.trimmed.isEmpty)
            }
        }
    }

    private var recoverForm: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Bring your account back on this Mac with your Recovery Kit, for example after "
                + "your old Mac was lost or replaced.")
                .fixedSize(horizontal: false, vertical: true)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 12) {
                GridRow {
                    Text("Server address")
                        .gridColumnAlignment(.trailing)
                    TextField("", text: $server, prompt: Text("https://keys.example.com"))
                        .textFieldStyle(.roundedBorder)
                }
                GridRow {
                    Text("Owner's fingerprint")
                    VStack(alignment: .leading, spacing: 4) {
                        TextField("", text: $ownerFingerprint, prompt: Text("From your Recovery Kit"))
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))
                            .autocorrectionDisabled()
                        Text("Leave it empty if you're your team's owner.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("The 24 words")
                    Spacer()
                    Button {
                        showsWords.toggle()
                    } label: {
                        Label(showsWords ? "Hide" : "Show",
                              systemImage: showsWords ? "eye.slash" : "eye")
                    }
                    .buttonStyle(.borderless)
                    .help(showsWords ? "Hide the words" : "Show the words")
                }
                RecoveryWordsInput(words: $recoveryWords, hidden: !showsWords)
                Text("In order, as numbered on your Recovery Kit. Paste all 24 into the first "
                    + "box, or type them: a space moves on to the next box.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button("No Recovery Kit?") { withHelp = true }
                    .buttonStyle(.link)
                    .help("Recover with your team owner's help instead")
                Spacer()
                Button("Recover") {
                    Task {
                        await model.recover(
                            server: server, ownerFingerprint: ownerFingerprint,
                            words: recoveryWords.joined(separator: " "))
                    }
                }
                .keyboardShortcut(.defaultAction)
                .controlSize(.large)
                .disabled(!hasScheme || recoveryWords.contains { $0.trimmed.isEmpty })
            }
        }
    }

    /// Recovering when every device and the Recovery Kit are gone: with a line from the owner.
    private var recoverWithHelpForm: AnyView {
        AnyView(VStack(alignment: .leading, spacing: 10) {
            Text("Lost every device and your Recovery Kit? Ask your team's owner to help you "
                + "recover, then paste the line they send you. You'll get new keys: what's "
                + "shared with you comes back, and your own logins and folders too if you let "
                + "the owner keep them in escrow.")
                .fixedSize(horizontal: false, vertical: true)
            TextField(
                "", text: $recoveryLine,
                prompt: Text("keystead recover-with-help https://… --owner …"), axis: .vertical
            )
            .textFieldStyle(.roundedBorder)
            .font(.system(.body, design: .monospaced))
            .lineLimit(3...5)
            HStack {
                Button("Use my Recovery Kit") { withHelp = false }
                    .buttonStyle(.link)
                Spacer()
                Button("Continue") { model.startRecoveringWithHelp(line: recoveryLine) }
                    .keyboardShortcut(.defaultAction)
                    .controlSize(.large)
                    .disabled(recoveryLine.trimmed.isEmpty)
            }
        })
    }

    /// The new fingerprint to read to the owner, while this Mac waits for their approval.
    private func waitingForOwner(claim: RecoveryClaimInfo) -> some View {
        VStack(spacing: 14) {
            Text("Read this fingerprint to your team's owner, in person or on a call:")
                .multilineTextAlignment(.center)
            Text(claim.fingerprint)
                .font(.system(.title2, design: .monospaced).weight(.semibold))
                .textSelection(.enabled)
            Text("It proves these new keys for \(claim.name) are really yours. Once the owner "
                + "approves them, this Mac signs in, and your old devices stop working.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 8) {
                ProgressView()
                    .controlSize(.small)
                Text("Waiting for the owner…")
                    .foregroundStyle(.secondary)
            }
            Button("Cancel") { model.cancelRecoveringWithHelp() }
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
    }

    /// Join, unless a Debug build was launched with `-welcome setup` or `-welcome recover`.
    private static var initialChoice: Choice {
        #if DEBUG
        let arguments = CommandLine.arguments
        if let index = arguments.firstIndex(of: "-welcome"), index + 1 < arguments.count {
            switch arguments[index + 1] {
            case "setup": return .setUp
            case "add": return .addThisMac
            case "recover", "recover-help": return .recover
            default: break
            }
        }
        #endif
        return .join
    }

    /// The owner's-help form, if a Debug build was launched with `-welcome recover-help`.
    private static var initialWithHelp: Bool {
        #if DEBUG
        CommandLine.arguments.contains("recover-help")
        #else
        false
        #endif
    }

    private var hasScheme: Bool {
        let server = server.trimmed.lowercased()
        return server.hasPrefix("https://") || server.hasPrefix("http://")
    }
}

struct LockedView: View {
    let model: AppModel

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.fill")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text("\(appName) is locked")
                .font(.title2.weight(.semibold))
            Button {
                Task { await model.unlock() }
            } label: {
                Label("Unlock with Touch ID", systemImage: "touchid")
            }
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
            if let message = model.message {
                Text(message)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}

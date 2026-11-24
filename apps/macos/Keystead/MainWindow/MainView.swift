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
        case join, setUp, recover
    }

    let model: AppModel
    @State private var choice = WelcomeView.initialChoice
    @State private var invite = ""
    @State private var ownerFingerprint = ""
    @State private var words = ""
    @State private var server = ""
    @State private var setupCode = ""
    @State private var name = ""

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
                Picker("", selection: $choice) {
                    Text("Join a team").tag(Choice.join)
                    Text("Set up a new team").tag(Choice.setUp)
                    Text("Recover an account").tag(Choice.recover)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 480)

                Group {
                    switch choice {
                    case .join: joinForm
                    case .setUp: setUpForm
                    case .recover: recoverForm
                    }
                }
                .frame(width: 480)

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
            Text("Paste the invite your admin sent you.")
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

    private var setUpForm: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("For whoever runs your team's Keystead server. You'll become its owner: you "
                + "invite people, approve them, and decide who sees which folders.")
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
                    TextField("", text: $ownerFingerprint, prompt: Text("From your Recovery Kit"))
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                }
                GridRow(alignment: .top) {
                    Text("The 24 words")
                    TextField(
                        "", text: $words, prompt: Text("In order, as on your Recovery Kit"),
                        axis: .vertical
                    )
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(2...8)
                }
            }
            HStack {
                Spacer()
                Button("Recover") {
                    Task {
                        await model.recover(
                            server: server, ownerFingerprint: ownerFingerprint, words: words)
                    }
                }
                .keyboardShortcut(.defaultAction)
                .controlSize(.large)
                .disabled(!hasScheme || ownerFingerprint.trimmed.isEmpty || words.trimmed.isEmpty)
            }
        }
    }

    /// Join, unless a Debug build was launched with `-welcome setup` or `-welcome recover`.
    private static var initialChoice: Choice {
        #if DEBUG
        let arguments = CommandLine.arguments
        if let index = arguments.firstIndex(of: "-welcome"), index + 1 < arguments.count {
            switch arguments[index + 1] {
            case "setup": return .setUp
            case "recover": return .recover
            default: break
            }
        }
        #endif
        return .join
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

import AppKit
import PDFKit
import SwiftUI

/// Shows the recovery kit after Touch ID, and prints or copies it. The words stay hidden
/// until asked for, in case someone is looking over the user's shoulder. Right after setup it
/// first explains why the kit matters, since the owner's account then exists only on this Mac.
struct RecoveryKitSheet: View {
    let model: AppModel
    let afterSetup: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var kit: RecoveryKit?
    @State private var error: String?
    @State private var loading = false
    @State private var revealed = false
    /// When the words were last copied, while the clipboard still holds them.
    @State private var copiedAt: Date?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let kit {
                Text("Your Recovery Kit")
                    .font(.title3.weight(.semibold))
                Text("Print this page, or write the 24 words down by hand, and keep it somewhere "
                    + "safe and offline. With it, you can bring your account back on a new Mac.")
                    .fixedSize(horizontal: false, vertical: true)
                RecoveryKitWords(words: kit.words, hidden: !revealed)
                HStack(spacing: 12) {
                    Button {
                        revealed.toggle()
                    } label: {
                        Label(revealed ? "Hide Words" : "Show Words",
                              systemImage: revealed ? "eye.slash" : "eye")
                    }
                    Button {
                        model.copyRecoveryWords(of: kit)
                        copiedAt = .now
                    } label: {
                        Label("Copy Words", systemImage: "doc.on.doc")
                    }
                    .help("Copy only the 24 words, to this Mac's clipboard")
                    if copiedAt != nil {
                        Text("Copied to this Mac only. The clipboard clears in 30 seconds.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .task(id: copiedAt) {
                    guard copiedAt != nil else { return }
                    try? await Task.sleep(for: SecureClipboard.clearAfter)
                    if !Task.isCancelled { copiedAt = nil }
                }
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12, verticalSpacing: 6) {
                    GridRow {
                        Text("Server").foregroundStyle(.secondary)
                        Text(kit.server)
                    }
                    GridRow {
                        Text("Owner's fingerprint").foregroundStyle(.secondary)
                        Text(kit.ownerFingerprint + (kit.ownerFingerprint == kit.fingerprint ? " (you)" : ""))
                            .font(.system(.body, design: .monospaced))
                    }
                }
                Text("Anyone with these words can be you on \(host(kit.server)). Don't photograph "
                    + "them. If you copy them, paste them only somewhere as safe as Keystead, like "
                    + "an encrypted vault, never into a note, chat or email.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button("Print…") { printRecoveryKit(kit) }
                    Button("Done") { dismiss() }
                        .keyboardShortcut(.defaultAction)
                }
            } else {
                Text(afterSetup ? "Save Your Recovery Kit" : "Recovery Kit")
                    .font(.title3.weight(.semibold))
                Text(
                    afterSetup
                        ? "Your owner account exists only on this Mac. If it's lost, broken or "
                            + "wiped, the Recovery Kit is the only way back: without it, nobody "
                            + "could invite or approve people on your server again."
                        : "If this Mac is lost, broken or wiped, your Recovery Kit brings your "
                            + "account back on a new one."
                )
                .fixedSize(horizontal: false, vertical: true)
                Text("It's 24 words. Print them or write them down, and keep the page somewhere "
                    + "safe and offline, like a safe.")
                    .fixedSize(horizontal: false, vertical: true)
                if let error {
                    Label(error, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    if loading {
                        ProgressView().controlSize(.small)
                    }
                    Spacer()
                    Button(afterSetup ? "Later" : "Cancel") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                    Button("Show Recovery Kit") { Task { await load() } }
                        .keyboardShortcut(.defaultAction)
                        .disabled(loading)
                }
            }
        }
        .padding(20)
        .frame(width: 540)
        #if DEBUG
        .task {
            // Demo snapshots show the kit itself; there's no Touch ID to wait for.
            if model.isDemo && !afterSetup { await load() }
        }
        #endif
    }

    private func load() async {
        loading = true
        error = nil
        do {
            kit = try await model.recoveryKit()
        } catch let failure {
            error = describe(failure)
        }
        loading = false
    }
}

/// The 24 words in six rows of four, numbered across the rows so they read in order like
/// text. Hidden, each shows as the same row of dots, so not even word lengths show.
struct RecoveryKitWords: View {
    let words: [String]
    var hidden = false
    var fontSize: CGFloat = 13

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 20, verticalSpacing: 8) {
            ForEach(0..<6, id: \.self) { row in
                GridRow {
                    ForEach(0..<4, id: \.self) { column in
                        let index = row * 4 + column
                        let word = index < words.count ? words[index] : ""
                        HStack(spacing: 6) {
                            Text("\(index + 1)")
                                .font(.system(size: fontSize - 2).monospacedDigit())
                                .foregroundStyle(.secondary)
                                .frame(width: 20, alignment: .trailing)
                            Text(hidden ? "••••••••" : word)
                                .font(.system(size: fontSize, design: .monospaced))
                                .foregroundStyle(hidden ? .secondary : .primary)
                                .accessibilityLabel(hidden ? "Hidden" : word)
                        }
                    }
                }
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
    }
}

/// 24 numbered boxes for entering the recovery words, laid out like the kit. Pasting several
/// words into a box fills it and the boxes after it, and typing a space moves on to the
/// next box. Masked unless `hidden` is false.
struct RecoveryWordsInput: View {
    @Binding var words: [String]
    let hidden: Bool
    @FocusState private var focused: Int?

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
            ForEach(0..<6, id: \.self) { row in
                GridRow {
                    ForEach(0..<4, id: \.self) { column in
                        let index = row * 4 + column
                        HStack(spacing: 6) {
                            Text("\(index + 1)")
                                .font(.callout.monospacedDigit())
                                .foregroundStyle(.secondary)
                                .frame(width: 20, alignment: .trailing)
                            box(index)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func box(_ index: Int) -> some View {
        let text = Binding(get: { words[index] }, set: { enter($0, at: index) })
        Group {
            if hidden {
                SecureField("", text: text)
            } else {
                TextField("", text: text)
                    // Spelling correction could swap one valid word for another.
                    .autocorrectionDisabled()
            }
        }
        .textFieldStyle(.roundedBorder)
        .font(.system(.body, design: .monospaced))
        .focused($focused, equals: index)
        .accessibilityLabel("Word \(index + 1)")
    }

    private func enter(_ text: String, at index: Int) {
        guard text.contains(where: \.isWhitespace) else {
            words[index] = text
            return
        }
        let parts = text.split(whereSeparator: \.isWhitespace).map(String.init)
        words[index] = parts.first ?? ""
        for (offset, part) in parts.enumerated().dropFirst() where index + offset < words.count {
            words[index + offset] = part
        }
        // Move on, and leave the box either way: a box still being edited may keep showing
        // everything that was pasted into it.
        if !parts.isEmpty {
            let next = index + parts.count
            focused = next < words.count ? next : nil
        }
    }
}

/// The printed recovery kit: one US Letter page, black on white.
struct RecoveryKitPage: View {
    let kit: RecoveryKit
    let printed: Date

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 12) {
                Image(nsImage: NSApp.applicationIconImage)
                    .resizable()
                    .frame(width: 52, height: 52)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Keystead Recovery Kit")
                        .font(.system(size: 24, weight: .bold))
                    Text("For \(kit.name) on \(kit.server), printed "
                        + printed.formatted(date: .long, time: .omitted))
                        .font(.system(size: 11))
                }
            }
            Divider()
            Text("Your 24 words")
                .font(.system(size: 13, weight: .semibold))
            RecoveryKitWords(words: kit.words, fontSize: 15)
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 6) {
                GridRow {
                    Text("Server address").font(.system(size: 11, weight: .semibold))
                    Text(kit.server).font(.system(size: 12, design: .monospaced))
                }
                GridRow {
                    Text("Owner's fingerprint").font(.system(size: 11, weight: .semibold))
                    Text(kit.ownerFingerprint).font(.system(size: 12, design: .monospaced))
                }
                GridRow {
                    Text("Your fingerprint").font(.system(size: 11, weight: .semibold))
                    Text(kit.fingerprint).font(.system(size: 12, design: .monospaced))
                }
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("To recover on a new Mac")
                    .font(.system(size: 13, weight: .semibold))
                Text("Open Keystead, choose Recover an account, and enter the server address, the "
                    + "owner's fingerprint and these 24 words. Then remove your old Mac under "
                    + "People › You, so it can't sign in any more.")
                    .font(.system(size: 11))
                    .fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("Keep this page safe")
                    .font(.system(size: 13, weight: .semibold))
                Text("Anyone with these words can be you on this server and read everything you "
                    + "can. Keep the page somewhere safe and offline, like a safe or a sealed "
                    + "envelope with someone you trust. Don't photograph it or store it on a "
                    + "computer or online.")
                    .font(.system(size: 11))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(48)
        .frame(width: 612, height: 792, alignment: .topLeading)
        .background(Color.white)
        .environment(\.colorScheme, .light)
    }
}

/// Renders the kit to a PDF in memory and opens the print panel, which can also save it
/// as a PDF. Nothing is written to disk unless the user chooses to.
@MainActor
func printRecoveryKit(_ kit: RecoveryKit) {
    let renderer = ImageRenderer(content: RecoveryKitPage(kit: kit, printed: .now))
    let data = NSMutableData()
    renderer.render { size, draw in
        var box = CGRect(origin: .zero, size: size)
        guard let consumer = CGDataConsumer(data: data),
            let pdf = CGContext(consumer: consumer, mediaBox: &box, nil)
        else { return }
        pdf.beginPDFPage(nil)
        draw(pdf)
        pdf.endPDFPage()
        pdf.closePDF()
    }
    guard let document = PDFDocument(data: data as Data),
        let operation = document.printOperation(
            for: NSPrintInfo.shared, scalingMode: .pageScaleToFit, autoRotate: false)
    else { return }
    operation.jobTitle = "Keystead Recovery Kit"
    operation.showsPrintPanel = true
    operation.run()
}

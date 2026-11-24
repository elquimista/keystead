import AppKit

/// Copies passwords the careful way:
///
/// - Only to this Mac: Universal Clipboard doesn't send it to the user's other devices.
/// - Marked concealed and transient, so clipboard managers that honour the
///   nspasteboard.org markers don't record it.
/// - After 30 seconds, if the clipboard still holds our copy, puts back what was there
///   before, or clears it; something the user copied since is left alone.
///
/// What was there before is kept only in memory, and only from before the first of several
/// copies in a row, so a password copied earlier never comes back. Anything marked as a
/// secret (by Keystead or another password manager) is never put back. On macOS 26 and
/// later, reading the clipboard can make macOS ask the user, so Keystead only does it if
/// it's allowed to paste from other apps without asking; otherwise it just clears.
@MainActor
final class SecureClipboard {
    nonisolated static let clearAfter: Duration = .seconds(30)
    /// Bigger clipboards (large images, say) aren't kept; they're cleared instead.
    nonisolated static let largestKept = 10 * 1024 * 1024

    private let pasteboard: NSPasteboard
    private let clearAfter: Duration
    private var clearTask: Task<Void, Never>?
    /// The clipboard's change count right after our last copy, while it may still hold it.
    private var ours: Int?
    /// What the clipboard held before our first copy in a row, to put back.
    private var saved: [NSPasteboardItem]?

    init(pasteboard: NSPasteboard = .general, clearAfter: Duration = SecureClipboard.clearAfter) {
        self.pasteboard = pasteboard
        self.clearAfter = clearAfter
    }

    func copy(_ text: String) {
        // Over our own copy, keep what was there before the first; else save what's there.
        if ours == nil || pasteboard.changeCount != ours {
            saved = snapshot()
        }
        _ = pasteboard.prepareForNewContents(with: .currentHostOnly)
        pasteboard.setString(text, forType: .string)
        pasteboard.setData(Data(), forType: Self.concealed)
        pasteboard.setData(Data(), forType: Self.transient)
        ours = pasteboard.changeCount

        clearTask?.cancel()
        clearTask = Task {
            try? await Task.sleep(for: clearAfter)
            if !Task.isCancelled { expire() }
        }
    }

    /// Clears the clipboard now if it still holds our copy, putting nothing back (when
    /// locking because the user is away); something copied since stays.
    func clearNow() {
        clearTask?.cancel()
        if let ours, pasteboard.changeCount == ours {
            pasteboard.clearContents()
        }
        ours = nil
        saved = nil
    }

    /// Our copy's time is up: put back what was there before, or clear.
    private func expire() {
        if let ours, pasteboard.changeCount == ours {
            pasteboard.clearContents()
            if let saved, !saved.isEmpty {
                pasteboard.writeObjects(saved)
            }
        }
        ours = nil
        saved = nil
    }

    /// A copy of what's on the clipboard now, or nothing if there's nothing worth putting
    /// back: it's empty, a secret, too big, or can't be read without asking the user.
    private func snapshot() -> [NSPasteboardItem]? {
        guard mayReadWithoutAsking, let items = pasteboard.pasteboardItems, !items.isEmpty else {
            return nil
        }
        if items.contains(where: { !Set($0.types).isDisjoint(with: Self.secretMarkers) }) {
            return nil
        }
        var size = 0
        var copies: [NSPasteboardItem] = []
        for item in items {
            let copy = NSPasteboardItem()
            for type in item.types {
                guard let data = item.data(forType: type) else { continue }
                size += data.count
                if size > Self.largestKept { return nil }
                copy.setData(data, forType: type)
            }
            copies.append(copy)
        }
        return copies
    }

    /// Whether reading the clipboard shows no alert. macOS 26 asks by default; before
    /// that, apps read it freely.
    private var mayReadWithoutAsking: Bool {
        if #available(macOS 15.4, *) {
            switch pasteboard.accessBehavior {
            case .alwaysAllow:
                return true
            case .default:
                return ProcessInfo.processInfo.operatingSystemVersion.majorVersion < 26
            default:
                return false
            }
        }
        return true
    }

    private static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
    private static let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")
    /// How Keystead and other password managers mark what they copy.
    private static let secretMarkers: Set<NSPasteboard.PasteboardType> = [
        concealed, transient,
        NSPasteboard.PasteboardType("de.petermaurer.TransientPasteboardType"),
        NSPasteboard.PasteboardType("com.agilebits.onepassword"),
    ]
}

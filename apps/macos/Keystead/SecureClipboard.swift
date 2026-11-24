import AppKit

/// Copies passwords the careful way:
///
/// - Only to this Mac: Universal Clipboard doesn't send it to the user's other devices.
/// - Marked concealed and transient, so clipboard managers that honour the
///   nspasteboard.org markers don't record it.
/// - Cleared after 30 seconds, but only if the clipboard still holds our copy; something
///   the user copied since is left alone.
@MainActor
final class SecureClipboard {
    static let clearAfter: Duration = .seconds(30)

    private var clearTask: Task<Void, Never>?
    /// The clipboard's change count right after our last copy, while it may still hold it.
    private var ours: Int?

    func copy(_ text: String) {
        let pasteboard = NSPasteboard.general
        _ = pasteboard.prepareForNewContents(with: .currentHostOnly)
        pasteboard.setString(text, forType: .string)
        pasteboard.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        pasteboard.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType"))
        ours = pasteboard.changeCount

        clearTask?.cancel()
        clearTask = Task {
            try? await Task.sleep(for: Self.clearAfter)
            if !Task.isCancelled { clearNow() }
        }
    }

    /// Clears the clipboard now if it still holds our copy; something copied since stays.
    func clearNow() {
        clearTask?.cancel()
        let pasteboard = NSPasteboard.general
        if let ours, pasteboard.changeCount == ours {
            pasteboard.clearContents()
        }
        ours = nil
    }
}

import AppKit
import Observation

/// Whether a newer Keystead is out, from this repository's latest GitHub release: once a
/// day on its own (unless turned off in Settings), or when asked from the app menu. Nothing
/// is downloaded or installed; Download opens the release's page, which has the app and
/// what changed.
@MainActor
@Observable
final class Updates {
    /// Settings › Updates: whether to check once a day on its own.
    static let automaticKey = "CheckForUpdates"
    private static let lastCheckedKey = "UpdatesLastChecked"
    private static let foundKey = "UpdatesFound"
    private static let dismissedKey = "UpdatesDismissed"
    private static let interval: TimeInterval = 24 * 60 * 60

    /// This app's version, as GitHub's releases number them.
    static let current = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"

    /// The newer version the last check found, kept across launches until it's installed.
    private(set) var available: AppUpdate?
    private(set) var isChecking = false
    private(set) var lastChecked: Date?
    /// Why the last check failed, as a sentence, until one succeeds.
    private(set) var failure: String?
    /// The version whose notice was closed: it stays closed until a newer one is out.
    private var dismissed: String?
    @ObservationIgnored private var automaticTask: Task<Void, Never>?
    @ObservationIgnored private var activationObserver: NSObjectProtocol?

    init() {
        let defaults = UserDefaults.standard
        lastChecked = defaults.object(forKey: Self.lastCheckedKey) as? Date
        dismissed = defaults.string(forKey: Self.dismissedKey)
        if let found = defaults.dictionary(forKey: Self.foundKey) as? [String: String],
            let version = found["version"], let page = found["page"], let download = found["download"],
            Self.isNewer(version)
        {
            available = AppUpdate(version: version, page: page, download: download)
        }
    }

    /// Whether the main window and the menu bar panel mention it.
    var showsNotice: Bool {
        guard let available else { return false }
        return available.version != dismissed
    }

    private var automatic: Bool {
        UserDefaults.standard.object(forKey: Self.automaticKey) as? Bool ?? true
    }

    /// Checks a little after launch, then whenever a day has passed since the last check:
    /// asked hourly, and when the app comes to the front.
    func startAutomaticChecks() {
        guard automaticTask == nil else { return }
        automaticTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(10))
            while !Task.isCancelled {
                await self?.checkIfDue()
                try? await Task.sleep(for: .seconds(60 * 60))
            }
        }
        activationObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                Task { await self.checkIfDue() }
            }
        }
    }

    /// Checks if checking on its own is on and a day has passed since the last check.
    func checkIfDue() async {
        guard automatic, !isChecking else { return }
        if let lastChecked, Date.now.timeIntervalSince(lastChecked) < Self.interval { return }
        // A failure is tried again within the hour; only the menu's check says so.
        _ = try? await check()
    }

    /// From Settings › Updates, which shows what it found, or why it couldn't check.
    func checkNow() async {
        guard !isChecking else { return }
        _ = try? await check()
    }

    /// From the app menu: says what it found in an alert, even when there's nothing new.
    func checkFromMenu() async {
        guard !isChecking else { return }
        let alert = NSAlert()
        alert.icon = NSApp.applicationIconImage
        do {
            if let update = try await check() {
                alert.messageText = "A new version of \(appName) is available"
                alert.informativeText = "\(appName) \(update.version) is out; you have \(Self.current). "
                    + "Its page has the app and what changed."
                alert.addButton(withTitle: "Download\u{2026}")
                alert.addButton(withTitle: "Later")
                NSApp.activate()
                if alert.runModal() == .alertFirstButtonReturn {
                    openPage()
                } else {
                    dismiss()
                }
            } else {
                alert.messageText = "\(appName) is up to date"
                alert.informativeText = "\(Self.current) is the newest version."
                NSApp.activate()
                alert.runModal()
            }
        } catch {
            alert.alertStyle = .warning
            alert.messageText = "Couldn't check for updates"
            alert.informativeText = Self.sentence(error)
            NSApp.activate()
            alert.runModal()
        }
    }

    /// Opens the release's page in the browser.
    func openPage() {
        guard let available, let url = URL(string: available.page) else { return }
        NSWorkspace.shared.open(url)
    }

    /// Closes the notice until a newer version than this one is out.
    func dismiss() {
        guard let available else { return }
        dismissed = available.version
        UserDefaults.standard.set(available.version, forKey: Self.dismissedKey)
    }

    private func check() async throws -> AppUpdate? {
        isChecking = true
        defer { isChecking = false }
        let current = Self.current
        let update: AppUpdate?
        do {
            update = try await Task.detached { try checkForAppUpdate(current: current) }.value
        } catch {
            failure = Self.sentence(error)
            throw error
        }
        failure = nil
        available = update
        lastChecked = .now
        let defaults = UserDefaults.standard
        defaults.set(lastChecked, forKey: Self.lastCheckedKey)
        if let update {
            defaults.set(
                ["version": update.version, "page": update.page, "download": update.download],
                forKey: Self.foundKey)
        } else {
            defaults.removeObject(forKey: Self.foundKey)
        }
        return update
    }

    /// "couldn't reach GitHub: …" as "Couldn't reach GitHub: ….".
    private static func sentence(_ error: Error) -> String {
        let reason = describe(error)
        let sentence = reason.prefix(1).uppercased() + reason.dropFirst()
        return sentence.hasSuffix(".") ? sentence : sentence + "."
    }

    /// Whether `version` is newer than this app's, comparing the numbers ("0.13.10" is newer
    /// than "0.13.9").
    private static func isNewer(_ version: String) -> Bool {
        version.compare(current, options: .numeric) == .orderedDescending
    }

    #if DEBUG
    enum DemoState {
        case available, upToDate, failed, checking, unchecked
    }

    /// Demo snapshots: what a check might have found, without asking GitHub.
    func showDemo(_ state: DemoState = .available) {
        available = state == .available
            ? AppUpdate(
                version: "0.14.0",
                page: "https://github.com/elquimista/keystead/releases/tag/v0.14.0",
                download: "https://github.com/elquimista/keystead/releases/download/v0.14.0/Keystead-0.14.0.zip")
            : nil
        failure = state == .failed
            ? Self.sentence(CoreError.Failed(message: "couldn't reach GitHub: the network is offline"))
            : nil
        isChecking = state == .checking
        dismissed = nil
        lastChecked = state == .unchecked ? nil : .now.addingTimeInterval(-5 * 60)
    }
    #endif
}

import AppKit

/// Locks Keystead so its keys don't stay in memory while it isn't being used:
///
/// - after a few minutes without using Keystead (5 unless changed in Settings), whatever
///   else is happening on the Mac. Using means a click, key press or scroll in Keystead's
///   window or menu bar panel, so it counts from the last time you did something here,
///   unlocking included;
/// - at once when the screen locks, the Mac or its display goes to sleep, or another user
///   takes over the screen.
///
/// Locking this way also clears the clipboard if it still holds a password Keystead copied.
@MainActor
final class AutoLock {
    /// Minutes without using Keystead before it locks; 0 means never.
    static let minutesKey = "autoLockMinutes"
    static let defaultMinutes = 5
    static let choices = [1, 5, 10, 30, 60, 0]

    static var minutes: Int {
        UserDefaults.standard.object(forKey: minutesKey) as? Int ?? defaultMinutes
    }

    private let model: AppModel
    private var lastUse = ContinuousClock.now
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    private var eventMonitor: Any?
    private var timer: Task<Void, Never>?

    init(model: AppModel) {
        self.model = model
        let workspace = NSWorkspace.shared.notificationCenter
        for name in [
            NSWorkspace.willSleepNotification,
            NSWorkspace.screensDidSleepNotification,
            NSWorkspace.sessionDidResignActiveNotification,
        ] {
            observe(workspace, name)
        }
        observe(DistributedNotificationCenter.default(), Notification.Name("com.apple.screenIsLocked"))

        // Only events sent to Keystead's own windows: what happens in other apps isn't
        // using Keystead.
        eventMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.keyDown, .leftMouseDown, .rightMouseDown, .otherMouseDown, .scrollWheel]
        ) { [weak self] event in
            MainActor.assumeIsolated { self?.lastUse = .now }
            return event
        }
        timer = Task { [weak self] in await self?.run() }
    }

    private func observe(_ center: NotificationCenter, _ name: Notification.Name) {
        let token = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.model.lockBecauseAway() }
        }
        observers.append((center, token))
    }

    /// `-autoLockTest`, in Debug builds: check every second, print the time since Keystead
    /// was last used, and lock after 5 seconds of it. A property, not a constant, so Release
    /// builds don't warn that the test's branches never run.
    private static var testing: Bool {
        #if DEBUG
        CommandLine.arguments.contains("-autoLockTest")
        #else
        false
        #endif
    }

    /// Checks every 15 seconds how long it's been since Keystead was last used.
    private func run() async {
        let testing = Self.testing
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(testing ? 1 : 15))
            let limit: Duration = testing ? .seconds(5) : .seconds(Self.minutes * 60)
            let unused = ContinuousClock.now - lastUse
            if testing {
                // Unbuffered, so nothing is lost when the test run is stopped.
                FileHandle.standardError.write(Data(
                    "auto-lock: unused \(unused.components.seconds) s, phase \(model.phase)\n".utf8))
            }
            if limit > .zero && unused >= limit {
                model.lockBecauseAway()
            }
        }
    }
}

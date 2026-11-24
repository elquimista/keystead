#if DEBUG
import AppKit

/// Debug builds only: with `-snapshot`, steps the main window through its sections and
/// selections, saves a picture of each and how its split view's columns are laid out, then
/// quits. Pair it with `-demo`. Everything goes to the app's temporary folder, inside its sandbox
/// container; the path is printed.
///
///   Keystead.app/Contents/MacOS/Keystead -demo -snapshot
enum DebugSnapshots {
    @MainActor
    static func runIfRequested(_ model: AppModel) async {
        guard CommandLine.arguments.contains("-snapshot") else { return }
        let directory = FileManager.default.temporaryDirectory.appending(path: "snapshots")
        try? FileManager.default.removeItem(at: directory)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var report = ""

        // Each step sets up the window, then it's captured. With a team, also select a
        // login and each kind of person, and show the notices.
        var steps: [(String, () -> Void)] = [
            ("1-all-logins", { model.section = .allLogins }),
            ("2-people", { model.section = .people }),
        ]
        if model.users.count > 1 {
            steps += [
                ("3-person-waiting", { model.selectedUserID = 3 }),
                ("4-person-approved", { model.selectedUserID = 2 }),
                ("5-person-you", { model.selectedUserID = 1 }),
                ("6-login", {
                    model.section = .allLogins
                    model.selectedItemID = model.items.first?.id
                }),
                ("7-notices", { model.showDemoNotices() }),
            ]
        }
        steps.append(("8-back-to-all-logins", { model.section = .allLogins }))

        try? await Task.sleep(for: .seconds(2))
        for (name, setUp) in steps {
            setUp()
            try? await Task.sleep(for: .seconds(1.5))
            guard let window = mainWindow() else {
                report += "\(name): no main window\n"
                continue
            }
            report += "\(name): window \(Int(window.frame.width))x\(Int(window.frame.height))\n"
            report += columns(in: window)
            save(window, to: directory.appending(path: "\(name).png"))
        }
        try? report.write(to: directory.appending(path: "report.txt"), atomically: true, encoding: .utf8)
        print("Snapshots in \(directory.path)")
        NSApp.terminate(nil)
    }

    @MainActor
    private static func mainWindow() -> NSWindow? {
        NSApp.windows.filter { $0.isVisible && $0.frame.width > 400 }.max { $0.frame.width < $1.frame.width }
    }

    /// Each split view's panes: width, and whether collapsed.
    @MainActor
    private static func columns(in window: NSWindow) -> String {
        var lines = ""
        func visit(_ view: NSView) {
            if let split = view as? NSSplitView {
                let panes = split.arrangedSubviews.map { pane in
                    "\(Int(pane.frame.width))\(split.isSubviewCollapsed(pane) ? " (collapsed)" : "")"
                }
                lines += "  split view panes: \(panes.joined(separator: ", "))\n"
            }
            view.subviews.forEach(visit)
        }
        if let frame = window.contentView?.superview { visit(frame) }
        return lines
    }

    @MainActor
    private static func save(_ window: NSWindow, to url: URL) {
        // The frame view includes the title bar and toolbar.
        guard let view = window.contentView?.superview,
            let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds)
        else { return }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        try? bitmap.representation(using: .png, properties: [:])?.write(to: url)
    }
}
#endif

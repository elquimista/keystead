#if DEBUG
import AppKit
import SwiftUI

/// Debug builds only: with `-snapshot`, steps the main window through its sections and
/// selections, saves a picture of each (and of any sheet) and how its split view's columns
/// are laid out, then quits. Pair it with `-demo`. Everything goes to the app's temporary
/// folder, inside its sandbox container; the path is printed.
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
        if model.users.count <= 1 {
            steps += [
                ("2a-kit-after-setup", { model.sheet = .recoveryKit(afterSetup: true) }),
                ("2b-kit-closed", { model.sheet = nil }),
                // The owner's only device: the strongest warning.
                ("2c-sign-out", { model.sheet = .signOut }),
                ("2d-closed", { model.sheet = nil }),
            ]
        } else {
            steps += [
                ("3-person-waiting", { model.selectedUserID = 3 }),
                ("4-person-approved", { model.selectedUserID = 2 }),
                // Pat was removed and could see two of Olivia's logins.
                ("4a-person-removed", { model.selectedUserID = 4 }),
                ("5-person-you", { model.selectedUserID = 1 }),
                ("5a-recovery-kit", { model.sheet = .recoveryKit(afterSetup: false) }),
                ("5b-kit-closed", { model.sheet = nil }),
                ("5c-sign-out", { model.sheet = .signOut }),
                ("5d-closed", { model.sheet = nil }),
                ("5e-add-device", { model.sheet = .addDevice }),
                ("5f-closed", { model.sheet = nil }),
                ("5g-adding-this-mac", { model.showDemoJoining() }),
                ("5h-back", { model.showDemoJoining(false) }),
                ("6-login", {
                    model.section = .allLogins
                    model.selectedItemID = model.items.first?.id
                }),
                // The demo's third login is Olivia's own; the fourth Mo shared with her.
                ("6a-own-login", { model.selectedItemID = model.items[2].id }),
                ("6b-share-login", { model.sheet = .shareLogin(model.items[2]) }),
                ("6c-closed", { model.sheet = nil }),
                ("6c1-edit-login", { model.sheet = .editLogin(model.items[2]) }),
                ("6c2-closed", { model.sheet = nil }),
                // AWS root has one-time codes.
                ("6c2a-edit-with-code", { model.sheet = .editLogin(model.items[0]) }),
                ("6c2b-closed", { model.sheet = nil }),
                ("6c2c-history", { model.sheet = .history(model.items[0]) }),
                ("6c2c1-import", { model.sheet = .importLogins }),
                ("6c2c1b-export", { model.sheet = .exportLogins }),
                ("6c2c2-move", { model.sheet = .moveLogin(model.items[0]) }),
                ("6c2d-closed", { model.sheet = nil }),
                // AWS root: in a folder, and also shared with Mo.
                ("6c3-delete-login", { model.sheet = .deleteLogin(model.items[0]) }),
                ("6c4-closed", { model.sheet = nil }),
                // Bank: Olivia's own; Domain registrar: Mo's, shared with her.
                ("6c5-delete-own", { model.sheet = .deleteLogin(model.items[2]) }),
                ("6c6-closed", { model.sheet = nil }),
                ("6c7-delete-shared", { model.sheet = .deleteLogin(model.items[3]) }),
                ("6c8-closed", { model.sheet = nil }),
                // Roles: sharing AWS root (Olivia manages it), Production's members, a
                // login Olivia may only view, and Mo's login she may edit but not share.
                ("6c9-share-aws", { model.sheet = .shareLogin(model.items[0]) }),
                ("6c10-closed", { model.sheet = nil }),
                ("6c11-folder-access", { model.sheet = .manageFolder("Production") }),
                ("6c12-closed", { model.sheet = nil }),
                ("6c13-view-only-login", { model.selectedItemID = model.items[1].id }),
                ("6c14-access-shared", { model.sheet = .shareLogin(model.items[3]) }),
                ("6c15-closed", { model.sheet = nil }),
                ("6d-new-login", { model.sheet = .addLogin(folder: nil) }),
                ("6e-shared-with-me", {
                    model.sheet = nil
                    model.section = .sharedWithMe
                    model.selectedItemID = model.items[3].id
                }),
                // Groups: Olivia manages Engineering and is in it; On-call she can manage as
                // the owner but isn't in. Bank is shared with On-call.
                ("6e1-groups", {
                    model.section = .groups
                    model.selectedGroupID = model.groups.first?.id
                }),
                ("6e2-group-not-in", { model.selectedGroupID = model.groups.last?.id }),
                ("6e3-new-group", { model.sheet = .newGroup }),
                ("6e4-closed", { model.sheet = nil }),
                ("6e5-share-with-group", { model.sheet = .shareWithGroup(model.groups[0]) }),
                ("6e6-closed", { model.sheet = nil }),
                ("6e7-bank-shared-with-group", {
                    model.section = .allLogins
                    model.selectedItemID = model.items[2].id
                    model.sheet = .shareLogin(model.items[2])
                }),
                ("6e8-closed", { model.sheet = nil }),
                ("6e10-recently-deleted", {
                    model.section = .recentlyDeleted
                    model.selectedDeletedID = model.recentlyDeleted.first?.id
                }),
                ("6e11-new-folder-inside", { model.sheet = .newFolder(inside: "Production") }),
                ("6e12-subfolder", {
                    model.sheet = nil
                    model.section = .folder("Production / Databases")
                }),
                ("6e12b-help-recover", {
                    if let user = model.users.first(where: { !$0.isOwner && $0.approved }) {
                        model.sheet = .helpRecover(user)
                    }
                }),
                ("6e12c-approve", {
                    if let user = model.users.first(where: { !$0.approved && !$0.removed }) {
                        model.sheet = .approve(user)
                    }
                }),
                ("6e12d-invite", { model.sheet = .invite }),
                ("6e12e-fingerprint", { model.sheet = .fingerprint }),
                ("6e12f-remove-user", {
                    if let user = model.users.first(where: { !$0.isOwner && $0.approved && !$0.removed }) {
                        model.sheet = .removeUser(user)
                    }
                }),
                ("6e13-rename-folder", { model.sheet = .renameFolder("Production") }),
                ("6e14-delete-folder", { model.sheet = .deleteFolder("Production") }),
                ("6e15-closed", { model.sheet = nil }),
                ("6e9-to-change", {
                    model.section = .toChange
                    model.selectedItemID = model.items[0].id
                }),
                ("6e9b-password-health", { model.section = .health }),
                ("6f-quick-search", { QuickSearch.shared?.show(query: "a") }),
                // The down arrow, as the keyboard sends it: the second match is picked.
                ("6f2-quick-search-down", { pressKey(keyCode: 125) }),
                ("6g-quick-search-closed", { QuickSearch.shared?.close() }),
                ("7-notices", { model.showDemoNotices() }),
                ("w1-welcome", { model.showDemoWelcome(.start) }),
                ("w2-join", { model.welcomePage = .join }),
                ("w3-set-up", { model.welcomePage = .setUp }),
                ("w4-add-this-mac", { model.welcomePage = .addThisMac }),
                ("w5-recover", { model.welcomePage = .recover }),
                ("w6-recover-with-help", { model.welcomePage = .recoverWithHelp }),
                ("w7-adding-this-mac", { model.showDemoJoining() }),
                ("w8-waiting-for-owner", { model.showDemoWaitingForOwner() }),
                ("w9-locked", { model.showDemoPhase(.locked) }),
                ("w10-working", { model.showDemoPhase(.working("Unlocking…")) }),
                ("w11-back", { model.showDemoPhase(.unlocked) }),
            ]
        }
        steps.append(("8-back-to-all-logins", { model.section = .allLogins }))
        // With `-windowsOnly`, just Settings and the menu bar panel, for quick checks.
        if CommandLine.arguments.contains("-windowsOnly") {
            steps = []
        }

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
            if let sheet = window.attachedSheet {
                save(sheet, to: directory.appending(path: "\(name)-sheet.png"))
            }
            if let panel = NSApp.windows.first(where: { $0 is QuickSearchPanel && $0.isVisible }) {
                save(panel, to: directory.appending(path: "\(name)-quick-search.png"))
            }
        }
        if model.users.count > 1 {
            report += await captureSettings(model, to: directory)
            report += await capturePanel(model, to: directory)
            report += await probeSheets(model, to: directory)
        }
        if model.users.count > 1, let kit = try? await model.recoveryKit() {
            // The printed page, as the print panel would get it.
            let renderer = ImageRenderer(content: RecoveryKitPage(kit: kit, printed: .now))
            renderer.scale = 1.5
            if let image = renderer.nsImage, let tiff = image.tiffRepresentation,
                let png = NSBitmapImageRep(data: tiff)?.representation(using: .png, properties: [:])
            {
                try? png.write(to: directory.appending(path: "9-printed-kit.png"))
            }
        }
        report += "quick search shortcut registered: "
            + "\(QuickSearch.shared?.isShortcutRegistered ?? false)\n"
        try? report.write(to: directory.appending(path: "report.txt"), atomically: true, encoding: .utf8)
        print("Snapshots in \(directory.path)")
        NSApp.terminate(nil)
    }

    /// Opens Settings from the app menu, as a person would, and saves each tab.
    @MainActor
    private static func captureSettings(_ model: AppModel, to directory: URL) async -> String {
        guard let menu = NSApp.mainMenu?.items.first?.submenu,
            let index = menu.items.firstIndex(where: { $0.keyEquivalent == "," })
        else { return "settings: no Settings menu item\n" }
        let tabs: [SettingsView.Tab] = [.general, .security, .account, .updates]
        let titles = ["General", "Security", "Account", "Updates"]
        let earlier = UserDefaults.standard.string(forKey: SettingsView.tabKey)
        func settingsWindow() -> NSWindow? {
            NSApp.windows.first { $0.isVisible && titles.contains($0.title) }
        }
        var report = ""
        for tab in tabs {
            UserDefaults.standard.set(tab.rawValue, forKey: SettingsView.tabKey)
            if settingsWindow() == nil { menu.performActionForItem(at: index) }
            try? await Task.sleep(for: .seconds(1.5))
            guard let window = settingsWindow() else {
                report += "settings-\(tab.rawValue): no window\n"
                continue
            }
            report += "settings-\(tab.rawValue): window \(Int(window.frame.width))x\(Int(window.frame.height))\n"
            save(window, to: directory.appending(path: "s-settings-\(tab.rawValue).png"))
        }
        // The Updates tab, still showing, in each state a check can leave it in.
        let hadUpdate = model.updates.available != nil
        let states: [(String, Updates.DemoState)] = [
            ("up-to-date", .upToDate), ("checking", .checking), ("failed", .failed),
            ("unchecked", .unchecked), ("available", .available),
        ]
        for (name, state) in states {
            model.updates.showDemo(state)
            try? await Task.sleep(for: .seconds(0.6))
            guard let window = settingsWindow() else { continue }
            report += "settings-updates-\(name): window \(Int(window.frame.width))x\(Int(window.frame.height))\n"
            save(window, to: directory.appending(path: "s-settings-updates-\(name).png"))
        }
        model.updates.showDemo(hadUpdate ? .available : .upToDate)
        if let window = settingsWindow() {
            report += "settings window: \(type(of: window)), controller "
                + "\(window.contentViewController.map { String(describing: type(of: $0)) } ?? "none"), "
                + "resizable \(window.styleMask.contains(.resizable)), "
                + "content min \(window.contentMinSize), max \(window.contentMaxSize)\n"
            // Tall to short and back, clicked as a person would.
            report += await probeResize(window, clicking: "General")
            report += await probeResize(window, clicking: "Account")
            report += await probeResize(window, clicking: "Updates")
        }
        settingsWindow()?.close()
        UserDefaults.standard.set(earlier, forKey: SettingsView.tabKey)
        return report
    }

    /// Opens sheets that load something after appearing, and records each one's height
    /// every few milliseconds for 1.5 seconds from when it's attached: heights between the
    /// first and last mean it grew smoothly; a single step means it jumped. Add
    /// `-slowDemo` to see them load as from a slow server.
    @MainActor
    private static func probeSheets(_ model: AppModel, to directory: URL) async -> String {
        model.section = .allLogins
        let sheets: [(String, AppModel.Sheet?)] = [
            ("share", .shareLogin(model.items[0])),
            ("folder access", .manageFolder("Production")),
            ("history", .history(model.items[0])),
            ("add device", .addDevice),
            ("import", .importLogins),
            ("help recover", model.users.first { !$0.isOwner && $0.approved }.map { .helpRecover($0) }),
        ]
        var report = ""
        for (name, sheet) in sheets {
            guard let sheet, let window = mainWindow() else { continue }
            model.sheet = sheet
            let start = ContinuousClock.now
            var attached: NSWindow?
            while attached == nil && ContinuousClock.now - start < .seconds(2) {
                attached = window.attachedSheet
                try? await Task.sleep(for: .milliseconds(2))
            }
            guard let attached else {
                report += "sheet \(name): never attached\n"
                continue
            }
            var heights: [Int] = []
            var tops: Set<Int> = []
            var topsInOrder: [Int] = []
            let shown = ContinuousClock.now
            while ContinuousClock.now - shown < .milliseconds(1500) {
                let height = Int(attached.frame.height)
                if heights.last != height { heights.append(height) }
                tops.insert(Int(attached.frame.maxY))
                if topsInOrder.last != Int(attached.frame.maxY) { topsInOrder.append(Int(attached.frame.maxY)) }
                try? await Task.sleep(for: .milliseconds(4))
            }
            report += "sheet \(name): heights \(heights.map(String.init).joined(separator: " → ")), "
                + "top edge \(tops.count == 1 ? "fixed" : "moved \(topsInOrder.map(String.init).joined(separator: " → "))"), "
                + "resizable \(attached.styleMask.contains(.resizable))\n"
            save(attached, to: directory.appending(path: "q-\(name.replacingOccurrences(of: " ", with: "-")).png"))
            model.sheet = nil
            try? await Task.sleep(for: .seconds(0.6))
        }
        return report
    }

    /// Clicks a Settings tab's toolbar item and records the window's height every few
    /// milliseconds for 0.6 seconds: heights between the first and last mean it animated.
    @MainActor
    private static func probeResize(_ window: NSWindow, clicking label: String) async -> String {
        guard let item = window.toolbar?.items.first(where: { $0.label == label }),
            let action = item.action
        else { return "settings resize to \(label): no toolbar item\n" }
        let start = ContinuousClock.now
        NSApp.sendAction(action, to: item.target, from: item)
        let clickTook = ContinuousClock.now - start
        var heights: [Int] = []
        var tops: Set<Int> = []
        while ContinuousClock.now - start < .milliseconds(600) {
            let height = Int(window.frame.height)
            if heights.last != height { heights.append(height) }
            tops.insert(Int(window.frame.maxY))
            try? await Task.sleep(for: .milliseconds(5))
        }
        let after = "top edge \(tops.count == 1 ? "fixed" : "moved \(tops.sorted())"), "
            + "resizable \(window.styleMask.contains(.resizable))"
        let milliseconds = clickTook.components.seconds * 1000
            + clickTook.components.attoseconds / 1_000_000_000_000_000
        return "settings resize to \(label): click took \(milliseconds) ms, "
            + "heights \(heights.map(String.init).joined(separator: " → ")), \(after)\n"
    }

    /// The menu bar panel, opened by clicking the status item: unlocked, then locked, and
    /// how its height follows a search that leaves one login of four.
    @MainActor
    private static func capturePanel(_ model: AppModel, to directory: URL) async -> String {
        func find<View: NSView>(_ type: View.Type, in view: NSView?) -> View? {
            guard let view else { return nil }
            if let match = view as? View { return match }
            for subview in view.subviews {
                if let match = find(type, in: subview) { return match }
            }
            return nil
        }
        let before = Set(NSApp.windows.filter(\.isVisible).map(ObjectIdentifier.init))
        guard let button = NSApp.windows.lazy.compactMap({ find(NSStatusBarButton.self, in: $0.contentView) }).first
        else { return "panel: no status item\n" }
        button.performClick(nil)
        var opened: NSWindow?
        let clicked = ContinuousClock.now
        while opened == nil && ContinuousClock.now - clicked < .seconds(3) {
            try? await Task.sleep(for: .milliseconds(50))
            opened = NSApp.windows.first {
                $0.isVisible && !before.contains(ObjectIdentifier($0)) && !($0 is QuickSearchPanel)
            }
        }
        try? await Task.sleep(for: .seconds(0.5))
        guard let panel = opened else {
            let windows = NSApp.windows.map {
                "\(type(of: $0)) visible \($0.isVisible) \(Int($0.frame.width))x\(Int($0.frame.height))"
            }
            return "panel: didn't open; windows: \(windows.joined(separator: "; "))\n"
        }
        var report = "panel: \(type(of: panel))\n"
        for (name, phase) in [("p1-panel", AppModel.Phase.unlocked), ("p2-panel-locked", .locked)] {
            model.showDemoPhase(phase)
            try? await Task.sleep(for: .seconds(1))
            report += "\(name): window \(Int(panel.frame.width))x\(Int(panel.frame.height))\n"
            save(panel, to: directory.appending(path: "\(name).png"))
        }
        model.showDemoPhase(.unlocked)
        try? await Task.sleep(for: .seconds(1))
        report += "p3-panel-unlocked-again: window \(Int(panel.frame.width))x\(Int(panel.frame.height)), "
            + "visible \(panel.isVisible)\n"
        save(panel, to: directory.appending(path: "p3-panel-unlocked-again.png"))
        for search in ["aws", ""] {
            let start = ContinuousClock.now
            model.search = search
            var heights: [Int] = []
            var tops: Set<Int> = []
            while ContinuousClock.now - start < .milliseconds(600) {
                let height = Int(panel.frame.height)
                if heights.last != height { heights.append(height) }
                tops.insert(Int(panel.frame.maxY))
                try? await Task.sleep(for: .milliseconds(4))
            }
            report += "panel search \"\(search)\": heights \(heights.map(String.init).joined(separator: " → ")), "
                + "top edge \(tops.count == 1 ? "fixed" : "moved")\n"
        }
        panel.orderOut(nil)
        return report
    }

    /// Sends a key press to the key window through the app, as the keyboard would.
    @MainActor
    private static func pressKey(keyCode: UInt16) {
        guard let window = NSApp.keyWindow,
            let event = NSEvent.keyEvent(
                with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
                windowNumber: window.windowNumber, context: nil, characters: "",
                charactersIgnoringModifiers: "", isARepeat: false, keyCode: keyCode)
        else { return }
        NSApp.sendEvent(event)
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
        // The frame view includes the title bar and toolbar; a borderless panel has only its
        // content view.
        guard let view = window.contentView?.superview ?? window.contentView,
            let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds)
        else { return }
        view.cacheDisplay(in: view.bounds, to: bitmap)
        try? bitmap.representation(using: .png, properties: [:])?.write(to: url)
    }
}
#endif

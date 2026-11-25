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
                ("6e9-to-change", {
                    model.section = .toChange
                    model.selectedItemID = model.items[0].id
                }),
                ("6f-quick-search", { QuickSearch.shared?.show(query: "a") }),
                // The down arrow, as the keyboard sends it: the second match is picked.
                ("6f2-quick-search-down", { pressKey(keyCode: 125) }),
                ("6g-quick-search-closed", { QuickSearch.shared?.close() }),
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
            if let sheet = window.attachedSheet {
                save(sheet, to: directory.appending(path: "\(name)-sheet.png"))
            }
            if let panel = NSApp.windows.first(where: { $0 is QuickSearchPanel && $0.isVisible }) {
                save(panel, to: directory.appending(path: "\(name)-quick-search.png"))
            }
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

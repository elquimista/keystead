import AppKit
import SwiftUI

@main
struct KeysteadApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model: AppModel
    private let autoLock: AutoLock
    private let quickSearch: QuickSearch

    init() {
        let model = KeysteadApp.launchModel()
        _model = State(initialValue: model)
        autoLock = AutoLock(model: model)
        quickSearch = QuickSearch(model: model)
    }

    var body: some Scene {
        // The main window: setting up, browsing and adding logins, people and sharing.
        Window(appName, id: MainWindow.id) {
            MainView(model: model)
            #if DEBUG
                .task { await DebugSnapshots.runIfRequested(model) }
                .task { await DebugMeasure.runIfRequested(model) }
            #endif
        }
        .defaultSize(width: 920, height: 580)
        .commands { AppCommands(model: model) }

        // Quick access from the menu bar: search and copy without opening the window.
        MenuBarExtra {
            PanelView(model: model)
        } label: {
            // Debug builds ("Keystead Dev") show a dot on the icon, so the two are easy to
            // tell apart when both are running. Both are template images, so macOS tints
            // them to match the menu bar.
            #if DEBUG
            Image("MenuBarIcon-Dev")
            #else
            Image("MenuBarIcon")
            #endif
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(model: model)
        }
    }
}

extension KeysteadApp {
    /// The model to start with. Debug builds launched with `-demo` get made-up data.
    @MainActor
    static func launchModel() -> AppModel {
        #if DEBUG
        let arguments = CommandLine.arguments
        if let index = arguments.firstIndex(of: "-demo") {
            let variant = arguments.dropFirst(index + 1).first
            return AppModel.demo(alone: variant == "alone", big: variant == "big")
        }
        #endif
        return AppModel()
    }
}

enum MainWindow {
    static let id = "main"
}

/// "Keystead", or "Keystead Dev" for Debug builds.
let appName = Bundle.main.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String ?? "Keystead"

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        DockIcon.applyPreference()
    }

    /// Closing the window leaves Keystead running in the menu bar.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}

/// Whether Keystead shows in the Dock and the app switcher. It does by default; people
/// who only want the menu bar icon can turn that off in Settings.
enum DockIcon {
    static let preferenceKey = "showInDock"

    static var isShown: Bool {
        UserDefaults.standard.object(forKey: preferenceKey) as? Bool ?? true
    }

    @MainActor
    static func applyPreference() {
        NSApp.setActivationPolicy(isShown ? .regular : .accessory)
    }
}

/// Menu commands for the main window.
private struct AppCommands: Commands {
    let model: AppModel

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("New Login…") { model.sheet = .addLogin(folder: nil) }
                .keyboardShortcut("n")
                .disabled(model.phase != .unlocked)
            Button("New Folder…") { model.sheet = .newFolder(inside: nil) }
                .keyboardShortcut("n", modifiers: [.command, .shift])
                .disabled(model.phase != .unlocked)
            Divider()
            Button("Import from Passbolt or KeePass…") { model.sheet = .importLogins }
                .disabled(model.phase != .unlocked)
            Button("Export Logins…") { model.sheet = .exportLogins }
                .disabled(model.phase != .unlocked)
        }
        CommandGroup(before: .sidebar) {
            Button("All Logins") { model.section = .allLogins }
                .keyboardShortcut("1")
                .disabled(model.phase != .unlocked)
            Button("Shared with Me") { model.section = .sharedWithMe }
                .keyboardShortcut("2")
                .disabled(model.phase != .unlocked || !model.hasSharedWithMe)
            Button("People") { model.section = .people }
                .keyboardShortcut("3")
                .disabled(model.phase != .unlocked)
            Button("Groups") { model.section = .groups }
                .keyboardShortcut("4")
                .disabled(model.phase != .unlocked)
            Divider()
        }
        CommandMenu("Login") {
            let item = model.selectedItem
            Button("Copy Password") {
                if let item { Task { await model.copyPassword(of: item) } }
            }
            .disabled(item == nil)
            Button("Copy Username") {
                if let item { model.copy(item.username) }
            }
            .keyboardShortcut("c", modifiers: [.command, .shift])
            .disabled(item?.username.isEmpty ?? true)
            Button("Copy One-Time Code") {
                if let item { Task { await model.copyOneTimeCode(of: item) } }
            }
            .keyboardShortcut("c", modifiers: [.command, .option])
            .disabled(!(item?.hasOneTimeCode ?? false))
            Divider()
            Button("Edit…") {
                if let item { model.sheet = .editLogin(item) }
            }
            .keyboardShortcut("e")
            .disabled(item == nil || item?.role == .view)
            Button(item?.role == .manage || item == nil ? "Share…" : "Access…") {
                if let item { model.sheet = .shareLogin(item) }
            }
            .disabled(item == nil)
            Button("History…") {
                if let item { model.sheet = .history(item) }
            }
            .keyboardShortcut("y")
            .disabled(item == nil || item?.role == .view)
            Button("Move To…") {
                if let item { model.sheet = .moveLogin(item) }
            }
            .disabled(item.map { !model.canMove($0) } ?? true)
            Divider()
            Button("Delete…") {
                if let item { model.sheet = .deleteLogin(item) }
            }
            .disabled(item == nil || item?.role == .view)
        }
        CommandMenu("Vault") {
            Button("Sync") { Task { await model.refresh() } }
                .keyboardShortcut("r")
                .disabled(model.phase != .unlocked)
            Button("Lock") { model.lock() }
                .keyboardShortcut("l", modifiers: [.command, .shift])
                .disabled(model.phase != .unlocked)
            Divider()
            Button("Sign Out…") { model.sheet = .signOut }
                .disabled(model.phase != .unlocked)
        }
    }
}

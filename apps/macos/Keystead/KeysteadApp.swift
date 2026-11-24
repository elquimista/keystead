import AppKit
import SwiftUI

@main
struct KeysteadApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = AppModel()

    var body: some Scene {
        // The main window: setting up, browsing and adding logins, people and sharing.
        Window(appName, id: MainWindow.id) {
            MainView(model: model)
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
                .disabled(model.phase != .unlocked || model.folders.isEmpty)
            Button("New Folder…") { model.sheet = .newFolder }
                .keyboardShortcut("n", modifiers: [.command, .shift])
                .disabled(model.phase != .unlocked)
        }
        CommandMenu("Vault") {
            Button("Sync") { Task { await model.refresh() } }
                .keyboardShortcut("r")
                .disabled(model.phase != .unlocked)
            Button("Lock") { model.lock() }
                .keyboardShortcut("l", modifiers: [.command, .shift])
                .disabled(model.phase != .unlocked)
        }
    }
}

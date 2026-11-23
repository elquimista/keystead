import SwiftUI

@main
struct KeysteadApp: App {
    var body: some Scene {
        MenuBarExtra("Keystead", systemImage: "key.fill") {
            Text("Keystead")
            Divider()
            Button("Quit Keystead") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q")
        }
    }
}

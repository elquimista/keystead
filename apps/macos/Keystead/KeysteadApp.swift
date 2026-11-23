import SwiftUI

@main
struct KeysteadApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        MenuBarExtra("Keystead", systemImage: "key.fill") {
            MenuContent(model: model)
        }
    }
}

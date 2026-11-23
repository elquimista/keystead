import SwiftUI

struct MenuContent: View {
    let model: AppModel

    var body: some View {
        Text("Keystead \(coreVersion())")
        switch model.state {
        case .noDeviceKey:
            Text("This Mac has no device key yet")
            Button("Create Device Key") { model.createDeviceKey() }
        case .locked:
            Text("Locked")
            Button("Unlock…") { Task { await model.unlock() } }
        case .unlocked(let fingerprint):
            Text("Unlocked · fingerprint \(fingerprint)")
            Button("Lock") { model.lock() }
        }
        if let message = model.message {
            Text(message)
        }
        Divider()
        Button("Quit Keystead") { NSApplication.shared.terminate(nil) }
            .keyboardShortcut("q")
    }
}

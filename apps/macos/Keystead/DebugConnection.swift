#if DEBUG
import AppKit

/// Debug builds only: with `-checkConnection`, connects to servers on the internet from
/// inside the app's sandbox, as the core does, prints whether each certificate was
/// accepted, and quits. No server or Touch ID needed:
///
///   Keystead.app/Contents/MacOS/Keystead -checkConnection
///
/// Each check starts adding a device with a token that doesn't exist, so a server that
/// answers at all (404, say) means the certificate was accepted; "couldn't reach the
/// server" means it wasn't. Nothing about this Mac or its account is sent.
enum DebugConnection {
    @MainActor
    static func runIfRequested() async {
        guard CommandLine.arguments.contains("-checkConnection") else { return }
        let servers = [
            ("https://example.com", "accepted"),
            ("https://self-signed.badssl.com", "refused"),
            ("https://expired.badssl.com", "refused"),
            ("https://wrong.host.badssl.com", "refused"),
        ]
        var lines: [String] = []
        for (server, expected) in servers {
            let outcome = await Task.detached { () -> String in
                do {
                    _ = try DeviceJoin.start(line: "\(server) no-such-token --owner 0", deviceName: "check")
                    return "accepted"
                } catch {
                    let text = describe(error)
                    return text.contains("couldn't reach the server") ? "refused (\(text))" : "accepted (\(text))"
                }
            }.value
            let ok = outcome.hasPrefix(expected)
            lines.append("\(ok ? "ok" : "UNEXPECTED") \(server): \(outcome)")
        }
        print(lines.joined(separator: "\n"))
        NSApp.terminate(nil)
    }
}
#endif

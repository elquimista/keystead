#if DEBUG
import AppKit
import Darwin

/// Debug builds only: with `-measure`, times what the main window's list does on each
/// keystroke with the demo's logins (`-demo big` has 5,000), prints it with the app's memory
/// footprint, and quits. Build with `SWIFT_OPTIMIZATION_LEVEL=-O` for meaningful numbers:
///
///   Keystead.app/Contents/MacOS/Keystead -demo big -measure
enum DebugMeasure {
    @MainActor
    static func runIfRequested(_ model: AppModel) async {
        guard CommandLine.arguments.contains("-measure") else { return }
        // Let the window draw its list first.
        try? await Task.sleep(for: .seconds(2))
        var lines = ["\(model.items.count) logins, memory \(footprint() / 1_000_000) MB"]
        let sections: [(String, AppModel.Section)] = [
            ("all", .allLogins), ("to change", .toChange), ("health", .health),
        ]
        for (label, section) in sections {
            for query in ["", "l", "lo", "login 4", "user42 prod"] {
                let time = median(of: 15) { _ = model.items(matching: query, in: section) }
                lines.append(String(format: "%@ %@: %.2f ms", label, "\"\(query)\"", time))
            }
        }
        // Quick search: the first time ranks every login by name; then per keystroke.
        let first = median(of: 1) { _ = model.quickSearch("l") }
        lines.append(String(format: "quick search, first: %.2f ms", first))
        for query in ["l", "lo", "login 4", "user42 prod"] {
            let time = median(of: 15) { _ = model.quickSearch(query) }
            lines.append(String(format: "quick search %@: %.2f ms", "\"\(query)\"", time))
        }
        print(lines.joined(separator: "\n"))
        NSApp.terminate(nil)
    }

    /// The median time of `runs` runs, in milliseconds.
    @MainActor
    private static func median(of runs: Int, _ work: () -> Void) -> Double {
        let clock = ContinuousClock()
        let times = (0..<runs).map { _ in
            let elapsed = clock.measure(work)
            return Double(elapsed.components.attoseconds) / 1e15
                + Double(elapsed.components.seconds) * 1000
        }.sorted()
        return times[runs / 2]
    }

    /// Memory the system charges this app for, in bytes.
    private static func footprint() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? info.phys_footprint : 0
    }
}
#endif

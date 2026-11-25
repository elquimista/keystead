import AppKit
import SwiftUI

extension View {
    /// Lets the window around this view follow its height smoothly, as AppKit's tabbed
    /// preference windows and sheets do, instead of jumping to it. The view keeps its own
    /// height at the top of the window while the window glides to fit it.
    ///
    /// SwiftUI otherwise sizes a window to its content's size, so a new tab, a sheet's next
    /// step or a shorter list resizes the window in a single frame.
    func windowFollowsHeight() -> some View {
        modifier(WindowFollowsHeight())
    }
}

private struct WindowFollowsHeight: ViewModifier {
    @State private var window: NSWindow?
    /// The view's own height: what the window should fit.
    @State private var height: CGFloat?
    /// The height the window has come to rest at. SwiftUI is told it's the ideal height,
    /// so windows that size themselves to their content (like the menu bar panel's) stay
    /// put while the window animates, rather than jumping ahead to the new height.
    @State private var settled: CGFloat?
    /// When the window turned up: changes while it's still appearing, like a sheet whose
    /// content was already loaded, apply at once rather than animate.
    @State private var foundAt = ContinuousClock.now
    /// Counts resizes, so only the last one to finish sets the resting height.
    @State private var generation = 0

    func body(content: Content) -> some View {
        content
            .fixedSize(horizontal: false, vertical: true)
            .background {
                GeometryReader { proxy in
                    Color.clear.preference(key: NaturalHeight.self, value: proxy.size.height)
                }
            }
            .onPreferenceChange(NaturalHeight.self) { newHeight in
                height = newHeight
                fit()
            }
            // Any height is fine to SwiftUI, so the window's size is ours to animate.
            .frame(minHeight: 0, idealHeight: settled, maxHeight: .infinity, alignment: .top)
            .background(WindowReader { found in
                // SwiftUI keeps a tab's views while another tab shows and puts them back
                // in the same window: that's not the window appearing.
                guard window !== found else { return }
                window = found
                foundAt = .now
                fit()
            })
    }

    /// Resizes the window so its content area is exactly the view's height, keeping its top
    /// edge (AppKit keeps a sheet centred on its window instead): animated once it's on
    /// screen, at once while it's appearing or when motion is reduced.
    private func fit() {
        guard let window, let height, height > 0 else { return }
        generation += 1
        let chrome = window.frame.height - window.contentLayoutRect.height
        let target = (height + chrome).rounded()
        guard abs(window.frame.height - target) >= 1 else {
            settled = height
            return
        }
        var frame = window.frame
        frame.origin.y = frame.maxY - target
        frame.size.height = target
        let appearing = ContinuousClock.now - foundAt < .milliseconds(300)
        let animate = window.isVisible && !appearing
            && !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        let resize = generation
        NSAnimationContext.runAnimationGroup { context in
            // A zero-length animation also stops one still running towards an older height.
            context.duration = animate ? 0.22 : 0
            context.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
            window.animator().setFrame(frame, display: true)
        } completionHandler: {
            DispatchQueue.main.async {
                if generation == resize { settled = height }
            }
        }
    }
}

private struct NaturalHeight: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}

/// Finds the window a view is in.
private struct WindowReader: NSViewRepresentable {
    let found: (NSWindow) -> Void

    func makeNSView(context: Context) -> ReaderView {
        ReaderView(found: found)
    }

    func updateNSView(_ view: ReaderView, context: Context) {
        view.found = found
    }

    final class ReaderView: NSView {
        var found: (NSWindow) -> Void

        init(found: @escaping (NSWindow) -> Void) {
            self.found = found
            super.init(frame: .zero)
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) {
            nil
        }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let window else { return }
            // Not during the layout that put this view in the window.
            DispatchQueue.main.async { [found] in found(window) }
        }
    }
}

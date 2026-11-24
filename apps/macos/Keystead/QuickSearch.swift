import AppKit
import Carbon.HIToolbox
import SwiftUI

/// The shortcut that opens quick search from any app.
enum QuickSearchShortcut: String, CaseIterable, Identifiable {
    case shiftCommandSpace, optionCommandK, controlOptionCommandK, off

    static let preferenceKey = "quickSearchShortcut"
    /// 1Password's choice for the same thing, and free in macOS by default.
    static let standard = QuickSearchShortcut.shiftCommandSpace

    static var current: QuickSearchShortcut {
        UserDefaults.standard.string(forKey: preferenceKey).flatMap(Self.init(rawValue:)) ?? .standard
    }

    var id: String { rawValue }

    var label: String {
        switch self {
        case .shiftCommandSpace: "⇧⌘Space"
        case .optionCommandK: "⌥⌘K"
        case .controlOptionCommandK: "⌃⌥⌘K"
        case .off: "Off"
        }
    }

    /// The Carbon key code and modifiers, or nil when off.
    fileprivate var hotKey: (keyCode: UInt32, modifiers: UInt32)? {
        switch self {
        case .shiftCommandSpace: (UInt32(kVK_Space), UInt32(shiftKey | cmdKey))
        case .optionCommandK: (UInt32(kVK_ANSI_K), UInt32(optionKey | cmdKey))
        case .controlOptionCommandK: (UInt32(kVK_ANSI_K), UInt32(controlKey | optionKey | cmdKey))
        case .off: nil
        }
    }
}

/// Quick search: a Spotlight-style box that the shortcut opens over any app. Type to find a
/// login, Return copies its password and closes the box, so the app you were in is still
/// in front, ready to paste.
@MainActor
final class QuickSearch: NSObject, NSWindowDelegate {
    /// The one quick search, so Settings can change its shortcut.
    private(set) static weak var shared: QuickSearch?

    private let model: AppModel
    private var hotKey: HotKey?
    private var panel: QuickSearchPanel?
    private var state: QuickSearchState?
    private var keyMonitor: Any?

    init(model: AppModel) {
        self.model = model
        super.init()
        Self.shared = self
        applyShortcut()
    }

    /// Registers the shortcut chosen in Settings. Returns false if macOS refused it, for
    /// example because another app already has it.
    @discardableResult
    func applyShortcut() -> Bool {
        hotKey = nil
        guard let (keyCode, modifiers) = QuickSearchShortcut.current.hotKey else { return true }
        hotKey = HotKey(keyCode: keyCode, modifiers: modifiers) { [weak self] in self?.toggle() }
        return hotKey != nil
    }

    /// Whether macOS accepted the shortcut.
    var isShortcutRegistered: Bool { hotKey != nil }

    func toggle() {
        if panel?.isVisible == true {
            close()
        } else {
            show()
        }
    }

    /// Opens the box on the screen with the pointer, a third of the way down, like Spotlight.
    func show(query: String = "") {
        let state = QuickSearchState(model: model)
        state.query = query
        self.state = state
        let panel = self.panel ?? makePanel()
        self.panel = panel
        panel.contentView = NSHostingView(rootView: QuickSearchView(
            state: state,
            copy: { [weak self] item, username in self?.copy(username ? .username : .password, of: item) }))
        let size = panel.contentView?.fittingSize ?? NSSize(width: 640, height: 400)
        let screen = NSScreen.screens.first { NSMouseInRect(NSEvent.mouseLocation, $0.frame, false) }
            ?? NSScreen.main
        if let area = screen?.visibleFrame {
            panel.setFrame(
                NSRect(
                    x: area.midX - size.width / 2, y: area.maxY - area.height / 3 - size.height / 2,
                    width: size.width, height: size.height),
                display: false)
        }
        panel.makeKeyAndOrderFront(nil)
        watchKeys()
    }

    func close() {
        panel?.orderOut(nil)
        if let keyMonitor {
            NSEvent.removeMonitor(keyMonitor)
            self.keyMonitor = nil
        }
        state = nil
    }

    func windowDidResignKey(_ notification: Notification) {
        // Clicking anywhere else closes it, like Spotlight.
        close()
    }

    private func makePanel() -> QuickSearchPanel {
        let panel = QuickSearchPanel(
            contentRect: NSRect(x: 0, y: 0, width: 640, height: 400),
            styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
        panel.isFloatingPanel = true
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        panel.hidesOnDeactivate = false
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.isReleasedWhenClosed = false
        panel.delegate = self
        return panel
    }

    /// Arrows, Return and Escape steer the list while the search field keeps the typing.
    private func watchKeys() {
        if keyMonitor != nil { return }
        keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            MainActor.assumeIsolated {
                guard let self, let state = self.state, event.window === self.panel else {
                    return event
                }
                switch Int(event.keyCode) {
                case kVK_DownArrow:
                    state.move(by: 1)
                case kVK_UpArrow:
                    state.move(by: -1)
                case kVK_Return, kVK_ANSI_KeypadEnter:
                    let what: Copy = event.modifierFlags.contains(.shift) ? .username
                        : event.modifierFlags.contains(.option) ? .oneTimeCode : .password
                    Task { await state.activate { item in self.copy(what, of: item) } }
                case kVK_Escape:
                    self.close()
                default:
                    return event
                }
                return nil
            }
        }
    }

    private enum Copy { case password, username, oneTimeCode }

    private func copy(_ what: Copy, of item: ItemSummary) {
        close()
        switch what {
        case .password: Task { await model.copyPassword(of: item) }
        case .username: model.copy(item.username)
        case .oneTimeCode: Task { await model.copyOneTimeCode(of: item) }
        }
    }
}

/// A borderless panel that can still take the keyboard, without bringing Keystead to the
/// front: the app you were in stays active.
final class QuickSearchPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

/// What quick search shows: the query, the matching logins and which one is picked.
@MainActor
@Observable
final class QuickSearchState {
    let model: AppModel
    var query = "" {
        didSet { selection = 0 }
    }
    var selection = 0

    init(model: AppModel) {
        self.model = model
    }

    /// Matching logins, those whose name starts with the first word first.
    var results: [ItemSummary] {
        let first = query.lowercased().split(whereSeparator: \.isWhitespace).first.map(String.init)
        let matches = model.items(matching: query)
        return Array(
            matches.sorted { a, b in
                let aStarts = first.map { a.name.lowercased().hasPrefix($0) } ?? false
                let bStarts = first.map { b.name.lowercased().hasPrefix($0) } ?? false
                if aStarts != bStarts { return aStarts }
                return a.name.localizedStandardCompare(b.name) == .orderedAscending
            }
            .prefix(50))
    }

    func move(by step: Int) {
        let count = results.count
        guard count > 0 else { return }
        selection = min(max(selection + step, 0), count - 1)
    }

    /// Return: unlock first if locked, otherwise hand the picked login to `copy`.
    func activate(copy: (ItemSummary) -> Void) async {
        switch model.phase {
        case .locked:
            await model.unlock()
        case .unlocked:
            let results = results
            if results.indices.contains(selection) {
                copy(results[selection])
            }
        case .welcome, .working:
            break
        }
    }
}

struct QuickSearchView: View {
    @Bindable var state: QuickSearchState
    let copy: (ItemSummary, _ username: Bool) -> Void
    @FocusState private var searchFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "magnifyingglass")
                    .font(.title2)
                    .foregroundStyle(.secondary)
                TextField("Search logins", text: $state.query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 22))
                    .focused($searchFocused)
                    .disabled(state.model.phase != .unlocked)
            }
            .padding(16)
            Divider()
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            Text(hint)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 8)
        }
        .frame(width: 640, height: 400)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(.quaternary))
        .onAppear { searchFocused = true }
        .onChange(of: state.model.phase) { searchFocused = true }
    }

    private var hint: String {
        switch state.model.phase {
        case .unlocked: "↩ password    ⇧↩ username    ⌥↩ one-time code    ↑↓ choose    esc close"
        case .locked: "↩ unlock    esc close"
        default: "esc close"
        }
    }

    @ViewBuilder
    private var content: some View {
        switch state.model.phase {
        case .unlocked:
            let results = state.results
            if results.isEmpty {
                Text(state.query.trimmed.isEmpty ? "No logins yet." : "No logins match.")
                    .foregroundStyle(.secondary)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 2) {
                            ForEach(Array(results.enumerated()), id: \.element.id) { index, item in
                                row(item, selected: index == state.selection)
                                    .id(item.id)
                                    .onTapGesture { copy(item, false) }
                            }
                        }
                        .padding(8)
                    }
                    .onChange(of: state.selection) {
                        if results.indices.contains(state.selection) {
                            proxy.scrollTo(results[state.selection].id)
                        }
                    }
                }
            }
        case .locked:
            VStack(spacing: 10) {
                Image(systemName: "lock.fill")
                    .font(.largeTitle)
                    .foregroundStyle(.secondary)
                Text("\(appName) is locked")
                    .font(.headline)
                Button("Unlock") { Task { await state.model.unlock() } }
            }
        case .welcome:
            Text("Set up \(appName) in its window first.")
                .foregroundStyle(.secondary)
        case .working(let note):
            ProgressView(note)
        }
    }

    private func row(_ item: ItemSummary, selected: Bool) -> some View {
        HStack(spacing: 10) {
            Image(systemName: "key")
                .foregroundStyle(selected ? .white : .secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name)
                    .foregroundStyle(selected ? .white : .primary)
                Text(item.username.isEmpty ? item.place : "\(item.username) · \(item.place)")
                    .font(.caption)
                    .foregroundStyle(selected ? .white.opacity(0.85) : .secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(
            selected ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.clear),
            in: RoundedRectangle(cornerRadius: 8))
        .contentShape(Rectangle())
    }
}

/// A system-wide keyboard shortcut, through Carbon's hot key API. It needs no Accessibility
/// permission and works inside the App Sandbox; macOS only ever tells the app that its own
/// shortcut was pressed.
@MainActor
private final class HotKey {
    private var reference: EventHotKeyRef?
    private var handler: EventHandlerRef?
    private let action: () -> Void

    /// Nil if macOS refused, for example because another app already registered it.
    init?(keyCode: UInt32, modifiers: UInt32, action: @escaping () -> Void) {
        self.action = action
        var pressed = EventTypeSpec(
            eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        let installed = InstallEventHandler(
            GetApplicationEventTarget(),
            { _, _, context in
                guard let context else { return OSStatus(eventNotHandledErr) }
                let hotKey = Unmanaged<HotKey>.fromOpaque(context).takeUnretainedValue()
                MainActor.assumeIsolated { hotKey.action() }
                return noErr
            },
            1, &pressed, Unmanaged.passUnretained(self).toOpaque(), &handler)
        guard installed == noErr else { return nil }
        // "KSTD": Keystead's hot key signature.
        let id = EventHotKeyID(signature: 0x4B53_5444, id: 1)
        let registered = RegisterEventHotKey(
            keyCode, modifiers, id, GetApplicationEventTarget(), 0, &reference)
        guard registered == noErr else {
            if let handler { RemoveEventHandler(handler) }
            return nil
        }
    }

    deinit {
        if let reference { UnregisterEventHotKey(reference) }
        if let handler { RemoveEventHandler(handler) }
    }
}

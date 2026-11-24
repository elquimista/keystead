import AppKit
import CryptoKit
import Foundation
import LocalAuthentication
import Observation
import SystemConfiguration

/// The app's state and actions, shared by the main window and the menu bar panel. The Rust
/// `Vault` does the real work; every call into it runs off the main thread because it may
/// wait on the network or disk.
@MainActor
@Observable
final class AppModel {
    enum Phase: Equatable {
        /// This Mac isn't set up yet.
        case welcome
        case working(String)
        case locked
        case unlocked
    }

    /// What the main window shows, chosen in its sidebar or the Go menu.
    enum Section: Hashable {
        case allLogins
        case folder(String)
        case people
    }

    /// The sheet the main window shows, if any.
    enum Sheet: Identifiable {
        case addLogin(folder: String?)
        case changePassword(ItemSummary)
        case newFolder
        case share(folder: String?, user: User?)
        case invite
        case approve(User)
        /// After joining: the fingerprint to read to the owner.
        case fingerprint
        /// The recovery kit; right after setup it first explains why it matters.
        case recoveryKit(afterSetup: Bool)

        var id: String {
            switch self {
            case .addLogin(let folder): "add-\(folder ?? "")"
            case .changePassword(let item): "change-\(item.id)"
            case .newFolder: "new-folder"
            case .share(let folder, let user): "share-\(folder ?? "")-\(user?.userId ?? 0)"
            case .invite: "invite"
            case .approve(let user): "approve-\(user.userId)"
            case .fingerprint: "fingerprint"
            case .recoveryKit: "recovery-kit"
            }
        }
    }

    private(set) var phase: Phase
    private(set) var identity: Identity?
    private(set) var items: [ItemSummary] = []
    private(set) var folders: [String] = []
    private(set) var users: [User] = []
    /// This account's devices, this Mac included.
    private(set) var devices: [AccountDevice] = []
    /// Why the device list couldn't be loaded, such as a server older than 0.2.0.
    private(set) var devicesProblem: String?
    /// A short note: why the last action failed, or what sync skipped.
    private(set) var message: String?
    /// The login whose password is on the clipboard, until it's cleared.
    private(set) var copiedName: String?
    var sheet: Sheet?
    var section: Section? = .allLogins
    /// The login or person selected in the main window's list.
    var selectedItemID: ItemSummary.ID?
    var selectedUserID: User.ID?
    /// The menu bar panel's search.
    var search = ""

    private var vault: Vault?
    private let store = DeviceStore()
    private let clipboard = SecureClipboard()
    private var copiedNoticeTask: Task<Void, Never>?
    #if DEBUG
    /// Demo mode: made-up data, no vault and no Touch ID.
    private(set) var isDemo = false
    #endif

    init() {
        phase = store.isEnrolled ? .locked : .welcome
    }

    var isOwner: Bool { identity?.isOwner ?? false }

    /// Logins matching every word of `query` in name, username, URL or folder.
    func items(matching query: String, in folder: String? = nil) -> [ItemSummary] {
        let words = query.lowercased().split(whereSeparator: \.isWhitespace)
        return items.filter { item in
            guard folder == nil || item.folder == folder else { return false }
            let text = "\(item.name) \(item.username) \(item.url) \(item.folder)".lowercased()
            return words.allSatisfy { text.contains($0) }
        }
    }

    var filteredItems: [ItemSummary] { items(matching: search) }

    // MARK: - Setting up this Mac

    /// Claims a new server with its setup code. This Mac's account becomes the owner.
    func setUp(server: String, setupCode: String, name: String) async {
        let server = server.trimmingCharacters(in: .whitespacesAndNewlines)
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let done = await enroll(working: "Setting up your team…") {
            profilePath, secret, deviceId, deviceName, signer in
            try Vault.setup(
                profilePath: profilePath, server: server, setupCode: setupCode, name: name,
                accountSecret: secret, deviceId: deviceId, deviceName: deviceName, signer: signer)
        }
        if done {
            // The owner's account exists only on this Mac until there's a kit.
            sheet = .recoveryKit(afterSetup: true)
        }
    }

    /// Joins a team with an invite. Afterwards the user reads their fingerprint to the
    /// owner, who approves them.
    func join(invite text: String) async {
        let invite: Invitation
        do {
            invite = try parseInvite(text: text)
        } catch {
            message = "That doesn't look like an invite. Paste the whole line, starting with "
                + "\"keystead join\"."
            return
        }
        let joined = await enroll(working: "Joining…") {
            profilePath, secret, deviceId, deviceName, signer in
            try Vault.join(
                profilePath: profilePath, server: invite.server, token: invite.token,
                ownerFingerprint: invite.ownerFingerprint, accountSecret: secret,
                deviceId: deviceId, deviceName: deviceName, signer: signer)
        }
        if joined {
            sheet = .fingerprint
        }
    }

    /// Brings an account back on this Mac with the 24 words from its recovery kit. The
    /// owner's fingerprint from the kit is checked before anything is registered.
    func recover(server: String, ownerFingerprint: String, words: String) async {
        let server = server.trimmingCharacters(in: .whitespacesAndNewlines)
        let secret: SymmetricKey
        do {
            secret = SymmetricKey(data: try accountSecretFromRecoveryWords(words: words))
        } catch {
            // For example "word 7 isn't on the recovery kit word list".
            message = "Check the words: \(describe(error))."
            return
        }
        let recovered = await enroll(working: "Recovering your account…", secret: secret) {
            profilePath, secret, deviceId, deviceName, signer in
            try Vault.recover(
                profilePath: profilePath, server: server, ownerFingerprint: ownerFingerprint,
                accountSecret: secret, deviceId: deviceId, deviceName: deviceName, signer: signer)
        }
        if recovered, let identity {
            // Show the account's devices, so the lost Mac can be removed.
            section = .people
            selectedUserID = identity.userId
        }
    }

    /// Creates both Secure Enclave keys, wraps the account secret (a new one, unless
    /// recovering) to them, then runs `create` to set up, join or recover. One Touch ID
    /// approval covers the whole thing.
    @discardableResult
    private func enroll(
        working: String,
        secret: SymmetricKey = SymmetricKey(size: .bits256),
        create: @escaping @Sendable (
            _ profilePath: String, _ secret: Data, _ deviceId: String, _ deviceName: String,
            _ signer: SecureEnclaveSigner
        ) throws -> Vault
    ) async -> Bool {
        message = nil
        phase = .working(working)
        do {
            let agreementKey = try SecureEnclaveDeviceKey.create()
            let signingKey = try SecureEnclaveSigningKey.create()
            let device = DeviceStore.Device(
                deviceId: newDeviceId(),
                agreementKey: agreementKey.dataRepresentation,
                signingKey: signingKey.dataRepresentation,
                accountSecret: try AccountSecretWrap.wrap(secret, to: agreementKey.publicKey))
            try store.save(device)

            let context = try await DeviceAuthentication.authenticate(
                reason: "set up Keystead on this Mac")
            let signer = SecureEnclaveSigner(
                key: try SecureEnclaveSigningKey.restore(from: device.signingKey, context: context))
            let secretBytes = secret.withUnsafeBytes { Data($0) }
            let profilePath = store.profileURL.path
            let deviceId = device.deviceId
            let deviceName = Self.thisMacName
            let vault = try await Task.detached {
                try create(profilePath, secretBytes, deviceId, deviceName, signer)
            }.value
            try await finishUnlocking(vault)
            return true
        } catch {
            store.removeDevice()
            phase = .welcome
            message = describe(error)
            return false
        }
    }

    // MARK: - Locking

    func unlock() async {
        message = nil
        phase = .working("Unlocking…")
        do {
            let device = try store.load()
            let context = try await DeviceAuthentication.authenticate(reason: "unlock Keystead")
            let agreementKey = try SecureEnclaveDeviceKey.restore(
                from: device.agreementKey, context: context)
            let secret = try AccountSecretWrap.unwrap(device.accountSecret, with: agreementKey.privateKey)
            let signer = SecureEnclaveSigner(
                key: try SecureEnclaveSigningKey.restore(from: device.signingKey, context: context))
            let secretBytes = secret.withUnsafeBytes { Data($0) }
            let profilePath = store.profileURL.path
            let vault = try await Task.detached {
                try Vault.open(profilePath: profilePath, accountSecret: secretBytes, signer: signer)
            }.value
            try await finishUnlocking(vault)
        } catch {
            phase = .locked
            message = describe(error)
        }
    }

    /// Drops the unlocked vault; its keys are freed with it.
    func lock() {
        vault = nil
        items = []
        folders = []
        users = []
        devices = []
        devicesProblem = nil
        search = ""
        sheet = nil
        section = .allLogins
        selectedItemID = nil
        selectedUserID = nil
        copiedName = nil
        message = nil
        phase = .locked
    }

    private func finishUnlocking(_ vault: Vault) async throws {
        self.vault = vault
        identity = try vault.identity()
        phase = .unlocked
        await refresh()
    }

    // MARK: - Reading

    /// Fetches changes and the people on the server. If the server can't be reached,
    /// keeps showing the copy on this Mac.
    func refresh() async {
        do {
            let result = try await perform { try $0.sync() }
            users = try await perform { try $0.users() }
            message = result.rejected > 0
                ? "Ignored \(result.rejected) item(s) not signed by an approved user." : nil
        } catch {
            message = "Couldn't sync (\(describe(error))). Showing the copy on this Mac."
        }
        await reloadLocal()
        await reloadDevices()
    }

    /// Loads the device list on its own, so an older server that has no device list
    /// doesn't make syncing look broken.
    private func reloadDevices() async {
        do {
            devices = try await perform { try $0.devices() }
            devicesProblem = nil
        } catch {
            devices = []
            devicesProblem = describe(error)
        }
    }

    func password(of item: ItemSummary) async throws -> String {
        try await perform { try $0.password(itemId: item.id) }
    }

    /// Copies a password to this Mac's clipboard only, cleared after 30 seconds.
    func copyPassword(of item: ItemSummary) async {
        do {
            clipboard.copy(try await password(of: item))
            copiedName = item.name
            copiedNoticeTask?.cancel()
            copiedNoticeTask = Task {
                try? await Task.sleep(for: SecureClipboard.clearAfter)
                if !Task.isCancelled { copiedName = nil }
            }
        } catch {
            message = describe(error)
        }
    }

    func dismissMessage() {
        message = nil
    }

    /// Copies something that isn't secret, like a username or an invite.
    func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    // MARK: - Changing things (each throws, so the sheet that asked can show why)

    func addLogin(folder: String, name: String, username: String, url: String, password: String)
        async throws
    {
        try await perform {
            try $0.addLogin(folder: folder, name: name, username: username, url: url, password: password)
        }
        await reloadLocal()
    }

    /// Returns a note if someone else changed the password first.
    func changePassword(of item: ItemSummary, to password: String) async throws -> String? {
        let outcome = try await perform { try $0.changePassword(itemId: item.id, password: password) }
        await reloadLocal()
        switch outcome {
        case .saved:
            return nil
        case .conflict(_, let author):
            return "\(author) changed this password first, so yours wasn't saved. Copying it "
                + "now gives you their version; change it again if you still need to."
        }
    }

    func createFolder(named name: String) async throws {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        try await perform { try $0.createFolder(name: name) }
        await reloadLocal()
    }

    func share(folder: String, with user: User) async throws {
        _ = try await perform { try $0.shareFolder(folder: folder, userId: user.userId) }
    }

    /// Creates a single-use invite (owner only).
    func invite(name: String) async throws -> Invitation {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return try await perform { try $0.invite(name: name) }
    }

    /// Approves a user (owner only) if the fingerprint they read out matches their keys.
    func approve(_ user: User, fingerprint: String) async throws {
        _ = try await perform { try $0.approve(userId: user.userId, fingerprint: fingerprint) }
        users = try await perform { try $0.users() }
    }

    // MARK: - Recovery kit and devices

    /// The recovery kit: the account secret as 24 words, after Touch ID. Nothing keeps it;
    /// it's only shown, and printed if the user asks.
    func recoveryKit() async throws -> RecoveryKit {
        guard let identity else { throw AppError("Unlock Keystead first.") }
        let secret: Data
        #if DEBUG
        if isDemo {
            return RecoveryKit(
                words: try recoveryWords(accountSecret: Data(count: 32)), identity: identity)
        }
        #endif
        let device = try store.load()
        let context = try await DeviceAuthentication.authenticate(reason: "show your recovery kit")
        let agreementKey = try SecureEnclaveDeviceKey.restore(from: device.agreementKey, context: context)
        secret = try AccountSecretWrap.unwrap(device.accountSecret, with: agreementKey.privateKey)
            .withUnsafeBytes { Data($0) }
        return RecoveryKit(words: try recoveryWords(accountSecret: secret), identity: identity)
    }

    /// Removes another of this account's devices, such as a lost Mac.
    func removeDevice(_ device: AccountDevice) async throws {
        let id = device.deviceId
        try await perform { try $0.removeDevice(deviceId: id) }
        await reloadDevices()
    }

    /// How this Mac shows in the device list: its name from Sharing settings.
    static var thisMacName: String {
        (SCDynamicStoreCopyComputerName(nil, nil) as String?) ?? "Mac"
    }

    // MARK: -

    private func reloadLocal() async {
        do {
            items = try await perform { try $0.items() }
            folders = try await perform { try $0.folders() }
        } catch {
            message = describe(error)
        }
    }

    /// Runs a blocking call on the vault off the main thread.
    private func perform<T: Sendable>(_ work: @escaping @Sendable (Vault) throws -> T) async throws -> T {
        guard let vault else { throw AppError("Keystead is locked.") }
        return try await Task.detached { try work(vault) }.value
    }
}

#if DEBUG
extension AppModel {
    /// A model filled with made-up data and no vault, for looking at the main window
    /// without a server or Touch ID. Debug builds only: launch with `-demo`, or with
    /// `-demo alone` for an owner who hasn't invited anyone yet. Actions that need the
    /// vault fail with "Keystead is locked."
    static func demo(alone: Bool) -> AppModel {
        let model = AppModel()
        model.isDemo = true
        model.phase = .unlocked
        model.identity = Identity(
            name: "Olivia", userId: 1, fingerprint: "ab12-cd34-ef56-7890-abcd",
            server: "https://keys.example.com", isOwner: true,
            ownerFingerprint: "ab12-cd34-ef56-7890-abcd")
        model.users = [User(userId: 1, name: "Olivia", approved: true, isOwner: true)]
        model.devices = [
            AccountDevice(
                deviceId: "00000000-0000-4000-8000-0000000000d1", name: "Olivia's MacBook Air",
                addedAt: 1_760_000_000, current: false),
            AccountDevice(
                deviceId: "00000000-0000-4000-8000-0000000000d2", name: "Olivia's MacBook Pro",
                addedAt: 1_795_000_000, current: true),
        ]
        if !alone {
            model.users += [
                User(userId: 2, name: "Mo", approved: true, isOwner: false),
                User(userId: 3, name: "Sam", approved: false, isOwner: false),
            ]
            model.folders = ["Production", "Staging"]
            model.items = [
                ItemSummary(
                    id: "00000000-0000-4000-8000-000000000001", folder: "Production",
                    name: "AWS root", username: "root@example.com", url: "https://aws.amazon.com"),
                ItemSummary(
                    id: "00000000-0000-4000-8000-000000000002", folder: "Staging",
                    name: "Database", username: "admin", url: ""),
            ]
        }
        return model
    }

    /// Shows both notices at the bottom of the window, as after a failed sync and a copy.
    func showDemoNotices() {
        message = "Couldn't sync (couldn't reach the server). Showing the copy on this Mac."
        copiedName = "AWS root"
    }
}
#endif

/// A recovery kit's contents: the secret's 24 words and what's needed to use them.
struct RecoveryKit {
    let words: [String]
    let name: String
    let server: String
    let fingerprint: String
    let ownerFingerprint: String

    init(words: String, identity: Identity) {
        self.words = words.split(separator: " ").map(String.init)
        name = identity.name
        server = identity.server
        fingerprint = identity.fingerprint
        ownerFingerprint = identity.ownerFingerprint
    }
}

extension ItemSummary: Identifiable {}

extension User: Identifiable {
    public var id: Int64 { userId }
}

struct AppError: LocalizedError {
    let errorDescription: String?

    init(_ message: String) {
        errorDescription = message
    }
}

/// A short, readable reason for an error.
func describe(_ error: Error) -> String {
    if let error = error as? CoreError {
        switch error {
        case .InvalidInput(let message), .Failed(let message):
            return message
        }
    }
    if let error = error as? LAError, error.code == .userCancel || error.code == .appCancel {
        return "Cancelled."
    }
    return error.localizedDescription
}

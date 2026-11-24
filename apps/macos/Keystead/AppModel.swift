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

    /// What the main window shows, chosen in its sidebar or the View menu.
    enum Section: Hashable {
        case allLogins
        /// Logins shared with you one by one, outside your folders.
        case sharedWithMe
        case folder(String)
        /// Logins whose passwords someone who lost access may still know.
        case toChange
        /// Logins deleted in the last 30 days, which can still be brought back.
        case recentlyDeleted
        case people
        case groups
    }

    /// The sheet the main window shows, if any.
    enum Sheet: Identifiable {
        case addLogin(folder: String?)
        case editLogin(ItemSummary)
        case history(ItemSummary)
        case deleteLogin(ItemSummary)
        case shareLogin(ItemSummary)
        case newFolder
        case share(folder: String?, user: User?)
        /// Shares one of your folders with a group, from the group's page.
        case shareWithGroup(GroupSummary)
        /// Who is in a folder, with their roles; managers change them here.
        case manageFolder(String)
        /// The owner removes someone from the team.
        case removeUser(User)
        /// Adding another device to this account from this Mac.
        case addDevice
        case invite
        case approve(User)
        /// After joining: the fingerprint to read to the owner.
        case fingerprint
        /// The recovery kit; right after setup it first explains why it matters.
        case recoveryKit(afterSetup: Bool)
        case signOut
        case newGroup
        case addToGroup(GroupSummary)
        case renameGroup(GroupSummary)

        var id: String {
            switch self {
            case .addLogin(let folder): "add-\(folder ?? "")"
            case .history(let item): "history-\(item.id)"
            case .editLogin(let item): "edit-\(item.id)"
            case .deleteLogin(let item): "delete-\(item.id)"
            case .shareLogin(let item): "share-login-\(item.id)"
            case .newFolder: "new-folder"
            case .share(let folder, let user): "share-\(folder ?? "")-\(user?.userId ?? 0)"
            case .shareWithGroup(let group): "share-with-group-\(group.id)"
            case .manageFolder(let folder): "manage-\(folder)"
            case .removeUser(let user): "remove-user-\(user.userId)"
            case .addDevice: "add-device"
            case .invite: "invite"
            case .approve(let user): "approve-\(user.userId)"
            case .fingerprint: "fingerprint"
            case .recoveryKit: "recovery-kit"
            case .signOut: "sign-out"
            case .newGroup: "new-group"
            case .addToGroup(let group): "add-to-group-\(group.id)"
            case .renameGroup(let group): "rename-group-\(group.id)"
            }
        }
    }

    private(set) var phase: Phase
    private(set) var identity: Identity?
    private(set) var items: [ItemSummary] = []
    private(set) var folders: [String] = []
    /// Your role in each folder, by name.
    private(set) var folderRoles: [String: Role] = [:]
    private(set) var users: [User] = []
    /// The team's groups, by name.
    private(set) var groups: [GroupSummary] = []
    /// Passwords to change: who lost access to which logins you can change, most recent
    /// first.
    private(set) var toChange: [ToChange] = []
    /// Logins deleted in the last 30 days that you can bring back, newest first.
    private(set) var recentlyDeleted: [DeletedLogin] = []
    /// The server keeps deleted logins for 30 days (0.9.0 and later).
    private(set) var keepsDeleted = false
    var selectedDeletedID: DeletedLogin.ID?
    /// This account's devices, this Mac included.
    private(set) var devices: [AccountDevice] = []
    /// Why the device list couldn't be loaded, such as a server older than 0.2.0.
    private(set) var devicesProblem: String?
    /// A short note: why the last action failed, or what sync skipped.
    private(set) var message: String?
    /// The login whose password is on the clipboard, until it's cleared.
    private(set) var copiedName: String?
    /// What was copied for `copiedName`: "password" or "one-time code".
    private(set) var copiedWhat = "password"
    /// Goes up each time the logins are reloaded from this Mac's copy, so views that show
    /// something decrypted (like a one-time code) know to fetch it again.
    private(set) var localRevision = 0
    var sheet: Sheet?
    var section: Section? = .allLogins
    /// The login or person selected in the main window's list.
    var selectedItemID: ItemSummary.ID?
    var selectedUserID: User.ID?
    var selectedGroupID: GroupSummary.ID?
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

    /// Logins in `section` matching every word of `query` in name, username, URL, folder or
    /// who shared them.
    func items(matching query: String, in section: Section = .allLogins) -> [ItemSummary] {
        let words = query.lowercased().split(whereSeparator: \.isWhitespace)
        return items.filter { item in
            switch section {
            case .folder(let folder): guard item.folder == folder else { return false }
            case .sharedWithMe: guard item.sharedWithMe else { return false }
            case .toChange: guard toChange.contains(where: { $0.itemId == item.id }) else { return false }
            case .recentlyDeleted: return false
            case .allLogins, .people, .groups: break
            }
            let text = "\(item.name) \(item.username) \(item.url) \(item.folder ?? "") \(item.owner ?? "")"
                .lowercased()
            return words.allSatisfy { text.contains($0) }
        }
    }

    /// Whether any login was shared with you one by one, so the sidebar shows them.
    var hasSharedWithMe: Bool { items.contains(where: \.sharedWithMe) }

    /// Who lost access to this login while its password stayed the same, most recent first.
    func toChange(for item: ItemSummary) -> [ToChange] {
        toChange.filter { $0.itemId == item.id }
    }

    /// How many logins are on the To Change list.
    var toChangeCount: Int { Set(toChange.map(\.itemId)).count }

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
    /// owner's fingerprint from the kit is checked before anything is registered; the owner
    /// can leave it empty, and their own keys are checked instead.
    func recover(server: String, ownerFingerprint: String, words: String) async {
        let server = server.trimmingCharacters(in: .whitespacesAndNewlines)
        let ownerFingerprint: String? = ownerFingerprint.trimmed.isEmpty ? nil : ownerFingerprint
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

    /// While this Mac joins its account from another device: the code to type there.
    private(set) var joiningCode: String?
    private var joinTask: Task<Void, Never>?

    /// Adds this Mac to an account another device already has, with the setup line that
    /// device shows: shows the code to type there, waits for the account (ten minutes at
    /// most), then enrolls the way recovery does, checking the owner's fingerprint.
    func startAddingThisMac(line: String) {
        joinTask?.cancel()
        joinTask = Task { await addThisMac(line: line) }
    }

    func cancelAddingThisMac() {
        joinTask?.cancel()
        joinTask = nil
        joiningCode = nil
    }

    private func addThisMac(line: String) async {
        message = nil
        let deviceName = Self.thisMacName
        let join: DeviceJoin
        do {
            join = try await Task.detached { try DeviceJoin.start(line: line, deviceName: deviceName) }.value
        } catch {
            message = describe(error)
            return
        }
        joiningCode = join.code()
        let deadline = Date().addingTimeInterval(10 * 60)
        var received: Data?
        while received == nil {
            if Task.isCancelled { return }
            do {
                received = try await Task.detached { try join.poll() }.value
            } catch {
                joiningCode = nil
                message = describe(error)
                return
            }
            if received == nil {
                if Date() > deadline {
                    joiningCode = nil
                    message = "Nothing arrived in ten minutes. Start again on your other device."
                    return
                }
                try? await Task.sleep(for: .seconds(2))
            }
        }
        joiningCode = nil
        guard let received, !Task.isCancelled else { return }
        let server = join.server()
        let ownerFingerprint = join.ownerFingerprint()
        await enroll(working: "Adding this Mac…", secret: SymmetricKey(data: received)) {
            profilePath, secret, deviceId, deviceName, signer in
            try Vault.recover(
                profilePath: profilePath, server: server, ownerFingerprint: ownerFingerprint,
                accountSecret: secret, deviceId: deviceId, deviceName: deviceName, signer: signer)
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
        folderRoles = [:]
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

    /// Locks because the user seems to be away (see `AutoLock`), and clears the clipboard if
    /// it still holds a password Keystead copied.
    func lockBecauseAway() {
        guard phase == .unlocked else { return }
        clipboard.clearNow()
        copiedNoticeTask?.cancel()
        lock()
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
            if result.rejected > 0 {
                message = "Ignored \(result.rejected) item(s) not signed by an approved user."
            } else if let problem = result.rekeyProblems.first {
                message = "Couldn't give a folder or group its new key (\(problem)). "
                    + "The next sync tries again."
            } else {
                message = nil
            }
        } catch {
            message = "Couldn't sync (\(describe(error))). Showing the copy on this Mac."
        }
        await reloadLocal()
        await reloadDevices()
        await reloadDeleted()
    }

    /// Loads Recently Deleted on its own, like the device list.
    private func reloadDeleted() async {
        do {
            let deleted = try await perform { try $0.deletedLogins() }
            keepsDeleted = deleted != nil
            recentlyDeleted = deleted ?? []
        } catch {
            recentlyDeleted = []
        }
    }

    /// Brings back a deleted login for everyone who had it. Returns a note if someone else
    /// changed it first, in which case nothing was saved.
    func undelete(_ login: DeletedLogin) async throws -> String? {
        let id = login.itemId
        let outcome = try await perform { try $0.undeleteLogin(itemId: id) }
        await reloadLocal()
        await reloadDeleted()
        if case .saved = outcome {
            section = .allLogins
            selectedItemID = id
        }
        return conflictNote(outcome, doing: "it wasn't brought back")
    }

    /// Deletes a deleted login for good, now instead of after 30 days.
    func purge(_ login: DeletedLogin) async throws {
        let id = login.itemId
        try await perform { try $0.purgeLogin(itemId: id) }
        await reloadDeleted()
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
            noteCopied("password", of: item)
        } catch {
            message = describe(error)
        }
    }

    /// A login's current one-time code, if it has one-time codes.
    func oneTimeCode(of item: ItemSummary) async throws -> OneTimeCode? {
        #if DEBUG
        if isDemo {
            let now = UInt64(Date().timeIntervalSince1970)
            return item.hasOneTimeCode ? OneTimeCode(code: "492039", period: 30, remaining: 30 - now % 30) : nil
        }
        #endif
        let id = item.id
        return try await perform { try $0.oneTimeCode(itemId: id) }
    }

    /// Copies a login's current one-time code the way passwords are copied.
    func copyOneTimeCode(of item: ItemSummary) async {
        do {
            guard let code = try await oneTimeCode(of: item) else {
                message = "\(item.name) has no one-time codes."
                return
            }
            clipboard.copy(code.code)
            noteCopied("one-time code", of: item)
        } catch {
            message = describe(error)
        }
    }

    /// Shows what was copied until the clipboard clears.
    private func noteCopied(_ what: String, of item: ItemSummary) {
        copiedWhat = what
        copiedName = item.name
        copiedNoticeTask?.cancel()
        copiedNoticeTask = Task {
            try? await Task.sleep(for: SecureClipboard.clearAfter)
            if !Task.isCancelled { copiedName = nil }
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

    /// Adds a login to `folder`, or with none as yours alone until you share it.
    func addLogin(folder: String?, _ fields: LoginFields) async throws {
        try await perform { try $0.addLogin(folder: folder, fields: fields) }
        await reloadLocal()
    }

    /// A login's password and notes, decrypted for showing or editing.
    func details(of item: ItemSummary) async throws -> LoginDetails {
        #if DEBUG
        if isDemo {
            return LoginDetails(
                password: "correct-horse-battery", notes: "Recovery codes are in the safe.",
                oneTimeCode: item.hasOneTimeCode
                    ? "otpauth://totp/AWS:root?secret=JBSWY3DPEHPK3PXP&issuer=AWS" : "")
        }
        #endif
        return try await perform { try $0.details(itemId: item.id) }
    }

    /// Saves all of a login's fields. Returns a note if someone else changed it first, in
    /// which case nothing was saved.
    func update(_ item: ItemSummary, _ fields: LoginFields) async throws -> String? {
        let id = item.id
        let outcome = try await perform { try $0.updateLogin(itemId: id, fields: fields) }
        await reloadLocal()
        return conflictNote(outcome, doing: "your changes weren't saved")
    }

    /// A login's history, newest first, fetched fresh (editors and managers).
    func history(of item: ItemSummary) async throws -> [HistoryEntry] {
        #if DEBUG
        if isDemo { return Self.demoHistory }
        #endif
        let id = item.id
        return try await perform { try $0.history(itemId: id) }
    }

    /// The password of a version in the history last fetched.
    func historyPassword(of item: ItemSummary, version: UInt64) async throws -> String {
        #if DEBUG
        if isDemo { return "older-password-\(version)" }
        #endif
        let id = item.id
        return try await perform { try $0.historyPassword(itemId: id, version: version) }
    }

    /// Copies an earlier password the way current ones are copied.
    func copyHistoryPassword(of item: ItemSummary, version: UInt64) async {
        do {
            clipboard.copy(try await historyPassword(of: item, version: version))
            noteCopied("password from version \(version)", of: item)
        } catch {
            message = describe(error)
        }
    }

    /// Brings back an earlier version as a new one. Returns a note if someone else changed
    /// the login first, in which case nothing was saved.
    func restore(_ item: ItemSummary, version: UInt64) async throws -> String? {
        let id = item.id
        let outcome = try await perform { try $0.restoreVersion(itemId: id, version: version) }
        await reloadLocal()
        return conflictNote(outcome, doing: "the earlier version wasn't brought back")
    }

    /// Deletes a login for everyone who can open it. Returns a note if someone else changed
    /// it first, in which case nothing was deleted.
    func delete(_ item: ItemSummary) async throws -> String? {
        let id = item.id
        let outcome = try await perform { try $0.deleteLogin(itemId: id) }
        if case .saved = outcome, selectedItemID == id {
            selectedItemID = nil
        }
        await reloadLocal()
        return conflictNote(outcome, doing: "it wasn't deleted")
    }

    private func conflictNote(_ outcome: SaveOutcome, doing: String) -> String? {
        switch outcome {
        case .saved:
            return nil
        case .conflict(_, let author):
            return "\(author) changed this login first, so \(doing). You now have their "
                + "version; look at it, then try again if you still need to."
        }
    }

    func createFolder(named name: String) async throws {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        try await perform { try $0.createFolder(name: name) }
        await reloadLocal()
    }

    func share(folder: String, with user: User, role: Role) async throws {
        _ = try await perform {
            try $0.shareFolder(folder: folder, userId: user.userId, role: role)
        }
    }

    /// Shares one login with an approved person, without the rest of its folder.
    func share(login item: ItemSummary, with user: User, role: Role) async throws {
        let id = item.id
        _ = try await perform { try $0.shareLogin(itemId: id, userId: user.userId, role: role) }
        await reloadLocal()
    }

    /// Shares a folder with a group: everyone in it gets the folder.
    func share(folder: String, with group: GroupSummary, role: Role) async throws {
        let name = group.name
        _ = try await perform {
            try $0.shareFolderWithGroup(folder: folder, group: name, role: role)
        }
    }

    /// Shares one login with a group, without the rest of its folder.
    func share(login item: ItemSummary, with group: GroupSummary, role: Role) async throws {
        let id = item.id
        let name = group.name
        _ = try await perform { try $0.shareLoginWithGroup(itemId: id, group: name, role: role) }
        await reloadLocal()
    }

    /// Whether you manage a folder: share it, change roles, remove people.
    func manages(folder: String) -> Bool { folderRoles[folder] == .manage }

    /// Everyone in a folder and the groups it's shared with, with their roles.
    func sharing(of folder: String) async throws -> Sharing {
        #if DEBUG
        if isDemo { return Self.demoSharing(folder) }
        #endif
        return try await perform { try $0.folderSharing(folder: folder) }
    }

    func setRole(_ role: Role, for share: GroupShare, in folder: String) async throws {
        let name = share.name
        try await perform { try $0.setFolderGroupRole(folder: folder, group: name, role: role) }
    }

    /// Stops sharing a folder with a group; the folder then gets a new key.
    func remove(_ share: GroupShare, from folder: String) async throws {
        let name = share.name
        let result = try await perform { try $0.removeGroupFromFolder(folder: folder, group: name) }
        note(result)
        await reloadLocal()
    }

    func setRole(_ role: Role, for person: Person, in folder: String) async throws {
        try await perform { try $0.setFolderRole(folder: folder, userId: person.userId, role: role) }
    }

    /// Takes someone out of a folder; the folder then gets a new key. Taking yourself out
    /// is leaving it.
    func remove(_ person: Person, from folder: String) async throws {
        try await perform { try $0.removeFromFolder(folder: folder, userId: person.userId) }
        if person.isMe && section == .folder(folder) {
            section = .allLogins
        }
        await reloadLocal()
    }

    /// Who has a login directly, its owner and everyone it's shared with, and the groups
    /// it's shared with.
    func sharing(of item: ItemSummary) async throws -> Sharing {
        #if DEBUG
        if isDemo { return Self.demoSharing(item) }
        #endif
        let id = item.id
        return try await perform { try $0.loginSharing(itemId: id) }
    }

    func setRole(_ role: Role, for share: GroupShare, on item: ItemSummary) async throws {
        let id = item.id
        let name = share.name
        try await perform { try $0.setLoginGroupRole(itemId: id, group: name, role: role) }
    }

    /// Takes a group's copy of a login away.
    func unshare(_ item: ItemSummary, from share: GroupShare) async throws {
        let id = item.id
        let name = share.name
        _ = try await perform { try $0.unshareLoginGroup(itemId: id, group: name) }
        await reloadLocal()
    }

    func setRole(_ role: Role, for person: Person, on item: ItemSummary) async throws {
        let id = item.id
        try await perform { try $0.setLoginRole(itemId: id, userId: person.userId, role: role) }
    }

    /// Takes away someone's copy of a login.
    func unshare(_ item: ItemSummary, from person: Person) async throws {
        let id = item.id
        _ = try await perform { try $0.unshareLogin(itemId: id, userId: person.userId) }
        await reloadLocal()
    }

    // MARK: - Groups

    /// Makes a group (owner only) with you, as its manager, and these people in it.
    func createGroup(named name: String, with members: [Int64]) async throws {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        try await perform { try $0.createGroup(name: name, memberIds: members) }
        await reloadLocal()
        selectedGroupID = groups.first { $0.name == name }?.id
    }

    /// Adds someone to a group: they get everything shared with it.
    func add(_ user: User, to group: GroupSummary) async throws {
        let name = group.name
        _ = try await perform { try $0.addToGroup(group: name, userId: user.userId) }
        await refresh()
    }

    /// Takes someone out of a group, or you, to leave it. The group, and folders shared
    /// with it, then get new keys.
    func remove(_ member: GroupMember, from group: GroupSummary) async throws {
        let name = group.name
        let result = try await perform { try $0.removeFromGroup(group: name, userId: member.userId) }
        await refresh()
        note(result)
    }

    /// Deletes a group (the owner, or a manager in it). Folders shared with it get new keys,
    /// from here if this account manages them.
    func delete(_ group: GroupSummary) async throws {
        let name = group.name
        let result = try await perform { try $0.deleteGroup(group: name) }
        if selectedGroupID == group.id { selectedGroupID = nil }
        await refresh()
        note(result)
    }

    func setManager(_ member: GroupMember, of group: GroupSummary, to manager: Bool) async throws {
        let name = group.name
        try await perform { try $0.setGroupManager(group: name, userId: member.userId, manager: manager) }
        await reloadLocal()
    }

    func rename(_ group: GroupSummary, to name: String) async throws {
        let old = group.name
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        try await perform { try $0.renameGroup(group: old, name: name) }
        await reloadLocal()
    }

    /// Says when a removal's new keys couldn't be made here.
    private func note(_ result: SyncResult) {
        if let problem = result.rekeyProblems.first {
            message = "Couldn't give a folder or group its new key (\(problem)). "
                + "The next sync tries again."
        }
    }

    /// Removes someone from the team (owner only), then says how many of the passwords they
    /// could see you can change.
    func remove(user: User) async throws {
        _ = try await perform { try $0.removeUser(userId: user.userId) }
        users = try await perform { try $0.users() }
        await reloadLocal()
        let count = Set(toChange.filter { $0.userId == user.userId }.map(\.itemId)).count
        if count > 0 {
            message = "\(user.name) could see \(count == 1 ? "1 password" : "\(count) passwords") "
                + "you can change. They're listed under To Change."
        }
    }

    /// Takes a login off To Change without changing its password, for everyone listed on it.
    func dismissToChange(of item: ItemSummary) async throws {
        for entry in toChange(for: item) {
            try await perform { try $0.dismissToChange(itemId: entry.itemId, userId: entry.userId) }
        }
        await reloadLocal()
    }

    /// Takes everything one person could see off To Change, as when they only moved teams.
    func dismissAllToChange(for userId: Int64) async throws {
        _ = try await perform { try $0.dismissAllToChange(userId: userId) }
        await reloadLocal()
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

    /// Starts adding another device to this account; returns the setup line to copy to it.
    func startAddingDevice() async throws -> String {
        #if DEBUG
        if isDemo {
            return "keystead add-device https://keys.example.com Qh5bMqdKvaJzJWde-ibpjJIar5ey9rAXIAhPOK1F4NA "
                + "--owner ab12-cd34-ef56-7890-abcd"
        }
        #endif
        return try await perform { try $0.startAddingDevice() }
    }

    /// The new device's name, once it has joined with the setup line.
    func newDevice() async throws -> String? {
        #if DEBUG
        if isDemo { return "Olivia's MacBook Air" }
        #endif
        return try await perform { try $0.newDevice() }
    }

    /// Sends this account to the new device, sealed for it, if `code` is the one it shows.
    /// Takes Touch ID, as it unwraps the account secret. Returns the device's name.
    func sendAccount(toNewDevice code: String) async throws -> String {
        let device = try store.load()
        let context = try await DeviceAuthentication.authenticate(reason: "send your account to your new device")
        let agreementKey = try SecureEnclaveDeviceKey.restore(from: device.agreementKey, context: context)
        let secret = try AccountSecretWrap.unwrap(device.accountSecret, with: agreementKey.privateKey)
            .withUnsafeBytes { Data($0) }
        return try await perform { try $0.sendAccountToNewDevice(code: code, accountSecret: secret) }
    }

    func cancelAddingDevice() async {
        _ = try? await perform { try $0.cancelAddingDevice() }
    }

    /// After sending the account to a new device: it registers itself within seconds, so
    /// the device list is fetched again shortly.
    func noteAddedDevice(_ name: String) {
        Task {
            try? await Task.sleep(for: .seconds(5))
            await reloadDevices()
        }
    }

    /// Copies the kit's 24 words, and nothing else, the way passwords are copied: to this Mac
    /// only, kept out of clipboard history, and cleared after 30 seconds.
    func copyRecoveryWords(of kit: RecoveryKit) {
        clipboard.copy(kit.words.joined(separator: " "))
    }

    /// Signs out: the server forgets this Mac, so it can't sign in again, and the account's
    /// files and keys on this Mac are deleted. Coming back takes the Recovery Kit. Ends on the
    /// welcome screen. The vault is already unlocked, so there's no Touch ID step; the
    /// confirmation sheet guards against signing out by accident.
    func signOut() async {
        #if DEBUG
        if isDemo {
            forgetAccount(note: nil)
            return
        }
        #endif
        var notTold: String?
        do {
            notTold = try await perform { try $0.signOut() }
        } catch {
            notTold = describe(error)
        }
        store.forgetAccount()
        forgetAccount(
            note: notTold.map {
                "Signed out, but the server couldn't be told (\($0)). This Mac stays in your "
                    + "device list until you remove it from another device."
            })
    }

    private func forgetAccount(note: String?) {
        lock()
        identity = nil
        message = note
        phase = .welcome
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
            groups = try await perform { try $0.groups() }.sorted { $0.name < $1.name }
            toChange = try await perform { try $0.toChange() }
            let tooNew = try await perform { try $0.tooNew() }
            if tooNew > 0 && message == nil {
                message = "\(tooNew == 1 ? "A login is" : "\(tooNew) logins are") from a newer "
                    + "Keystead and can't be shown. Update Keystead to see them."
            }
            localRevision += 1
            let summaries = try await perform { try $0.folderSummaries() }
            folders = summaries.map(\.name).sorted()
            folderRoles = Dictionary(summaries.map { ($0.name, $0.role) }, uniquingKeysWith: { a, _ in a })
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
        model.users = [User(userId: 1, name: "Olivia", approved: true, isOwner: true, removed: false)]
        model.devices = [
            AccountDevice(
                deviceId: "00000000-0000-4000-8000-0000000000d1", name: "Olivia's MacBook Air",
                addedAt: 1_760_000_000, current: false),
            AccountDevice(
                deviceId: "00000000-0000-4000-8000-0000000000d2", name: "Olivia's MacBook Pro",
                addedAt: 1_795_000_000, current: true),
        ]
        if alone {
            // A new owner's only device, as right after setup.
            model.devices.removeFirst()
        }
        if !alone {
            model.users += [
                User(userId: 2, name: "Mo", approved: true, isOwner: false, removed: false),
                User(userId: 3, name: "Sam", approved: false, isOwner: false, removed: false),
                User(userId: 4, name: "Pat", approved: true, isOwner: false, removed: true),
            ]
            model.folders = ["Production", "Staging"]
            // Mo's Staging folder, shared with Olivia to view.
            model.folderRoles = ["Production": .manage, "Staging": .view]
            model.items = [
                ItemSummary(
                    id: "00000000-0000-4000-8000-000000000001", folder: "Production",
                    name: "AWS root", username: "root@example.com", url: "https://aws.amazon.com",
                    owner: nil, sharedWith: ["Mo"], sharedWithGroups: [], sharedWithMe: false,
                    role: .manage, hasOneTimeCode: true),
                ItemSummary(
                    id: "00000000-0000-4000-8000-000000000002", folder: "Staging",
                    name: "Database", username: "admin", url: "",
                    owner: nil, sharedWith: [], sharedWithGroups: [], sharedWithMe: false,
                    role: .view, hasOneTimeCode: false),
                ItemSummary(
                    id: "00000000-0000-4000-8000-000000000003", folder: nil,
                    name: "Bank", username: "olivia@example.com", url: "https://bank.example.com",
                    owner: nil, sharedWith: [], sharedWithGroups: ["On-call"], sharedWithMe: false,
                    role: .manage, hasOneTimeCode: false),
                ItemSummary(
                    id: "00000000-0000-4000-8000-000000000004", folder: nil,
                    name: "Domain registrar", username: "ops@example.com", url: "",
                    owner: "Mo", sharedWith: [], sharedWithGroups: [], sharedWithMe: true,
                    role: .edit, hasOneTimeCode: false),
            ]
            model.groups = [
                GroupSummary(
                    id: "00000000-0000-4000-8000-0000000000a1", name: "Engineering",
                    members: [
                        GroupMember(userId: 1, name: "Olivia", isManager: true, isMe: true),
                        GroupMember(userId: 2, name: "Mo", isManager: false, isMe: false),
                    ],
                    isMember: true, canManage: true, canAdd: true),
                GroupSummary(
                    id: "00000000-0000-4000-8000-0000000000a2", name: "On-call",
                    members: [GroupMember(userId: 2, name: "Mo", isManager: true, isMe: false)],
                    isMember: false, canManage: true, canAdd: false),
            ]
            model.keepsDeleted = true
            model.recentlyDeleted = [
                DeletedLogin(
                    itemId: "00000000-0000-4000-8000-000000000005", name: "Old VPN",
                    username: "ops", folder: "Production", deletedBy: "Mo",
                    deletedAt: 1_795_400_000, keptUntil: 1_795_400_000 + 30 * 86_400),
            ]
            // Pat, removed from the team, could see two of Olivia's logins.
            model.toChange = [
                ToChange(
                    itemId: "00000000-0000-4000-8000-000000000001", name: "AWS root",
                    folder: "Production", userId: 4, userName: "Pat", since: 1_795_500_000),
                ToChange(
                    itemId: "00000000-0000-4000-8000-000000000003", name: "Bank",
                    folder: nil, userId: 4, userName: "Pat", since: 1_795_500_000),
            ]
        }
        return model
    }

    static func demoSharing(_ folder: String) -> Sharing {
        folder == "Production"
            ? Sharing(
                people: [Person(userId: 1, name: "Olivia", role: .manage, isMe: true),
                         Person(userId: 2, name: "Mo", role: .edit, isMe: false)],
                groups: [GroupShare(
                    groupId: "00000000-0000-4000-8000-0000000000a1", name: "Engineering",
                    role: .edit, isMine: true)])
            : Sharing(
                people: [Person(userId: 2, name: "Mo", role: .manage, isMe: false),
                         Person(userId: 1, name: "Olivia", role: .view, isMe: true)],
                groups: [])
    }

    static func demoSharing(_ item: ItemSummary) -> Sharing {
        switch item.name {
        case "AWS root":
            Sharing(people: [Person(userId: 2, name: "Mo", role: .edit, isMe: false)], groups: [])
        case "Domain registrar":
            Sharing(
                people: [Person(userId: 2, name: "Mo", role: .manage, isMe: false),
                         Person(userId: 1, name: "Olivia", role: .edit, isMe: true)],
                groups: [])
        default:
            Sharing(
                people: [Person(userId: 1, name: "Olivia", role: .manage, isMe: true)],
                groups: [GroupShare(
                    groupId: "00000000-0000-4000-8000-0000000000a2", name: "On-call",
                    role: .view, isMine: false)])
        }
    }

    /// AWS root's history.
    static let demoHistory = [
        HistoryEntry(
            version: 5, author: "Olivia", savedAt: 1_795_600_000, current: true, readable: true,
            changes: ["password"]),
        HistoryEntry(
            version: 4, author: "Mo", savedAt: 1_795_300_000, current: false, readable: true,
            changes: ["notes"]),
        HistoryEntry(
            version: 3, author: "Olivia", savedAt: 1_794_900_000, current: false, readable: true,
            changes: []),
        HistoryEntry(
            version: 2, author: "Olivia", savedAt: nil, current: false, readable: true,
            changes: ["password", "one-time code"]),
        HistoryEntry(
            version: 1, author: "Olivia", savedAt: nil, current: false, readable: false,
            changes: []),
    ]

    /// Shows both notices at the bottom of the window, as after a failed sync and a copy.
    /// The welcome screen as while this Mac waits for its account from another device, or
    /// back to the vault.
    func showDemoJoining(_ joining: Bool = true) {
        phase = joining ? .welcome : .unlocked
        joiningCode = joining ? "e0df-9242-f81b-7272-aa2f" : nil
    }

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

extension ItemSummary: Identifiable {
    /// Where a login lives, in a few words: its folder, who shared it with you, or that it's
    /// yours alone.
    var place: String {
        if let folder { return folder }
        if let owner { return "From \(owner)" }
        if sharedWithMe { return "Shared with you" }
        if sharedWithAll.isEmpty { return "Only you" }
        return "Shared with \(ListFormatter.localizedString(byJoining: sharedWithAll))"
    }

    /// Everyone and every group it's shared with directly, people first.
    var sharedWithAll: [String] {
        sharedWith + sharedWithGroups
    }
}

extension GroupSummary: Identifiable {}

extension DeletedLogin: Identifiable {
    public var id: String { itemId }
}

extension GroupMember: Identifiable {
    public var id: Int64 { userId }
}

extension GroupShare: Identifiable {
    public var id: String { groupId }
}

extension User: Identifiable {
    public var id: Int64 { userId }
}

extension Person: Identifiable {
    public var id: Int64 { userId }
}

extension Role {
    /// How a role reads in a picker.
    var label: String {
        switch self {
        case .view: "Can view"
        case .edit: "Can edit"
        case .manage: "Can manage"
        }
    }

    static let all: [Role] = [.view, .edit, .manage]
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

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

    /// The welcome screen's page: the choices, or the form for one.
    enum WelcomePage: Hashable {
        case start, join, setUp, addThisMac, recover, recoverWithHelp
    }

    /// The choices, unless a Debug build was launched with `-welcome` and a page: `join`,
    /// `setup`, `add`, `recover` or `recover-help`.
    private static var initialWelcomePage: WelcomePage {
        #if DEBUG
        let arguments = CommandLine.arguments
        if let index = arguments.firstIndex(of: "-welcome"), index + 1 < arguments.count {
            switch arguments[index + 1] {
            case "join": return .join
            case "setup": return .setUp
            case "add": return .addThisMac
            case "recover": return .recover
            case "recover-help": return .recoverWithHelp
            default: break
            }
        }
        #endif
        return .start
    }

    /// What the main window shows, chosen in its sidebar or the View menu.
    enum Section: Hashable {
        case allLogins
        /// Logins shared with you one by one, outside your folders.
        case sharedWithMe
        case folder(String)
        /// Logins whose passwords someone who lost access may still know.
        case toChange
        /// Logins you can change whose password is weak, reused or over a year old.
        case health
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
        case moveLogin(ItemSummary)
        case deleteLogin(ItemSummary)
        case shareLogin(ItemSummary)
        /// A new folder, or one inside another.
        case newFolder(inside: String?)
        case renameFolder(String)
        /// Asks before deleting a folder, saying what goes with it.
        case deleteFolder(String)
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
        /// After joining with an invite's key: the owner's Keystead approves this account.
        case joined
        /// The recovery kit; right after setup it first explains why it matters.
        case recoveryKit(afterSetup: Bool)
        case signOut
        case newGroup
        /// Importing logins from a Passbolt export, or a KeePass or KeePassXC file.
        case importLogins
        /// Exporting every login you can open to an encrypted KeePass file.
        case exportLogins
        case addToGroup(GroupSummary)
        case renameGroup(GroupSummary)
        /// The owner helps someone who lost every device and their Recovery Kit.
        case helpRecover(User)

        var id: String {
            switch self {
            case .addLogin(let folder): "add-\(folder ?? "")"
            case .history(let item): "history-\(item.id)"
            case .moveLogin(let item): "move-\(item.id)"
            case .editLogin(let item): "edit-\(item.id)"
            case .deleteLogin(let item): "delete-\(item.id)"
            case .shareLogin(let item): "share-login-\(item.id)"
            case .newFolder(let parent): "new-folder-\(parent ?? "")"
            case .renameFolder(let folder): "rename-folder-\(folder)"
            case .deleteFolder(let folder): "delete-folder-\(folder)"
            case .share(let folder, let user): "share-\(folder ?? "")-\(user?.userId ?? 0)"
            case .shareWithGroup(let group): "share-with-group-\(group.id)"
            case .manageFolder(let folder): "manage-\(folder)"
            case .removeUser(let user): "remove-user-\(user.userId)"
            case .addDevice: "add-device"
            case .invite: "invite"
            case .approve(let user): "approve-\(user.userId)"
            case .fingerprint: "fingerprint"
            case .joined: "joined"
            case .recoveryKit: "recovery-kit"
            case .signOut: "sign-out"
            case .newGroup: "new-group"
            case .importLogins: "import-logins"
            case .exportLogins: "export-logins"
            case .addToGroup(let group): "add-to-group-\(group.id)"
            case .renameGroup(let group): "rename-group-\(group.id)"
            case .helpRecover(let user): "help-recover-\(user.userId)"
            }
        }
    }

    private(set) var phase: Phase
    var welcomePage = AppModel.initialWelcomePage
    private(set) var identity: Identity?
    /// A sync is under way.
    private(set) var isSyncing = false
    /// A sync has finished since unlocking, so an empty list really is empty rather than
    /// not fetched yet (on a new Mac, before the first sync).
    private(set) var hasSynced = false
    /// Another sync was asked for during this one; it runs right after.
    @ObservationIgnored private var syncAgain = false
    @ObservationIgnored private var lastSync: ContinuousClock.Instant?
    @ObservationIgnored private var autoSyncTask: Task<Void, Never>?
    @ObservationIgnored private var activationObserver: NSObjectProtocol?
    private(set) var items: [ItemSummary] = [] {
        didSet {
            searchTexts = items.map(Self.searchText)
            nameRanks = nil
        }
    }
    /// Where each of `items` comes by name, for quick search; worked out when first needed.
    @ObservationIgnored private var nameRanks: [Int]?
    /// What search looks in for each of `items`, in the same order: lowercased once when
    /// the list changes, not on every keystroke.
    private(set) var searchTexts: [String] = []
    private(set) var folders: [String] = []
    /// Your role in each folder, by name.
    private(set) var folderRoles: [String: Role] = [:]
    private(set) var users: [User] = []
    /// The team's groups, by name.
    private(set) var groups: [GroupSummary] = []
    /// Passwords to change: who lost access to which logins you can change, most recent
    /// first.
    private(set) var toChange: [ToChange] = [] {
        didSet { toChangeByItem = Dictionary(grouping: toChange, by: \.itemId) }
    }
    /// `toChange` by login, for the list and each login's page.
    private(set) var toChangeByItem: [String: [ToChange]] = [:]
    /// Reads an export file (.kdbx) with its passphrase, off the main thread.
    func readExport(_ file: Data, passphrase: String) async throws -> LoginExport {
        try await Task.detached { try LoginExport.read(file: file, passphrase: passphrase) }.value
    }

    /// Writes every login you can open to `url`, as a KeePass file encrypted with
    /// `passphrase` that only you can read, after Touch ID and a sync. Returns how many
    /// logins went in, and how many were left out.
    func exportLogins(to url: URL, passphrase: String) async throws -> (logins: UInt32, leftOut: UInt32) {
        _ = try await DeviceAuthentication.authenticate(reason: "export your logins")
        await refresh()
        let exported = try await perform { try $0.exportLogins(passphrase: passphrase) }
        // Only you can read it from the start. The Save panel already asked to replace a file
        // with that name.
        try? FileManager.default.removeItem(at: url)
        guard FileManager.default.createFile(
            atPath: url.path, contents: exported.data, attributes: [.posixPermissions: 0o600])
        else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
        }
        return (exported.logins, exported.leftOut)
    }

    /// What importing would do; logins in no folder go into `unfiled`, or stay yours.
    func planImport(_ export: LoginExport, unfiled: String?) async throws -> ImportPreview {
        try await perform { try $0.planImport(export: export, unfiledFolder: unfiled) }
    }

    func runImport(_ export: LoginExport, unfiled: String?) async throws -> ImportResult {
        let result = try await perform { try $0.import(export: export, unfiledFolder: unfiled) }
        await refresh()
        return result
    }

    /// Logins deleted in the last 30 days that you can bring back, newest first.
    private(set) var recentlyDeleted: [DeletedLogin] = []
    /// The server keeps deleted logins for 30 days (0.9.0 and later); nil until it's asked.
    private(set) var keepsDeleted: Bool?
    var selectedDeletedID: DeletedLogin.ID?
    /// The invites nobody has used yet, oldest first. Only the owner has any, and only
    /// from a server on 0.16.0 or later.
    private(set) var invites: [PendingInvitation] = []
    /// This account's devices, this Mac included.
    private(set) var devices: [AccountDevice] = []
    /// Why the device list couldn't be loaded, such as a server older than 0.2.0.
    private(set) var devicesProblem: String?
    /// A short note: why the last action failed, or what sync skipped.
    private(set) var message: String?
    /// Who this Mac approved, as the owner, because they joined with an invite's key; shown
    /// until dismissed.
    private(set) var approvedNames: [String] = []
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
    /// An invite selected under People instead of a person.
    var selectedInviteID: PendingInvitation.ID?
    var selectedGroupID: GroupSummary.ID?
    /// The menu bar panel's search.
    var search = ""

    private var vault: Vault?
    /// The unlocked vault's device key; see `lockToSignInAgain`.
    private var signer: SecureEnclaveSigner?
    /// Why Keystead locked itself, shown on the lock screen until the next unlock.
    private(set) var lockNote: String?
    private let store = DeviceStore()
    private let clipboard = SecureClipboard()
    private var copiedNoticeTask: Task<Void, Never>?
    /// Whether a newer Keystead is out.
    let updates = Updates()
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
        if section == .recentlyDeleted { return [] }
        // Each word as bytes, compared byte for byte: both sides are lowercased and composed
        // the same way, so this matches what a Unicode-aware search would, many times faster.
        let words = Self.normalized(query).split(whereSeparator: \.isWhitespace)
            .map { Array(String($0).utf8CString) }
        var found: [ItemSummary] = []
        for (item, text) in zip(items, searchTexts) {
            switch section {
            case .folder(let folder): guard item.folder == folder else { continue }
            case .sharedWithMe: guard item.sharedWithMe else { continue }
            case .toChange: guard toChangeByItem[item.id] != nil else { continue }
            case .health: guard healthByItem[item.id] != nil else { continue }
            case .allLogins, .people, .groups, .recentlyDeleted: break
            }
            let matches = words.isEmpty || text.withCString { text in
                words.allSatisfy { word in
                    word.withUnsafeBufferPointer { strstr(text, $0.baseAddress!) != nil }
                }
            }
            if matches { found.append(item) }
        }
        return found
    }

    /// Quick search's results: logins matching `query`, those whose name starts with its
    /// first word first, then by name, at most `limit` of them.
    func quickSearch(_ query: String, limit: Int = 50) -> [ItemSummary] {
        let words = Self.normalized(query).split(whereSeparator: \.isWhitespace)
            .map { Array(String($0).utf8CString) }
        let first = words.first
        let ranks = nameRanks ?? rankByName()
        var hits: [(starts: Bool, rank: Int, index: Int)] = []
        for (index, text) in searchTexts.enumerated() {
            text.withCString { text in
                let matches = words.allSatisfy { word in
                    word.withUnsafeBufferPointer { strstr(text, $0.baseAddress!) != nil }
                }
                guard matches else { return }
                // The name comes first in the search text.
                let starts = first?.withUnsafeBufferPointer {
                    strncmp(text, $0.baseAddress!, $0.count - 1) == 0
                } ?? false
                hits.append((starts, ranks[index], index))
            }
        }
        hits.sort { ($0.starts ? 0 : 1, $0.rank) < ($1.starts ? 0 : 1, $1.rank) }
        return hits.prefix(limit).map { items[$0.index] }
    }

    /// Ranks `items` by name, as Finder sorts ("Login 9" before "Login 10"), once per list.
    private func rankByName() -> [Int] {
        let order = items.indices.sorted {
            items[$0].name.localizedStandardCompare(items[$1].name) == .orderedAscending
        }
        var ranks = [Int](repeating: 0, count: items.count)
        for (rank, index) in order.enumerated() {
            ranks[index] = rank
        }
        nameRanks = ranks
        return ranks
    }

    private static func searchText(_ item: ItemSummary) -> String {
        normalized(
            "\(item.name) \(item.username) \(item.url) \(item.folder ?? "") \(item.owner ?? "")")
    }

    /// Lowercased, with accents composed, so the same text always has the same bytes.
    private static func normalized(_ text: String) -> String {
        text.lowercased().precomposedStringWithCanonicalMapping
    }

    /// Whether any login was shared with you one by one, so the sidebar shows them.
    var hasSharedWithMe: Bool { items.contains(where: \.sharedWithMe) }

    /// Who lost access to this login while its password stayed the same, most recent first.
    func toChange(for item: ItemSummary) -> [ToChange] {
        toChangeByItem[item.id] ?? []
    }

    /// The login selected in the main window's list, while a list of logins shows.
    var selectedItem: ItemSummary? {
        guard phase == .unlocked, let id = selectedItemID else { return nil }
        switch section ?? .allLogins {
        case .people, .groups, .recentlyDeleted: return nil
        case .allLogins, .sharedWithMe, .folder, .toChange, .health: break
        }
        return items.first { $0.id == id }
    }

    /// How many logins are on the To Change list.
    var toChangeCount: Int { toChangeByItem.count }

    /// The last password health check; nil until Password Health is first shown.
    private(set) var health: PasswordHealth? {
        didSet {
            healthByItem = Dictionary(
                (health?.logins ?? []).map { ($0.itemId, $0) }, uniquingKeysWith: { a, _ in a })
        }
    }
    /// `health` by login.
    private(set) var healthByItem: [String: HealthLogin] = [:]
    private(set) var checkingHealth = false

    /// Checks the passwords of the logins you can change: weak, reused or over a year old.
    /// They're opened in memory on this Mac, and nothing about them is kept.
    func checkHealth() async {
        guard vault != nil, !checkingHealth else { return }
        checkingHealth = true
        defer { checkingHealth = false }
        do {
            health = try await perform { try $0.passwordHealth() }
        } catch {
            message = describe(error)
        }
    }

    /// What's wrong with this login's password, from the last check.
    func health(for item: ItemSummary) -> HealthLogin? {
        healthByItem[item.id]
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

    /// Joins a team with an invite. With the invite's key, the owner's Keystead approves
    /// this account on its own; without one, the user reads their fingerprint to the owner.
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
                ownerFingerprint: invite.ownerFingerprint, key: invite.key, accountSecret: secret,
                deviceId: deviceId, deviceName: deviceName, signer: signer)
        }
        if joined {
            sheet = invite.key == nil ? .fingerprint : .joined
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

    // MARK: Recovering with the owner's help

    /// While this Mac waits for the owner to approve its new keys: whose account, and the
    /// fingerprint to read to the owner.
    private(set) var recoveryClaim: RecoveryClaimInfo?
    /// The server couldn't be reached the last time this Mac asked; it keeps asking.
    private(set) var recoveryUnreachable = false
    private var recoveryTask: Task<Void, Never>?

    /// After the owner approved this Mac's new keys: what finishing needs, kept if it doesn't
    /// work out the first time (Touch ID cancelled, say), so the owner needn't start over.
    private struct ApprovedKeys {
        let line: String
        let device: DeviceStore.Device
        let secret: Data
        let deviceName: String
    }
    private var approvedKeys: ApprovedKeys?

    /// The owner approved this Mac's new keys, and finishing needs another try.
    var recoveryNeedsFinishing: Bool { approvedKeys != nil }

    /// Recovers an account with the line the owner sent, when every device and the Recovery
    /// Kit are gone: makes new keys, shows their fingerprint to read to the owner, and waits
    /// for their approval. Nothing is kept on this Mac unless they approve.
    func startRecoveringWithHelp(line: String) {
        recoveryTask?.cancel()
        recoveryTask = Task { await recoverWithHelp(line: line) }
    }

    func cancelRecoveringWithHelp() {
        recoveryTask?.cancel()
        recoveryTask = nil
        recoveryClaim = nil
        recoveryUnreachable = false
    }

    /// Gives up on keys the owner approved but this Mac didn't finish with; the owner has to
    /// start again.
    func forgetApprovedRecovery() {
        approvedKeys = nil
    }

    private func recoverWithHelp(line: String) async {
        message = nil
        do {
            _ = try parseRecoveryLine(text: line)
        } catch {
            message = "That doesn't look like a recovery line. Paste the whole line, starting "
                + "with \"keystead recover-with-help\"."
            return
        }
        do {
            let secret = SymmetricKey(size: .bits256)
            let agreementKey = try SecureEnclaveDeviceKey.create()
            let signingKey = try SecureEnclaveSigningKey.create()
            let device = DeviceStore.Device(
                deviceId: newDeviceId(),
                agreementKey: agreementKey.dataRepresentation,
                signingKey: signingKey.dataRepresentation,
                accountSecret: try AccountSecretWrap.wrap(secret, to: agreementKey.publicKey))
            let secretBytes = secret.withUnsafeBytes { Data($0) }
            let deviceName = Self.thisMacName
            // Claiming only needs the public half of this Mac's key: no Touch ID yet.
            let publicSigner = SecureEnclaveSigner(key: signingKey)
            let deviceId = device.deviceId
            recoveryClaim = try await Task.detached {
                try claimRecovery(
                    line: line, accountSecret: secretBytes, deviceId: deviceId,
                    deviceName: deviceName, signer: publicSigner)
            }.value
            try await waitForApproval(line: line)
            recoveryClaim = nil
            approvedKeys = ApprovedKeys(
                line: line, device: device, secret: secretBytes, deviceName: deviceName)
        } catch is CancellationError {
            recoveryClaim = nil
            recoveryUnreachable = false
            return
        } catch {
            recoveryClaim = nil
            recoveryUnreachable = false
            phase = .welcome
            message = describe(error)
            return
        }
        await finishRecoveringWithHelp()
    }

    /// Asks every few seconds whether the owner approved. A server it can't reach doesn't
    /// end the wait; a cancelled or expired recovery does.
    private func waitForApproval(line: String) async throws {
        while true {
            try Task.checkCancellation()
            let progress: RecoveryProgress
            do {
                progress = try await Task.detached { try recoveryProgress(line: line) }.value
                recoveryUnreachable = false
            } catch {
                recoveryUnreachable = true
                try await Task.sleep(for: .seconds(3))
                continue
            }
            switch progress {
            case .approved:
                // Cancel pressed while asking: stop here, before any Touch ID prompt.
                try Task.checkCancellation()
                recoveryUnreachable = false
                return
            case .ended:
                throw RecoveryEnded()
            case .waiting:
                try await Task.sleep(for: .seconds(3))
            }
        }
    }

    /// The owner approved this Mac's new keys: keeps them, asks for Touch ID and signs in.
    /// If that doesn't work out, the approval stays here to try again.
    func finishRecoveringWithHelp() async {
        guard let approved = approvedKeys else { return }
        message = nil
        do {
            try store.save(approved.device)
            phase = .working("Recovering your account…")
            let context = try await DeviceAuthentication.authenticate(
                reason: "set up Keystead on this Mac")
            let signer = SecureEnclaveSigner(
                key: try SecureEnclaveSigningKey.restore(
                    from: approved.device.signingKey, context: context),
                context: context)
            let profilePath = store.profileURL.path
            let (line, secret, deviceId, deviceName) =
                (approved.line, approved.secret, approved.device.deviceId, approved.deviceName)
            let vault = try await Task.detached {
                try Vault.finishRecovery(
                    profilePath: profilePath, line: line, accountSecret: secret,
                    deviceId: deviceId, deviceName: deviceName, signer: signer)
            }.value
            approvedKeys = nil
            try await finishUnlocking(vault, signer: signer)
            // New keys mean a new kit; the old one no longer works.
            sheet = .recoveryKit(afterSetup: false)
        } catch {
            if store.isEnrolled && vault == nil { store.removeDevice() }
            phase = .welcome
            message = "The owner approved your new keys, but this Mac couldn't finish ("
                + describe(error) + "). Choose Finish Recovering to try again."
        }
    }

    /// Starts helping someone recover (owner only); returns the line to send them. Signing
    /// out their devices asks for Touch ID first.
    func startRecovery(for user: User, signOutDevices: Bool) async throws -> String {
        #if DEBUG
        if isDemo { return "keystead recover-with-help https://keys.example.com 3Fq…x9 --owner 1a2b-3c4d-5e6f-7a8b-9c0d" }
        #endif
        if signOutDevices {
            _ = try await DeviceAuthentication.authenticate(
                reason: "sign out \(user.name)'s devices")
        }
        let id = user.userId
        let line = try await perform {
            try $0.startRecovery(userId: id, signOutDevices: signOutDevices)
        }
        users = try await perform { try $0.users() }
        return line
    }

    /// Someone's recovery waiting for approval, fetched fresh (owner only).
    func recoveryRequest(for user: User) async throws -> PendingRecovery? {
        #if DEBUG
        if isDemo {
            await demoLatency()
            return PendingRecovery(claimed: true, escrow: true)
        }
        #endif
        let id = user.userId
        return try await perform { try $0.recoveryRequest(userId: id) }
    }

    func approveRecovery(for user: User, fingerprint: String) async throws -> RecoveryApproval {
        // It gives someone this person's account: only the owner, at this Mac, may.
        _ = try await DeviceAuthentication.authenticate(reason: "approve new keys for \(user.name)")
        let id = user.userId
        let approval = try await perform { try $0.approveRecovery(userId: id, fingerprint: fingerprint) }
        await refresh()
        return approval
    }

    /// Cancels a recovery: someone's (owner), or your own from this Mac.
    func cancelRecovery(for userId: Int64) async throws {
        try await perform { try $0.cancelRecovery(userId: userId) }
        await refresh()
    }

    /// Cancels a recovery of your own account, from this Mac; a problem shows as a message.
    func cancelOwnRecovery() async {
        guard let id = identity?.userId else { return }
        do {
            try await cancelRecovery(for: id)
        } catch {
            message = describe(error)
        }
    }

    /// Lets the owner recover your own logins and folders if you lose everything, or stops it.
    func setEscrow(_ on: Bool) async throws {
        if on {
            _ = try await DeviceAuthentication.authenticate(
                reason: "let the owner recover your own logins and folders")
        }
        try await perform { try $0.setEscrow(on: on) }
        identity = try await perform { try $0.identity() }
        users = try await perform { try $0.users() }
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
                key: try SecureEnclaveSigningKey.restore(from: device.signingKey, context: context),
                context: context)
            let secretBytes = secret.withUnsafeBytes { Data($0) }
            let profilePath = store.profileURL.path
            let deviceId = device.deviceId
            let deviceName = Self.thisMacName
            let vault = try await Task.detached {
                try create(profilePath, secretBytes, deviceId, deviceName, signer)
            }.value
            try await finishUnlocking(vault, signer: signer)
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
        lockNote = nil
        phase = .working("Unlocking…")
        do {
            // Before asking: nothing to unlock on a Mac that isn't set up.
            _ = try store.load()
            let context = try await DeviceAuthentication.authenticate(reason: "unlock Keystead")
            let (vault, signer) = try await openVault(with: context)
            try await finishUnlocking(vault, signer: signer)
        } catch {
            phase = .locked
            message = describe(error)
        }
    }

    /// Opens this Mac's vault with an approval just given. Doesn't touch the network.
    private func openVault(with context: LAContext) async throws -> (Vault, SecureEnclaveSigner) {
        let device = try store.load()
        let agreementKey = try SecureEnclaveDeviceKey.restore(
            from: device.agreementKey, context: context)
        let secret = try AccountSecretWrap.unwrap(device.accountSecret, with: agreementKey.privateKey)
        let signer = SecureEnclaveSigner(
            key: try SecureEnclaveSigningKey.restore(from: device.signingKey, context: context),
            context: context)
        let secretBytes = secret.withUnsafeBytes { Data($0) }
        let profilePath = store.profileURL.path
        let vault = try await Task.detached {
            try Vault.open(profilePath: profilePath, accountSecret: secretBytes, signer: signer)
        }.value
        return (vault, signer)
    }

    /// Drops the unlocked vault; its keys are freed with it.
    func lock() {
        autoSyncTask?.cancel()
        autoSyncTask = nil
        vault = nil
        signer = nil
        lockNote = nil
        items = []
        folders = []
        folderRoles = [:]
        users = []
        groups = []
        toChange = []
        health = nil
        recentlyDeleted = []
        invites = []
        devices = []
        devicesProblem = nil
        hasSynced = false
        search = ""
        sheet = nil
        section = .allLogins
        selectedItemID = nil
        selectedUserID = nil
        selectedInviteID = nil
        copiedName = nil
        message = nil
        approvedNames = []
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

    /// Locks instead of macOS asking for Touch ID or the Mac password out of the blue.
    /// Signing in to the server again needs this Mac's key, and its approval from unlocking
    /// lasts only minutes: this comes 24 hours after the last sign-in, when the server has
    /// forgotten the session (after a restart, say), or every 15 minutes with a server too
    /// old to renew sessions. Unlocking signs in again.
    private func lockToSignInAgain(_ vault: Vault) async {
        let renews = (try? await Task.detached { try vault.serverRenewsSessions() }.value) ?? true
        guard self.vault === vault else { return }
        lock()
        lockNote = Self.signInAgainNote(serverRenews: renews)
    }

    static func signInAgainNote(serverRenews: Bool) -> String {
        "Unlock to sign in to your team's server again."
            + (serverRenews
                ? "" : " Until your server is on 0.14.0 or later, this comes every 15 minutes.")
    }

    private func finishUnlocking(_ vault: Vault, signer: SecureEnclaveSigner) async throws {
        self.vault = vault
        self.signer = signer
        lockNote = nil
        identity = try vault.identity()
        // The window opens with the copy on this Mac, then syncs: the server may be slow
        // or out of reach, and an empty list meanwhile looks like the logins are gone.
        update(\.users, to: try await perform { try $0.knownUsers() })
        await reloadLocal()
        phase = .unlocked
        startAutoSync()
        await refresh()
        // Signed in, while the approval from unlocking still holds. Later uses of the key
        // lock Keystead instead of asking; see `lockToSignInAgain`.
        signer.stopAsking()
    }

    /// Keeps this Mac's copy fresh without a button: every five minutes while unlocked, and
    /// when Keystead comes back to the front after a minute or more. Every minute while the
    /// owner has invites out, so whoever joins with one is approved soon after.
    private func startAutoSync() {
        autoSyncTask?.cancel()
        autoSyncTask = Task { [weak self] in
            while !Task.isCancelled {
                let waiting = self.map { $0.isOwner && !$0.invites.isEmpty } ?? false
                try? await Task.sleep(for: .seconds(waiting ? 60 : 300))
                guard let self, !Task.isCancelled, self.phase == .unlocked else { return }
                await self.refresh()
            }
        }
        if activationObserver == nil {
            activationObserver = NotificationCenter.default.addObserver(
                forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
            ) { [weak self] _ in
                Task { @MainActor in self?.syncIfStale() }
            }
        }
    }

    private func syncIfStale() {
        guard phase == .unlocked, vault != nil else { return }
        if let lastSync, ContinuousClock.now - lastSync < .seconds(60) { return }
        Task { await refresh() }
    }

    // MARK: - Reading

    /// Fetches changes and the people on the server. If the server can't be reached,
    /// keeps showing the copy on this Mac.
    func refresh() async {
        // One at a time: a sync asked for during another runs right after it.
        if isSyncing {
            syncAgain = true
            return
        }
        isSyncing = true
        repeat {
            syncAgain = false
            await syncOnce()
        } while syncAgain
        isSyncing = false
        lastSync = .now
        // Not if it locked meanwhile: the next unlock gets its logins afresh.
        if !hasSynced && phase == .unlocked { hasSynced = true }
    }

    private func syncOnce() async {
        do {
            let result = try await perform { try $0.sync() }
            // The sync fetched the directory already.
            update(\.users, to: try await perform { try $0.knownUsers() })
            update(\.identity, to: try await perform { try $0.identity() })
            if !result.approved.isEmpty {
                approvedNames += result.approved
            }
            if result.older > 0 || result.serverWentBack {
                // A server restored from a backup looks like this; so does one that lies.
                message = (result.older > 0
                    ? "The server sent older copies of \(result.older) login(s), folder(s) or "
                        + "group(s) than this Mac has already seen; it kept its own."
                    : "The server went back to an earlier point.")
                    + " If it was restored from a backup, save your recent changes again. "
                    + "If not, don't trust it."
            } else if result.rejected > 0 {
                message = "Ignored \(result.rejected) change(s) by someone who isn't approved, or who can "
                    + "only view the folder."
            } else if let problem = result.rekeyProblems.first {
                // Copies for someone who recovered say what they are; new keys don't.
                let what = problem.hasPrefix("couldn't")
                    ? problem.prefix(1).uppercased() + problem.dropFirst()
                    : "Couldn't give a folder or group its new key (\(problem))"
                message = what + ". The next sync tries again."
            } else {
                message = nil
            }
        } catch {
            // Locked meanwhile, as to sign in again: the lock screen says why.
            guard phase == .unlocked else { return }
            message = "Couldn't sync (\(describe(error))). Showing the copy on this Mac."
        }
        await reloadLocal()
        await reloadDeleted()
        await reloadInvites()
    }

    /// Sets a property only if its value changed, so the views that show it aren't drawn
    /// again for nothing after a sync that brought nothing new.
    private func update<Value: Equatable>(
        _ keyPath: ReferenceWritableKeyPath<AppModel, Value>, to value: Value
    ) {
        if self[keyPath: keyPath] != value {
            self[keyPath: keyPath] = value
        }
    }

    /// Loads Recently Deleted on its own, like the device list.
    private func reloadDeleted() async {
        do {
            let deleted = try await perform { try $0.deletedLogins() }
            update(\.keepsDeleted, to: deleted != nil)
            update(\.recentlyDeleted, to: deleted ?? [])
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

    /// Deletes everything in Recently Deleted for good, one login at a time. The server
    /// lists only logins you can change, so each is yours to delete. Stops at the first
    /// one that fails and says why; the ones before it are gone.
    func purgeAll() async {
        let ids = recentlyDeleted.map(\.itemId)
        message = nil
        for (done, id) in ids.enumerated() {
            do {
                try await perform { try $0.purgeLogin(itemId: id) }
            } catch {
                message = done == 0
                    ? describe(error)
                    : "Deleted \(done) of \(ids.count) for good, then: \(describe(error))"
                break
            }
        }
        await reloadDeleted()
    }

    /// Loads the owner's unused invites on its own, like Recently Deleted. A server older
    /// than 0.16.0 lists none; if it can't be asked, the ones already shown stay.
    func reloadInvites() async {
        #if DEBUG
        if isDemo { return }
        #endif
        guard isOwner else { return }
        do {
            update(\.invites, to: try await perform { try $0.pendingInvites() } ?? [])
        } catch {}
    }

    /// Loads the device list on its own, so an older server that has no device list
    /// doesn't make syncing look broken. Asked for where it's shown, not on every sync.
    func reloadDevices() async {
        #if DEBUG
        if isDemo { return }
        #endif
        do {
            update(\.devices, to: try await perform { try $0.devices() })
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

    func dismissApproved() {
        approvedNames = []
    }

    /// Quitting ends the timer that clears a copied password, so it's cleared now.
    func clearClipboardBeforeQuitting() {
        clipboard.clearNow()
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

    /// Whether a login can be moved by you: you can change it, and it's in a folder or
    /// yours.
    func canMove(_ item: ItemSummary) -> Bool {
        item.role != .view && item.owner == nil && !(item.folder == nil && item.sharedWithMe)
    }

    /// Moves a login to another folder, or out of folders as yours (`nil`), and shows it
    /// there. Returns a note if someone else changed it first.
    func move(_ item: ItemSummary, to folder: String?) async throws -> String? {
        let id = item.id
        let outcome = try await perform { try $0.moveLogin(itemId: id, toFolder: folder) }
        await reloadLocal()
        if case .saved = outcome {
            section = folder.map { .folder($0) } ?? .allLogins
            selectedItemID = id
        }
        return conflictNote(outcome, doing: "it wasn't moved")
    }

    /// A login's history, newest first, fetched fresh (editors and managers).
    func history(of item: ItemSummary) async throws -> [HistoryEntry] {
        #if DEBUG
        if isDemo {
            await demoLatency()
            return Self.demoHistory
        }
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

    /// Creates a folder inside another, shared like it unless asked not to, and shows it.
    func createFolder(named name: String, inside parent: String, shareLikeParent: Bool) async throws {
        let created = try await perform {
            try $0.createFolderInside(parent: parent, name: name, shareLikeParent: shareLikeParent)
        }
        await reloadLocal()
        section = .folder(created.name)
        if !created.problems.isEmpty {
            message = "Created \(created.name), but couldn't share it with "
                + ListFormatter.localizedString(byJoining: created.problems) + "."
        }
    }

    /// Renames a folder, and the folders inside it you manage, and keeps showing it. Says
    /// which ones inside kept their names or couldn't be renamed.
    func rename(folder: String, to name: String) async throws {
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let renamed = try await perform { try $0.renameFolder(folder: folder, name: name) }
        await reloadLocal()
        // Where a folder, or a step in the sidebar, went.
        func moved(_ old: String) -> String? {
            if old == folder { return renamed.name }
            if old.hasPrefix(folder + " / ") { return renamed.name + String(old.dropFirst(folder.count)) }
            return nil
        }
        if case .folder(let shown) = section, let new = moved(shown), folders.contains(new) {
            section = .folder(new)
        }
        collapsedFolders = Set(collapsedFolders.map { moved($0) ?? $0 })
        var notes: [String] = []
        if !renamed.kept.isEmpty {
            let one = renamed.kept.count == 1
            notes.append(ListFormatter.localizedString(byJoining: renamed.kept.map { "\u{201C}\($0)\u{201D}" })
                + (one ? " kept its name" : " kept their names")
                + ": you don't manage \(one ? "it" : "them").")
        }
        if !renamed.problems.isEmpty {
            notes.append("Couldn't rename " + ListFormatter.localizedString(byJoining: renamed.problems) + ".")
        }
        if !notes.isEmpty { message = notes.joined(separator: " ") }
    }

    /// What deleting a folder would delete, fetched fresh.
    func deletion(of folder: String) async throws -> FolderDeletion {
        #if DEBUG
        if isDemo {
            return FolderDeletion(
                logins: 3, toChange: 1, inside: folders.filter { $0.hasPrefix(folder + " / ") })
        }
        #endif
        return try await perform { try $0.folderDeletion(folder: folder) }
    }

    /// Deletes a folder and its logins for everyone, for good; `logins` is how many were
    /// agreed to.
    func delete(folder: String, logins: UInt64) async throws {
        let result = try await perform { try $0.deleteFolder(folder: folder, logins: logins) }
        if case .folder(let shown) = section, shown == folder { section = .allLogins }
        if let id = selectedItemID, items.first(where: { $0.id == id })?.folder == folder {
            selectedItemID = nil
        }
        await refresh()
        note(result)
    }

    /// Folders the sidebar shows collapsed; the rest are open.
    var collapsedFolders: Set<String> = []
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
        if isDemo {
            await demoLatency()
            return Self.demoSharing(folder)
        }
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
        if isDemo {
            await demoLatency()
            return Self.demoSharing(item)
        }
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
        let invitation = try await perform { try $0.invite(name: name) }
        await reloadInvites()
        return invitation
    }

    /// Revokes an invite nobody has used (owner only): its line stops working at once.
    func revokeInvite(_ invite: PendingInvitation) async throws {
        #if DEBUG
        if isDemo {
            invites.removeAll { $0.id == invite.id }
            return
        }
        #endif
        let id = invite.id
        do {
            try await perform { try $0.revokeInvite(id: id) }
        } catch {
            // Used or run out meanwhile: show what's waiting now.
            await reloadInvites()
            throw error
        }
        await reloadInvites()
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
            await demoLatency()
            return "keystead add-device https://keys.example.com Qh5bMqdKvaJzJWde-ibpjJIar5ey9rAXIAhPOK1F4NA "
                + "--owner ab12-cd34-ef56-7890-abcd"
        }
        #endif
        return try await perform { try $0.startAddingDevice() }
    }

    /// The new device's name, once it has joined with the setup line.
    func newDevice() async throws -> String? {
        #if DEBUG
        if isDemo {
            await demoLatency()
            return "Olivia's MacBook Air"
        }
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
    /// welcome screen.
    ///
    /// It takes Touch ID or the Mac password first, locked or not: signing out deletes the
    /// account from this Mac, which for an owner with one device and no Recovery Kit loses
    /// the team. Throws, with nothing done, if that isn't given. Once it is, the Mac
    /// forgets the account even if the vault won't open or the server can't be told, so a
    /// Mac whose account is broken can still be reset.
    func signOut() async throws {
        #if DEBUG
        if isDemo {
            forgetAccount(note: nil)
            return
        }
        #endif
        let context = try await DeviceAuthentication.authenticate(reason: "sign out of this Mac")
        var notTold: String?
        do {
            if vault != nil, let signer {
                // The approval from unlocking has stopped signing; this one tells the server.
                let device = try store.load()
                signer.approveAgain(
                    key: try SecureEnclaveSigningKey.restore(from: device.signingKey, context: context),
                    context: context)
                notTold = try await perform { try $0.signOut() }
            } else {
                let (vault, _) = try await openVault(with: context)
                notTold = try await Task.detached { try vault.signOut() }.value
            }
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
            update(\.items, to: try await perform { try $0.items() })
            update(\.groups, to: try await perform { try $0.groups() }.sorted { $0.name < $1.name })
            update(\.toChange, to: try await perform { try $0.toChange() })
            let tooNew = try await perform { try $0.tooNew() }
            if tooNew > 0 && message == nil {
                message = "\(tooNew == 1 ? "A login is" : "\(tooNew) logins are") from a newer "
                    + "Keystead and can't be shown. Update Keystead to see them."
            }
            localRevision += 1
            if section == .health {
                // A login just saved may have a better password now.
                Task { await checkHealth() }
            }
            let summaries = try await perform { try $0.folderSummaries() }
            update(\.folders, to: summaries.map(\.name).sorted())
            update(
                \.folderRoles,
                to: Dictionary(summaries.map { ($0.name, $0.role) }, uniquingKeysWith: { a, _ in a }))
        } catch {
            message = describe(error)
        }
    }

    /// Runs a blocking call on the vault off the main thread.
    private func perform<T: Sendable>(_ work: @escaping @Sendable (Vault) throws -> T) async throws -> T {
        guard let vault else { throw AppError("Keystead is locked.") }
        let signer = self.signer
        do {
            return try await Task.detached { try work(vault) }.value
        } catch {
            guard let signer, signer.neededYou else { throw error }
            await lockToSignInAgain(vault)
            throw AppError("Keystead locked to sign in to your team's server again.")
        }
    }
}

#if DEBUG
extension AppModel {
    /// A model filled with made-up data and no vault, for looking at the main window
    /// without a server or Touch ID. Debug builds only: launch with `-demo`, or with
    /// `-demo alone` for an owner who hasn't invited anyone yet. Actions that need the
    /// vault fail with "Keystead is locked."
    private static func demoUser(
        _ id: Int64, _ name: String, owner: Bool = false, approved: Bool = true,
        removed: Bool = false, escrow: Bool = false, inviteMismatch: Bool = false
    ) -> User {
        User(
            userId: id, name: name, approved: approved, isOwner: owner, removed: removed,
            escrow: escrow, recovering: false, keysReplaced: false, inviteMismatch: inviteMismatch)
    }

    /// With `-slowDemo`, demo loads take as long as a slow server's, to see sheets as
    /// they load and then grow.
    func demoLatency() async {
        if CommandLine.arguments.contains("-slowDemo") {
            try? await Task.sleep(for: .milliseconds(700))
        }
    }

    static func demo(alone: Bool, big: Bool = false) -> AppModel {
        let model = AppModel()
        model.isDemo = true
        model.phase = .unlocked
        model.hasSynced = true
        model.identity = Identity(
            name: "Olivia", userId: 1, fingerprint: "ab12-cd34-ef56-7890-abcd",
            server: "https://keys.example.com", isOwner: true,
            ownerFingerprint: "ab12-cd34-ef56-7890-abcd", escrow: false, recovering: false)
        model.users = [demoUser(1, "Olivia", owner: true)]
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
                demoUser(2, "Mo", escrow: true),
                demoUser(3, "Sam", approved: false),
                demoUser(4, "Pat", removed: true),
                // Joined with an invite's key that doesn't prove the keys on the server.
                demoUser(5, "Tom", approved: false, inviteMismatch: true),
            ]
            model.invites = [
                PendingInvitation(
                    id: 7, name: "Riley", createdAt: 1_795_300_000,
                    expiresAt: 1_795_300_000 + 7 * 86_400),
            ]
            model.folders = ["Production", "Production / Databases", "Staging"]
            // Mo's Staging folder, shared with Olivia to view.
            model.folderRoles = [
                "Production": .manage, "Production / Databases": .manage, "Staging": .view,
            ]
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
            model.health = PasswordHealth(
                logins: [
                    HealthLogin(
                        itemId: "00000000-0000-4000-8000-000000000001", name: "AWS root",
                        username: "root", folder: "Production", weak: false,
                        reusedWith: ["Bank"], oldSince: 1_740_000_000),
                    HealthLogin(
                        itemId: "00000000-0000-4000-8000-000000000003", name: "Bank",
                        username: "olivia", folder: nil, weak: true,
                        reusedWith: ["AWS root"], oldSince: nil),
                ],
                checked: 6, agesKnown: true)
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
        if big {
            // 5,000 logins, for `-measure`: a tenth on To Change, a tenth on Password Health.
            let folders = ["Production", "Production / Databases", "Staging", nil]
            model.items = (0..<5000).map { index in
                ItemSummary(
                    id: String(format: "00000000-0000-4000-8000-%012d", 1000 + index),
                    folder: folders[index % folders.count], name: "Login \(index)",
                    username: "user\(index)@example.com", url: "https://site\(index).example.com",
                    owner: nil, sharedWith: index % 7 == 0 ? ["Mo"] : [], sharedWithGroups: [],
                    sharedWithMe: false, role: .manage, hasOneTimeCode: index % 5 == 0)
            }
            model.toChange = model.items.enumerated().filter { $0.offset % 10 == 0 }.map {
                ToChange(
                    itemId: $0.element.id, name: $0.element.name, folder: $0.element.folder,
                    userId: 4, userName: "Pat", since: 1_795_500_000)
            }
            model.health = PasswordHealth(
                logins: model.items.enumerated().filter { $0.offset % 10 == 5 }.map {
                    HealthLogin(
                        itemId: $0.element.id, name: $0.element.name,
                        username: $0.element.username, folder: $0.element.folder, weak: true,
                        reusedWith: [], oldSince: nil)
                },
                checked: 5000, agesKnown: true)
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

    /// What importing a Passbolt export would do, for the demo.
    static let demoImportPreview = ImportPreview(
        folders: [
            ImportFolderSummary(name: "Production", new: false, logins: 31),
            ImportFolderSummary(name: "Production / Databases", new: true, logins: 12),
            ImportFolderSummary(name: "Marketing", new: true, logins: 8),
        ],
        own: 5, duplicates: 2,
        viewOnly: [ImportFolderSummary(name: "Staging", new: false, logins: 4)],
        oneTimeCodes: 9)

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

    func showDemoWelcome(_ page: WelcomePage) {
        joiningCode = nil
        recoveryClaim = nil
        approvedKeys = nil
        message = nil
        welcomePage = page
        phase = .welcome
    }

    func showDemoWaitingForOwner() {
        showDemoWelcome(.recoverWithHelp)
        recoveryClaim = RecoveryClaimInfo(
            userId: 2, name: "Mo", fingerprint: "7e3a-91c4-0b2d-58f6-a1e9")
    }

    func showDemoPhase(_ phase: Phase) {
        recoveryClaim = nil
        lockNote = nil
        self.phase = phase
    }

    /// Locked to sign in again, with a server too old to renew sessions: the longest note.
    /// A message from before stays hidden behind it.
    func showDemoLockedToSignIn() {
        message = "Couldn't sync (couldn't reach the server). Showing the copy on this Mac."
        lockNote = Self.signInAgainNote(serverRenews: false)
        phase = .locked
    }

    func showDemoNotices() {
        message = "Couldn't sync (couldn't reach the server). Showing the copy on this Mac."
        copiedName = "AWS root"
        updates.showDemo()
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

extension PendingInvitation: Identifiable {}

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
/// The owner cancelled a recovery this Mac was waiting on, or it expired.
private struct RecoveryEnded: LocalizedError {
    var errorDescription: String? {
        "The owner cancelled this recovery, or it expired. Ask them to start again."
    }
}

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

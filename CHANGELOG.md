# Changes

What each release changes, newest first. The release workflow puts a version's section at the top of its GitHub release, above the install notes. GitHub shows line breaks there as they are, so each paragraph and item is one line. Releases before 0.16.0 have their notes on the [releases page](https://github.com/elquimista/keystead/releases).

## 0.18.0

Update the server, then the apps, in any order; older apps keep working.

**Security**

- Turning escrow off is now the last word: your app remembers it, and doesn't take your earlier agreement if the server shows it again. Turning escrow on again later works as before. Needs the server and the app on 0.18.0.
- The server refuses an agreement to escrow that was already used, as from a copied session.
- Once someone has turned escrow on with 0.18.0, their older apps show it as off and can't turn it on again; they're told to update.
- An account has at most ten devices. Adding another from a device you have says to remove one you no longer use first; a Recovery Kit still brings your account back, in place of your oldest device.
- Keystead connects only to `https://` servers when setting up, joining, recovering or adding a device; `http://` works only for a server on the same computer, so nobody on the network can read or change what it sends. Macs and CLIs already set up with an `http://` address keep it, and warn that it isn't private.
- On a Mac, the CLI keeps your account secret and its sign-in key in the login Keychain instead of a plain file; an existing setup moves over the next time you run a command. The first run of a newly built `keystead` may ask to use them: choose Always Allow. Elsewhere they stay in `device.json`, readable only by you.
- Server certificates are checked by the operating system, as browsers do: a certificate from your company's own authority works once your Mac trusts it, so a self-hosted server doesn't need `http://`.

**Invites**

- No more reading out fingerprints to join. An invite line now carries a key that never reaches the server; joining with it proves the new account's keys are theirs, and the owner's Keystead approves them on its own the next time it syncs. While invites are waiting, the owner's Mac app syncs every minute.
- If the keys on the server don't match the invite, the owner's Keystead says so and leaves them waiting: approve them only if the fingerprint they read out matches. Fingerprints stay under People for anyone who wants to compare.
- Joining with a new invite line takes Keystead 0.18.0 or later; older apps can't read it. Invites made with an older server, or before updating, work as before, with a fingerprint check.

**Fixes**

- The CLI no longer refuses an invite, new-device or recovery line whose token starts with a dash, as about one in 64 did.

## 0.17.0

Update the server first, then every app and CLI soon after, starting with the owner and the folders' managers.

**Security**

- What each person may do in a folder (view, edit, manage) is now signed by its managers, and apps go by that rather than the server's word. A change by someone who only views a folder is ignored. The first time a folder's manager opens 0.17.0, the app signs the folder's roles as they are.
- Apps keep the newest copy they have seen of every login, folder and group, and say so if the server sends an older one.
- Apps before 0.17.0 keep reading and editing, but can't share a folder whose roles are signed, change a role in it, or remove from the team someone who is a folder's only manager; the server tells them to update.

**Fixes**

- A new device's first sync, and a big folder shared with someone, no longer fail past about 10 MB: they arrive in parts.
- After a server is restored from a backup, apps warn, pick up what changes from then on, and saving a login again puts it past what anyone saw. See Backups in `deploy/README.md`.

## 0.16.0

Update the server first, then the apps. Older apps keep working with a 0.16.0 server.

**Server**

- Invites work once, for seven days, and the owner can revoke one nobody has used. Invites made before the update run out seven days after it.
- A device keeps at most eight sessions and four waiting sign-in challenges, so one device can't make the server hold more and more.
- Joining, recovery and setup check their token before queueing to write, so bad tokens don't hold up saves.
- The setup code works for a day. After that, restarting a server nobody has claimed prints a new one.
- `deploy/keystead.nginx.conf` now limits requests per client address. Copy it over yours, as in step 3 of the deployment guide.

**Apps and CLI**

- People lists who has been invited and hasn't joined yet, with Revoke Invite. In the CLI: `keystead invites` and `keystead invites revoke <ID>`.
- With a server older than 0.16.0, invites work as before, and revoking says to update the server. 

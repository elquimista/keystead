# Changes

What each release changes, newest first. The release workflow puts a version's section at the top of its GitHub release, above the install notes. GitHub shows line breaks there as they are, so each paragraph and item is one line. Releases before 0.16.0 have their notes on the [releases page](https://github.com/elquimista/keystead/releases).

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

# Changes

What each release changes, newest first. The release workflow puts a version's section at the top of its GitHub release, above the install notes. GitHub shows line breaks there as they are, so each paragraph and item is one line. Releases before 0.16.0 have their notes on the [releases page](https://github.com/elquimista/keystead/releases).

## 0.19.0

Update the server and the apps in any order; each works with the other on an older version, without the new savings. Copy the new `deploy/keystead.nginx.conf` over yours, and `git pull` for the new `deploy/compose.yaml`, as in "Updating to 0.19.0" in `deploy/README.md`.

**Security**

- An error about a login whose content doesn't read right says where, but no longer quotes what it says, so its content never shows up in a message.
- Importing a KeePass file refuses one that asks for more than 1 GB of memory, or hours of work, to open, before trying; a file made to harm could otherwise stall or crash Keystead. KeePassXC's and Keystead's own exports are far inside that.
- The apps read at most 4 MB of a server's error answer, so a server can't make them read without end.
- In the CLI, `--otp -` asks for a one-time code setup instead of taking it in the command, where others on the computer could see it in `ps` and it stayed in your shell's history; a setup code can be left out to be asked for too. Passphrases and recovery words are wiped from memory once used, and so is the account secret the Mac app hands to Keystead's core.
- A server that says it has no groups no longer makes the next save of a login drop its groups' copies; the groups stay as they were.
- Mac app: if the screen locks or the Mac sleeps while Keystead is unlocking, it locks again as soon as unlocking finishes; and a click after the time without using it is up locks it, rather than counting as use. Locking also forgets your name and what was selected.
- Mac app: a revealed password or notes hide again a minute after they were shown.
- Mac app: invite, new-device and recovery lines are copied the way passwords are: to this Mac only, hidden from clipboard managers, and cleared after 30 seconds.
- Mac app: launch arguments no longer change the auto-lock time or put an update notice up, and the update's link is checked again before Keystead opens it.

**Speed**

- Saves no longer wait while the server tidies Recently Deleted: what logins deleted over 30 days ago kept is forgotten once an hour instead, and the list is read without holding up anyone's saves. With 30,000 logins, that's about 60 ms off every save, and a list that kept everyone's saves waiting about 100 ms now takes about 6 ms and keeps nobody waiting.
- New indexes for what saves and syncs look up, such as a login's people and a folder's members. The server adds them on its own when it starts.
- The Mac app fetches Recently Deleted when you open it, rather than after every sync.
- Copying a password or one-time code in the Mac app no longer waits for a sync in progress: the sync waits on the server without holding up the logins on your Mac. A server that can't be reached says so after 10 seconds rather than 30.
- A sync that brings nothing new downloads almost nothing: the server says which lists (people, groups, passwords to change, your roles) haven't changed instead of sending them again, and Keystead doesn't check them all over again. For someone on a 300-person team, each such sync went from about 90 KB to under 1 KB, and the work on the Mac from about 10 ms to under 3. It takes the server and the app or CLI on 0.19.0; either one alone works as before.
- Imports no longer slow down as you have more logins: the server now checks only who can reach the login being saved, rather than everything each of them can reach, and an import sends its logins 200 at a time instead of one request each. Importing into an account that already has 2,000 of its own logins went from about 3 ms a login to about a third of a millisecond, and saving a login shared with a 100-person group from about 60 ms to 25. Batches take the server and the app or CLI on 0.19.0; with an older server, an import sends one request a login as before.
- Password Health remembers which passwords it found weak, for each version of a login, so checking again only scores the ones that changed: with 20,000 logins, from about 6 seconds each time to a fifth of a second after the first. Only whether each is weak is kept, in memory, never the password. While it scores, the Mac app can still copy passwords.
- Moving a login, group actions and saving a login with a one-time code no longer open a new connection to ask the server what it can do; Keystead asks at most every five minutes.
- The server reads its database through a memory map, with a bigger cache and two connections kept ready, which makes its heavier reads up to about three times faster.
- A sync that brings nothing new no longer rewrites the copy of your logins on your Mac (with 30,000 logins, about 30 MB every five minutes); the CLI's likewise. When something changes, the file is a fifth smaller than before.

**Deployment**

- `deploy/compose.yaml` runs the server with a read-only file system (it writes only its database, in the volume), no Linux capabilities and no way to gain any, and won't start without `KEYSTEAD_VERSION` in `.env` rather than run whatever is newest. The `git pull` in the guide's update steps brings it. The server image is built from base images pinned by digest, with a pinned Rust.
- `deploy/keystead.nginx.conf` refuses requests for any domain name but yours, so another Cloudflare customer can't reach your server, past your Cloudflare rules, by pointing their own domain at it. It also keeps its connections to the server open between requests, and lets Cloudflare resume TLS sessions. Copy it over yours as in step 3 of `deploy/README.md`; nothing else changes. The guide also covers Authenticated Origin Pulls with a certificate of your own, which closes the rest of that gap.

## 0.18.0

Update the server and the apps in any order; older apps keep working with a 0.18.0 server. People joining with a new invite need Keystead 0.18.0.

**Security**

- Turning escrow off is now the last word: your app remembers it, and doesn't take your earlier agreement if the server shows it again. Turning escrow on again later works as before. Needs the server and the app on 0.18.0.
- The server refuses an agreement to escrow that was already used, as from a copied session.
- Once someone has turned escrow on with 0.18.0, their older apps show it as off and can't turn it on again; they're told to update.
- An account has at most ten devices. Adding another from a device you have says to remove one you no longer use first; a Recovery Kit still brings your account back, in place of your oldest device.
- Keystead connects only to `https://` servers when setting up, joining, recovering or adding a device; `http://` works only for a server on the same computer, so nobody on the network can read or change what it sends. Macs and CLIs already set up with an `http://` address keep it, and warn that it isn't private.
- Server certificates are checked by the operating system, as browsers do: a certificate from your company's own authority works once your Mac trusts it, so a self-hosted server doesn't need `http://`.
- On a Mac, the CLI keeps your account secret and its sign-in key in the login Keychain instead of a plain file; an existing setup moves over the next time you run a command. The first run of a newly built `keystead` may ask to use them: choose Always Allow. Elsewhere they stay in `device.json`, readable only by you.

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

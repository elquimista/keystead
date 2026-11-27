# Deploying Keystead on a server

This runs the Keystead server in Docker on a Linux server, behind nginx on the same
machine, with Cloudflare in front, at `https://<your domain>`:

```
Keystead app ──HTTPS──▶ Cloudflare ──HTTPS──▶ nginx ──HTTP, same machine──▶ Keystead server
```

The Keystead server listens only on the machine's own `127.0.0.1`. The firewall lets only
Cloudflare reach nginx. nginx limits how many requests each client address makes, so one
address can't flood the server.

**What Cloudflare sees.** HTTPS ends at Cloudflare, so Cloudflare can read the requests,
just as the server can. Passwords and folder contents are encrypted on the Mac before they
leave it, so neither sees them. Both see people's names and public keys, the encrypted
items, session tokens, and who syncs when.

**Save your Recovery Kit right after setup.** The owner's account exists only on their Mac.
If that Mac is lost or wiped, the Recovery Kit is the only way to get it back; without it,
nobody can invite or approve people on that server any more. Keystead asks for it after
setup, and it's always under People › You. Recovering needs server 0.2.0 or later.

**Keystead is early software**, and hasn't had a security audit yet. Keep another copy of
your passwords for now: from 0.13.0, File › Export Logins… (or `keystead export`) saves
them to an encrypted KeePass file.

## What you need

- A Linux server with nginx installed, on x86-64 or ARM. These steps use Ubuntu or
  Debian; other distributions work the same with their own paths. 1 CPU and 1 GB of
  memory are plenty.
- [Docker Engine](https://docs.docker.com/engine/install/) with the Compose plugin.
- A domain on Cloudflare, and a name in it for Keystead, such as `keys.example.com`.
  Choose the one you'll keep: every Mac stores the address when it joins, and there's no
  way to move them later.

## 1. Start the Keystead server

The server runs as the image published from each release, `ghcr.io/elquimista/keystead-server`.
`deploy/.env` pins which release:

```sh
git clone https://github.com/elquimista/keystead.git
cd keystead/deploy
cp .env.example .env           # check KEYSTEAD_VERSION; change KEYSTEAD_PORT if 8080 is taken
docker compose up -d
curl http://127.0.0.1:8080/v1/health
```

## 2. Set up Cloudflare

In the Cloudflare dashboard, for your domain:

1. **DNS:** add an `A` record for `keys` with the server's IPv4 address (and an `AAAA`
   record if it has IPv6), with the proxy on (orange cloud).
2. **SSL/TLS > Overview:** set the encryption mode to **Full (strict)**.
3. **SSL/TLS > Edge Certificates:** turn on **Always Use HTTPS**, and set the minimum TLS
   version to 1.2.
4. **SSL/TLS > Origin Server:** create a certificate for `keys.example.com`. Keep the
   certificate and private key it shows; Cloudflare shows the key only once.
5. **Keep Cloudflare's browser checks away from Keystead.** The Keystead app isn't a web
   browser, so anything that answers it with a challenge page breaks sign-in and sync:
   - **Security > Bots:** turn **Bot Fight Mode** off. It can't be turned off for just one
     hostname.
   - **Rules > Configuration Rules:** add a rule for hostname equals `keys.example.com`
     that turns **Browser Integrity Check** off.
   - Don't use "I'm Under Attack" mode for this hostname.
6. **Caching > Cache Rules:** add a rule for hostname equals `keys.example.com` that
   **bypasses the cache**. Cloudflare doesn't cache API responses by default; this makes
   sure it never does.

## 3. Put nginx in front of the Keystead server

Save the Origin certificate and its key where only root can read the key:

```sh
sudo mkdir -p /etc/ssl/keystead
sudo nano /etc/ssl/keystead/origin.pem    # paste the certificate
sudo nano /etc/ssl/keystead/origin.key    # paste the private key
sudo chmod 600 /etc/ssl/keystead/origin.key
```

Copy the site configuration, replace `keys.example.com` with your domain (and `8080` in
`proxy_pass` if you changed `KEYSTEAD_PORT`), enable it and reload nginx:

```sh
sudo cp keystead.nginx.conf /etc/nginx/sites-available/keystead
sudo nano /etc/nginx/sites-available/keystead
sudo ln -s /etc/nginx/sites-available/keystead /etc/nginx/sites-enabled/keystead
sudo nginx -t && sudo systemctl reload nginx
```

On distributions without `sites-available`, copy it to `/etc/nginx/conf.d/keystead.conf`
instead.

The configuration also answers HTTPS for any other domain name, closing the connection
without a reply, so a domain someone else points at this machine reaches nothing. If
`nginx -t` reports a duplicate default server, another site already claims port 443 with
`default_server`: remove that word from one of them. To check, from the server:

```sh
curl -sk --resolve other.example:443:127.0.0.1 https://other.example/v1/health   # Empty reply from server
```

## 4. Let only Cloudflare in

Allow SSH, and HTTPS only from [Cloudflare's addresses](https://www.cloudflare.com/ips/):

```sh
sudo ufw allow OpenSSH
for range in $(curl -s https://www.cloudflare.com/ips-v4) $(curl -s https://www.cloudflare.com/ips-v6); do
    sudo ufw allow proto tcp from "$range" to any port 443
done
sudo ufw enable
```

This applies to every site on this nginx. If other sites must stay reachable without
Cloudflare, skip this step. Cloudflare's address list changes rarely; run the loop again
if it does. The Keystead server's own port is published on `127.0.0.1` only, so it isn't
reachable from outside even though Docker bypasses `ufw` for the ports it publishes.

Check from your Mac:

```sh
curl https://keys.example.com/v1/health
```

### Optional: only through your own Cloudflare zone

The firewall lets in every Cloudflare customer, not only you. Step 3's configuration
already refuses their domains; only Cloudflare's Enterprise plan could make Cloudflare
send yours instead. **Authenticated Origin Pulls** closes that too: Cloudflare shows a
client certificate of your own on every connection, and nginx turns away connections
without it. Don't use Cloudflare's own certificate for this: every Cloudflare customer
shares it.

1. Make a certificate authority and, signed by it, the client certificate Cloudflare will
   show (replace `keys.example.com`):

   ```sh
   cd /etc/ssl/keystead
   sudo openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=Keystead origin pull CA" \
       -keyout origin-pull-ca.key -out origin-pull-ca.pem
   sudo openssl req -newkey rsa:2048 -nodes -subj "/CN=keys.example.com" \
       -keyout origin-pull.key -out origin-pull.csr
   printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n' \
       | sudo tee origin-pull.ext > /dev/null
   sudo openssl x509 -req -in origin-pull.csr -CA origin-pull-ca.pem -CAkey origin-pull-ca.key \
       -CAcreateserial -days 3650 -extfile origin-pull.ext -out origin-pull.pem
   ```

2. In Cloudflare, **SSL/TLS > Origin Server > Authenticated Origin Pulls**, under
   **Zone-level**, choose **Upload certificate** and paste `origin-pull.pem` and
   `origin-pull.key`. Leave the switch off for now.
3. In `/etc/nginx/sites-available/keystead`, uncomment the two `ssl_client_certificate`
   and `ssl_verify_client` lines, with `optional` in place of `on`, and reload nginx.
4. Turn on **Zone-level** in Cloudflare, and check Keystead still syncs.
5. Change `optional` to `on` and reload nginx. Keystead should still sync, and a request
   without the certificate should be refused, from the server:

   ```sh
   curl -sk -o /dev/null -w '%{http_code}\n' --resolve keys.example.com:443:127.0.0.1 https://keys.example.com/v1/health   # 400
   ```

6. Cloudflare has the client key now: delete `origin-pull.key`, `origin-pull.csr` and
   `origin-pull.ext`, and move `origin-pull-ca.key` off the server. You need it only to make
   a new client certificate in ten years; without it, make a new authority then.

To undo it, turn **Zone-level** off in Cloudflare after commenting the two lines out again.

## 5. Claim the server, right away

Until someone claims it, anyone with the one-time setup code can become the owner. The
code is only in the server's log, and works for a day from the server's first start:

```sh
docker compose logs server
```

If the day has passed, `docker compose restart server` makes a new code; use the last one
in the log.

In Keystead on your Mac, choose **Set up a new team** and enter `https://keys.example.com`,
the setup code and your name, then confirm with Touch ID. You're the owner. The setup code
stops working once it's used.

## 6. Invite your team

In Keystead, open **People** and choose **Invite**. Send each person their invite line
directly, for example in a private message; it works once, for seven days. Until they've
used it, they show under People as invited, where you can revoke the invite if it went to
the wrong place. They need Keystead 0.18.0 or later. When they've joined, your Keystead
approves them on its own the next time it syncs: the key on the line proves the keys they
joined with are theirs. If it says their keys don't match the invite, approve them only
after they read you the fingerprint their Keystead shows, in person or on a call. Then
share folders, or single logins, with them.

## Updating

Releases are listed on the repository's
[Releases page](https://github.com/elquimista/keystead/releases) from 0.13.1 on, with the
Mac app to download, and all of them under its
[tags](https://github.com/elquimista/keystead/tags). To move to one:

```sh
cd keystead
git pull                       # picks up any changes to these deploy files
cd deploy
nano .env                      # set KEYSTEAD_VERSION to the new release, such as 0.2.0
docker compose pull
docker compose up -d
```

The data stays in its volume across updates. Take a backup first (see below): a new version
may upgrade the database, and going back to an older version means restoring that backup.

**Updating to 0.2.0.** Logins get a new format, so that they can live outside folders and be
shared one by one. Update the server first, then every Mac app and the CLI: apps from 0.2.0
can't save logins to an older server, and older apps can't open logins saved by 0.2.0.
Existing logins keep working and switch to the new format when next saved.

**Updating to 0.3.0.** Folders and logins get roles (view, edit, manage), and people can
be removed from folders, from logins and from the team. Everyone who already had access
becomes a manager, so nothing changes until someone changes it. Update every app and the
CLI along with the server: once someone is removed from anything, apps older than 0.3.0
can't sync with that server any more.

**Updating to 0.4.0.** Groups: the owner makes them, and folders and logins can be shared
with a group as with a person. Nothing changes until someone makes a group. Update every
app and the CLI before anyone does: apps older than 0.4.0 can't sync once their user is in
a group, and can't open logins shared with one. Apps from 0.4.0 still work with a 0.3.0
server, but can't use groups until the server is updated.

**Updating to 0.5.0.** Passwords to change: from now on, when someone loses access, the
server remembers which passwords they could see until new ones are saved, and apps list
them under To Change. Nothing is recorded for people removed before the update. Older apps
keep working, but they don't tell the server when they save a new password, so a password
changed in one stays on the list until someone chooses to keep it; update the apps too.
Apps from 0.5.0 work with older servers and just show no list.

**Updating to 0.6.0.** One-time codes: a login can keep a site's one-time code setup, and
apps show the current code. A login with a code is saved in a new format that apps before
0.6.0 can't open, so they don't lose the code by saving the login without it. But an app
before 0.6.0 can't list any logins once it syncs one with a code, so update every app and
the CLI before anyone adds a code. Nothing changes until someone does. Apps from 0.6.0 work
with older servers, but say the server needs updating before saving a code.

**Updating to 0.7.0.** History: the server keeps the last 10 earlier versions of each
login, and apps from 0.7.0 show them to its editors and managers and can bring one back.
It starts from the update: logins saved before have no earlier versions yet. The database
grows with up to 10 earlier versions per login (a few KB each). Older apps keep working
without history, and apps from 0.7.0 work with older servers, saying the server keeps none.

**Updating to 0.8.0.** Adding a device from another: someone can add a new Mac or
computer from one that already has their account, by typing a code the new one shows,
without the Recovery Kit. The server only passes along a public key and the secret sealed
for it. Nothing else changes; older apps keep working, and apps from 0.8.0 say the server
needs updating if it's older.

**Updating to 0.8.1.** Only the Mac app changed: after a copied password clears, the
clipboard gets back what was on it before. The server is the same as 0.8.0, so updating it
is optional.

**Updating to 0.9.0.** Recently deleted: the server keeps a deleted login's earlier
versions for 30 days, so apps from 0.9.0 can bring it back, then forgets them. Logins
deleted before the update can't come back. The database keeps a little more for a while.
Older apps keep working without Recently Deleted, and apps from 0.9.0 work with older
servers, saying that deleted logins can't come back.

**Updating to 0.10.0.** Groups can be deleted: their members lose what only the group gave
them, and folders shared with it get new keys. Update the apps before deleting a group:
an app before 0.10.0 can't save a login that was shared with a deleted group until a newer
app has saved it once. Apps from 0.10.0 say the server needs updating if it's older. Also
fixes leaving a folder you still reach through a group, which made it vanish from the app.

**Updating to 0.11.0.** Only the apps and the CLI changed: importing from Passbolt (its
KDBX export) or a KeePass or KeePassXC file, and folders shown nested by name ("Production
/ Databases"), with new folders inside others starting out shared like their parent. The
Mac app can now read a file you choose in an Open panel, which also fixes reading a
one-time code's QR code from a screenshot. The server is the same as 0.10.0, so updating
it is optional.

**Updating to 0.12.0.** Logins can move to another folder, or out of folders as the mover's
own. Whoever had one only through its old folder loses it, and its password goes on their
To Change list. The database gets one more column. Update every app and the CLI before
anyone moves a login: apps before 0.12.0 keep showing a moved login in its old folder to
people who lost it. Apps from 0.12.0 work with older servers, saying the server needs
updating to move logins.

**Updating to 0.13.0.** Folders can be renamed and deleted, logins exported to an encrypted
KeePass file, and someone who lost every device and their Recovery Kit can recover with the
owner's help, getting back their own logins and private folders too if they turned on
escrow. Apps also check password health: weak, reused and old passwords. Renaming folders
and exporting work with any server; deleting folders, recovering with help, escrow and
spotting old passwords need this one. The database gets new tables and columns (schema
version 8 to 13): take a backup first. Update every app and the CLI before anyone recovers
with the owner's help: apps before 0.13.0 can't check a recovered person's new keys, so
they stop sharing with that person and ignore what they save. Apps from 0.13.0 work with
older servers, saying the server needs updating for what it can't do. The Mac app can now
write a file you choose in a Save panel, for exports.

**Updating to 0.13.1.** The server is the same as 0.13.0, but 0.13.0's image was never
published (its release waited on a macOS build that never got a machine), so a server on
0.12.0 goes straight to 0.13.1: follow the 0.13.0 note above, backup included. The Mac app
gets a new look, is about half the size, syncs on its own every few minutes, and has
keyboard shortcuts for the selected login. From this release on, each release's page has
the Mac app to download.

**Updating to 0.13.2.** The server is the same as 0.13.1; updating it is optional. The Mac
app now says when a newer release is out, with a link to its page: once a day it asks
`api.github.com` for this repository's latest release, sending only its version. People can
turn that off in Settings › Updates. Copies from 0.13.1 and earlier don't check, so tell
your team about this one.

**Updating to 0.14.0.** The Mac app stops asking for Touch ID or the password every
few minutes while it's unlocked. It used to sign in to the server again each time its
15-minute session ran out, and each sign-in used the Mac's device key; now it renews the
session without the key (`POST /v1/sign-in/renew`), so it asks only when it unlocks, or
after the server restarts. Update the server for this: with a 0.13 server, a 0.14.0 app
signs in as before and still asks, but says why. The order doesn't matter, and older apps
keep working with the new server.

**Updating to 0.14.1.** Sessions renew for up to 24 hours after a device signed in with
its key, so a copied session token can't be kept alive for good. After that the app signs
in with the key once, which asks for Touch ID or the password only if Keystead has stayed
unlocked that long. The limit comes from the server, so update it; the order doesn't
matter, and 0.14.0 apps keep working with it.

**Updating to 0.14.2.** The server is the same as 0.14.1; updating it is optional. When the
Mac app has to sign in with its key again while unlocked, it now locks instead of macOS
asking for Touch ID or the password out of the blue, and unlocking signs in. With a server
older than 0.14.0 that happens every 15 minutes, and the lock screen says to update it, so
update such a server first.

**Updating to 0.15.0.** Update the server and every app and CLI, the server first; take a
backup before, as the database gets new tables. This release fixes security problems, on
the server and in the apps, so don't leave either on an older version.

Who is in each folder and each group is now signed by its members, and apps hand a
folder's or a group's key only to the people those signatures name, not to whoever the
server lists. For the folders and groups you already have, nothing needs doing by hand:
the first time a folder's manager opens a 0.15.0 app, it signs for who is in the folder
then, and the owner's app, or a manager's, does the same for each group. Until a folder
has been signed for, people on 0.15.0 can open it but can't add logins to it, so have the
owner and the folders' managers update and open the app first.

Apps from before 0.15.0 keep reading and saving, but can't share or re-key a folder or
change a group once it has been signed for; the server tells them to update. Someone the
owner hasn't approved yet can no longer share anything or add a second device until they
are, and signing out of the Mac app now asks for Touch ID or the password.

**Updating to 0.16.0.** Update the server first, then the apps; older apps keep working
with it. Invites now work for seven days, and the owner can revoke one nobody has used,
under People. Invites made before the update run out seven days after it.

Copy the new `keystead.nginx.conf` over yours as in step 3, putting your domain (and
port) back in: it now limits how many requests each client address makes. The server
itself keeps only a few sessions for each device, and a setup code works for a day, which
matters only for a server nobody has claimed yet.

**Updating to 0.17.0.** Update the server first, then every app and CLI, soon after: the
folders' managers and the owner first.

What each person may do in a folder (view, edit, manage) is now signed by its managers,
like who is in it, and apps go by that instead of the server's word. Nothing needs doing
by hand: the first time a folder's manager opens a 0.17.0 app, it signs the folder's
roles as they are. From then on, for that folder:

- An app from before 0.17.0 still opens, adds and changes logins, but can't share the
  folder, change a role or give it a new key; the server tells it to update.
- The owner needs 0.17.0 to remove from the team someone who is a folder's only manager:
  their app signs in whoever has been in the folder longest as its next manager.
- Someone who only views a folder can't change its logins, even one shared with them
  directly to edit.

A new device's first sync, and a big folder shared with someone, used to fail once there
was more than about 10 MB to send. Both now arrive in parts. This needs the server and
the app on 0.17.0; an app from before still can't take a folder that big.

Apps now keep the newest copy they've seen of every login, folder and group, and say so if
the server hands them an older one, as a server restored from a backup does (see
Backups).

**Updating to 0.18.0.** Update the server and the apps in any order; older apps keep
working. Once the owner's app and the server are both on 0.18.0, new invite lines carry a
key, and the owner's Keystead approves whoever joins with one on its own, with no
fingerprint to read out. Whoever joins needs Keystead 0.18.0 or later: older apps can't
read the new lines. Invites made before keep working, with a fingerprint check.

Apps now set up, join and recover only with an `https://` address, or `http://` for a
server on the same computer; devices already set up with an `http://` address keep it and
show a warning. A certificate from your own certificate authority works once the Mac, or
the machine running the CLI, trusts it.

**Updating to 0.19.0.** Update the server and the apps in any order; each works with the
other on an older version, without the new savings. At its first start the server adds
some indexes, which takes a moment on a big database. It's faster throughout: an idle sync
downloads almost nothing, saves no longer wait on tidying Recently Deleted, and imports
send logins 200 at a time.

The `git pull` above brings a `compose.yaml` that runs the server with a read-only file
system (it writes only its database, in the volume), no Linux capabilities and no way to
gain any, and that won't start without `KEYSTEAD_VERSION` in `.env` rather than run
whatever is newest; `.env` from `.env.example` has it already. Copy
`keystead.nginx.conf` over yours as in step 3, putting your domain (and port) back in: it
refuses requests for any domain name but yours, so another Cloudflare customer can't reach
your server by pointing their domain at it, keeps its connections to the server open, and
lets Cloudflare resume TLS sessions. Authenticated Origin Pulls, which closes the rest of
that gap, is optional (end of step 4).

**Updating to 0.20.0.** Update the server and the apps in any order. From now on an
account the owner hasn't approved can't save logins or make folders; with an invite's key
the owner's Keystead approves people within minutes of their joining, so ask anyone
waiting to try again then. Fingerprints are longer (eight groups); the first five are the
ones earlier versions show, and those still work, on Recovery Kits printed before too.
Invite lines made by a 0.20.0 app need 0.20.0 to join.

## Backups

Everything the server knows is one SQLite database in the `keystead_keystead-data`
volume: encrypted logins and folders, plus people's names and public keys. A backup
reveals no passwords, but it's everything: without it, your team starts over. Stop the
server briefly so the copy is consistent:

```sh
docker compose stop server
docker run --rm -v keystead_keystead-data:/data:ro -v "$PWD":/backup \
    busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec \
    tar czf "/backup/keystead-$(date +%F).tgz" -C /data .
docker compose start server
```

Then copy the file somewhere else, for example with `scp` to your Mac.

To restore one, replacing what's on the server now:

```sh
docker compose stop server
docker run --rm -v keystead_keystead-data:/data -v "$PWD":/backup \
    busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec sh -c \
    'rm -rf /data/* && tar xzf /backup/keystead-2026-11-23.tgz -C /data && chown -R 65532:65532 /data'
docker compose start server
```

The server then knows nothing of what changed after the backup was made. Macs that synced
since keep their newer copies, and most say the server has older ones than they've seen; with a
0.17.0 server and apps, they pick up what changes from then on. Have people save again what
they changed since the backup: editing a login saves it past what anyone saw, so everyone
gets it. A login added since the backup has to be added again.

## Good to know

- **Building the image yourself** instead of using a published one, from the repository's
  root: `docker build -t ghcr.io/elquimista/keystead-server:local .`, then set
  `KEYSTEAD_VERSION=local` in `deploy/.env` and run `docker compose up -d`. The build
  compiles the server and needs about 2 GB of memory.

- `docker compose logs -f server` follows the server's log. It logs no passwords or other
  secrets; the server never sees them.
- If the app reports "server answered 403" (or 503) without a reason, Cloudflare probably
  challenged or blocked it: look in Cloudflare's **Security > Events** for
  `keys.example.com`.
- If the app reports "server answered 429", nginx turned the request away: that address
  made more requests than `keystead.nginx.conf` allows. The limits are far above what a
  team's apps make, even a large office behind one address; raise `rate` and `burst`
  there if yours meets them, and reload nginx.
- **Without Cloudflare's proxy** (grey cloud), the Keystead app would see the Origin CA
  certificate, which only Cloudflare trusts, and refuse to connect. Before turning the
  proxy off, switch nginx to a Let's Encrypt certificate (certbot) and open port 443 to
  everyone. Also change the `map` in `keystead.nginx.conf` so that `$keystead_client` is
  always `$binary_remote_addr`: without Cloudflare in front, anyone can send a
  `CF-Connecting-IP` of their own and so get around the limits.

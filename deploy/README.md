# Deploying Keystead on a server

This runs the Keystead server in Docker on a Linux server, behind nginx on the same
machine, with Cloudflare in front, at `https://<your domain>`:

```
Keystead app ──HTTPS──▶ Cloudflare ──HTTPS──▶ nginx ──HTTP, same machine──▶ Keystead server
```

The Keystead server listens only on the machine's own `127.0.0.1`. The firewall lets only
Cloudflare reach nginx.

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

## 5. Claim the server, right away

Until someone claims it, anyone with the one-time setup code can become the owner. The
code is only in the server's log:

```sh
docker compose logs server
```

In Keystead on your Mac, choose **Set up a new team** and enter `https://keys.example.com`,
the setup code and your name, then confirm with Touch ID. You're the owner. The setup code
stops working once it's used.

## 6. Invite your team

In Keystead, open **People** and choose **Invite**. Send each person their invite line
directly, for example in a private message; it works once. When they've joined, they show
up under People: approve them after they read you the fingerprint their Keystead shows, in
person or on a call. Then share folders, or single logins, with them.

## Updating

Releases are listed under the repository's
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

## Backups

Everything the server knows is one SQLite database in the `keystead_keystead-data`
volume: encrypted logins and folders, plus people's names and public keys. A backup
reveals no passwords, but it's everything: without it, your team starts over. Stop the
server briefly so the copy is consistent:

```sh
docker compose stop server
docker run --rm -v keystead_keystead-data:/data:ro -v "$PWD":/backup busybox \
    tar czf "/backup/keystead-$(date +%F).tgz" -C /data .
docker compose start server
```

Then copy the file somewhere else, for example with `scp` to your Mac.

To restore one, replacing what's on the server now:

```sh
docker compose stop server
docker run --rm -v keystead_keystead-data:/data -v "$PWD":/backup busybox sh -c \
    'rm -rf /data/* && tar xzf /backup/keystead-2026-11-23.tgz -C /data && chown -R 65532:65532 /data'
docker compose start server
```

Macs that synced after the backup was made keep their newer copies, but the server won't
know about changes made since. Have people re-add anything they changed.

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
- **Without Cloudflare's proxy** (grey cloud), the Keystead app would see the Origin CA
  certificate, which only Cloudflare trusts, and refuse to connect. Before turning the
  proxy off, switch nginx to a Let's Encrypt certificate (certbot) and open port 443 to
  everyone.

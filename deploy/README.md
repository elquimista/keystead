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
your passwords for now.

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
person or on a call. Then share folders with them.

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

The data stays in its volume across updates. To go back, set the previous version and run
the same two commands.

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

# Publishing the status page

aptwarden only writes `/var/lib/aptwarden/www/index.html` and `status.json` next to it;
it never runs a web server. This directory contains the pieces to publish the page on an existing nginx
server (e.g. your reverse proxy):

- The **central host pushes** the page and `status.json` whenever they change, using a
  dedicated SSH key. The key is restricted on the web server to writing (`rrsync -wo`)
  into one directory. A compromised central host can put any file into that directory,
  which nginx then serves under `/aptwarden/` (scripts are blocked by the page's CSP),
  but cannot read anything or write elsewhere. The web server gets no access to the
  central host.
- **nginx** serves it to the LAN only, and only with a password.

## 1. Central host

```sh
apt install rsync
runuser -u aptwarden -- ssh-keygen -t ed25519 -N '' -C "aptwarden-publish@$(hostname)" \
    -f /etc/aptwarden/ssh/publish_ed25519
cat /etc/aptwarden/ssh/publish_ed25519.pub      # needed in step 2
echo "PUBLISH_TARGET=aptwarden-publish@proxy.example.org" > /etc/aptwarden/publish.env
cp contrib/systemd/aptwarden-status-publish.{path,service} /etc/systemd/system/
systemctl daemon-reload
```

## 2. Web server

```sh
apt install rsync python3 apache2-utils         # rrsync ships with rsync; htpasswd
useradd --system --create-home --shell /bin/sh aptwarden-publish
install -d -m 755 -o aptwarden-publish -g aptwarden-publish /var/www/aptwarden
install -d -m 700 -o aptwarden-publish -g aptwarden-publish ~aptwarden-publish/.ssh
# one line: only from the central host, only rrsync, write-only, only /var/www/aptwarden
echo 'restrict,from="CENTRAL_IP",command="/usr/bin/rrsync -wo /var/www/aptwarden" ssh-ed25519 AAAA... aptwarden-publish@central' \
    > ~aptwarden-publish/.ssh/authorized_keys
chown aptwarden-publish: ~aptwarden-publish/.ssh/authorized_keys
chmod 600 ~aptwarden-publish/.ssh/authorized_keys

# password file with a bcrypt hash (prompts for the password); nginx checks it with
# the system's crypt(3), which supports bcrypt on Debian 12 and later
htpasswd -B -c /etc/nginx/aptwarden.htpasswd admin
chown root:www-data /etc/nginx/aptwarden.htpasswd
chmod 640 /etc/nginx/aptwarden.htpasswd
```

Add `nginx-aptwarden.conf` to the server block of an HTTPS vhost and adjust the
`allow` line and the HSTS header (it must repeat the server block's, see the comment
there), then `nginx -t && systemctl reload nginx`.

## 3. Connect and enable (central host)

```sh
# fetch the web server's host key and show its fingerprint
key=$(ssh-keyscan -t ed25519 proxy.example.org 2>/dev/null)
printf '%s\n' "$key" | ssh-keygen -lf -
# compare with the fingerprint on the web server itself:
#   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
# only if both match, record the key
printf '%s\n' "$key" >> /var/lib/aptwarden/known_hosts
runuser -u aptwarden -- aptwarden report             # writes the page the first time
systemctl start aptwarden-status-publish.service     # first copy, check for errors
systemctl enable --now aptwarden-status-publish.path
```

From now on every report or patch run updates the page within seconds.

## Check the restrictions

```sh
# on the central host: an interactive login must be refused
runuser -u aptwarden -- ssh -i /etc/aptwarden/ssh/publish_ed25519 aptwarden-publish@proxy.example.org
# from outside the allowed range, the page must answer 403; without a password, 401
```

`status.json` sits behind the same allowlist and password. A monitor such as Uptime
Kuma needs an `allow` line and the credentials (see the main README, "status.json for
monitoring").

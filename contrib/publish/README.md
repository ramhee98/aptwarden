# Publishing the status page

aptwarden only writes `/var/lib/aptwarden/www/index.html`; it never runs a web
server. This directory contains the pieces to publish the page on an existing nginx
server (e.g. your reverse proxy):

- The **central host pushes** the page whenever it changes, using a dedicated SSH key.
  The key is restricted on the web server to writing into one directory, so a
  compromised central host can only overwrite this file. The web server gets no access
  to the central host.
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
apt install rsync python3                       # rrsync ships with rsync
useradd --system --create-home --shell /bin/sh aptwarden-publish
install -d -m 755 -o aptwarden-publish -g aptwarden-publish /var/www/aptwarden
install -d -m 700 -o aptwarden-publish -g aptwarden-publish ~aptwarden-publish/.ssh
# one line: only from the central host, only rrsync, write-only, only /var/www/aptwarden
echo 'restrict,from="CENTRAL_IP",command="/usr/bin/rrsync -wo /var/www/aptwarden" ssh-ed25519 AAAA... aptwarden-publish@central' \
    > ~aptwarden-publish/.ssh/authorized_keys
chown aptwarden-publish: ~aptwarden-publish/.ssh/authorized_keys
chmod 600 ~aptwarden-publish/.ssh/authorized_keys

# password file (prompts for the password)
printf 'admin:%s\n' "$(openssl passwd -apr1)" > /etc/nginx/aptwarden.htpasswd
chown root:www-data /etc/nginx/aptwarden.htpasswd
chmod 640 /etc/nginx/aptwarden.htpasswd
```

Add `nginx-aptwarden.conf` to the server block of an HTTPS vhost and adjust the
`allow` line, then `nginx -t && systemctl reload nginx`.

## 3. Connect and enable (central host)

```sh
# record the web server's host key after checking its fingerprint
ssh-keyscan -t ed25519 proxy.example.org >> /var/lib/aptwarden/known_hosts
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

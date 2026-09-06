# pi_registrar

The registrar records authenticated IPv4 and IPv6 host addresses and can
optionally update DNS records. The package provides `pi_registrar_server` and
`pi_registrar_client`.

## Server configuration

Copy this example to `/etc/pi-registrar/server/config.yaml`:

```yaml
known_ca: |
  -----BEGIN CERTIFICATE-----
  REPLACE_WITH_CA_CERTIFICATE
  -----END CERTIFICATE-----
dns:
  zone: example.org
  ttl: 300
  key:
    name: registrar
    alg: hmac-sha256
    secret: replace-me
```

The server service runs as the dedicated `pi-registrar` user and is disabled
by default. Enable it with `systemctl enable --now pi-registrar-server`.

## Client configuration

Copy this example to `/etc/pi-registrar/client/client.conf` and set the
certificate file to a PEM containing both the certificate and private key:

```ini
ENDPOINT=https://registrar.example.org/
CERTIFICATE=/etc/pi-registrar/client/client.pem
CLIENT_ARGS=--ipv6
```

The client timer runs the request periodically. Enable it with
`systemctl enable --now pi-registrar-client.timer`.

## Debian packages

Build both packages with:

```sh
dpkg-buildpackage -us -uc
```

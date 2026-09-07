import base64
import datetime
import http
import ipaddress
import logging
import os
import sqlite3
import typing
import urllib.parse
import zoneinfo

import cherrypy
import cryptography.hazmat.backends
import cryptography.exceptions
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.x509
import cryptography.x509.oid
import dateutil.relativedelta
import dns.query
import dns.rcode
import dns.resolver
import dns.tsigkeyring
import dns.update
import jwt
import yaml


class Store:
    CONFIG_FILE = os.environ.get("CONFIG_FILE", "config.yaml")

    def __init__(self):
        self.dns_zone = None
        self.dns_ttl = 0
        self.dns_keyring = None
        self.known_ca = None
        self.timezone = datetime.timezone.utc
        try:
            with open(self.CONFIG_FILE, "rt", encoding="utf-8") as config_file:
                config = yaml.safe_load(config_file) or {}
        except (OSError, yaml.YAMLError) as err:
            logging.warning("Config read failed: %s", err)
            config = {}
        self.db = config.get("database", "hostreg.db")

        timezone = config.get("timezone", "UTC")
        try:
            self.timezone = zoneinfo.ZoneInfo(timezone)
        except (ValueError, zoneinfo.ZoneInfoNotFoundError):
            logging.warning("timezone %s is not a valid timezone name", timezone)

        known_ca = config.get("known_ca")
        if known_ca:
            try:
                self.known_ca = cryptography.x509.load_pem_x509_certificate(
                    known_ca.encode("ascii"), cryptography.hazmat.backends.default_backend()
                )
            except ValueError:
                logging.warning("known_ca is not a valid PEM certificate")
        cfg_dns = config.get("dns", {})
        if cfg_dns:
            self.dns_zone = cfg_dns["zone"]
            self.dns_ttl = int(cfg_dns["ttl"])
            dns_key = cfg_dns.get("key", cfg_dns)
            self.dns_keyring = dns.tsigkeyring.from_text(
                {dns_key["name"]: (dns_key["alg"], dns_key["secret"])}
            )

    def hit(self, ip_addr: typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address], cert: str):
        dt = datetime.datetime.now(datetime.timezone.utc)
        if self.dns_zone and self.dns_ttl > 0 and self.dns_keyring:
            soa = dns.resolver.resolve(self.dns_zone, "SOA")
            soa_server = str(soa[0].mname) if soa else None
            if soa_server:
                addresses = dns.resolver.resolve(soa_server, "AAAA")
                if addresses:
                    update = dns.update.Update(self.dns_zone, keyring=self.dns_keyring)
                    record_type = "A" if ip_addr.version == 4 else "AAAA"
                    update.replace(cert, self.dns_ttl, record_type, str(ip_addr))
                    dns.query.tcp(update, str(addresses[0]), timeout=5)

        with sqlite3.connect(self.db) as db_connection:
            cursor = db_connection.cursor()
            cursor.execute("DELETE FROM maps WHERE dt < ?", (dt + dateutil.relativedelta.relativedelta(days=-1),))
            cursor.execute(
                """INSERT INTO maps (ver, cert, address, dt) VALUES (?, ?, ?, ?)
                   ON CONFLICT(ver, cert) DO UPDATE SET address=excluded.address, dt=excluded.dt""",
                (ip_addr.version, cert, str(ip_addr), dt),
            )

    def format_dt(self, value) -> str:
        if not isinstance(value, datetime.datetime):
            try:
                value = datetime.datetime.fromisoformat(str(value))
            except ValueError:
                return str(value)
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(self.timezone).strftime("%Y-%m-%d %H:%M:%S")

    def read(self):
        with sqlite3.connect(self.db) as db_connection:
            for row in db_connection.execute("SELECT ver, cert, address, dt FROM maps ORDER BY dt DESC"):
                yield str(row[0]), str(row[1]), str(row[2]), self.format_dt(row[3])


def _verify_dt(value):
    try:
        dt = datetime.datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        raise cherrypy.HTTPError(http.HTTPStatus.UNAUTHORIZED.value, "Invalid dt claim")
    now = datetime.datetime.now(datetime.timezone.utc)
    if abs(now - dt) > datetime.timedelta(minutes=1):
        raise cherrypy.HTTPError(http.HTTPStatus.UNAUTHORIZED.value, "Invalid dt claim")


def _certificate_from_x5c(value: str):
    try:
        return cryptography.x509.load_der_x509_certificate(
            base64.b64decode(value), cryptography.hazmat.backends.default_backend()
        )
    except (ValueError, TypeError):
        raise cherrypy.HTTPError(http.HTTPStatus.UNAUTHORIZED.value, "Invalid certificate")


def _verify_certificate(certificate, known_ca):
    if known_ca is None:
        return False
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = certificate.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    valid_until = certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if not (valid_from <= now <= valid_until):
        return False
    if certificate.issuer != known_ca.subject:
        return False
    public_key = known_ca.public_key()
    try:
        if isinstance(public_key, cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
        elif isinstance(public_key, cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(certificate.signature_hash_algorithm),
            )
        else:
            return False
    except (
        cryptography.exceptions.InvalidSignature,
        TypeError,
        ValueError,
    ):
        return False
    return True


_store = Store()


class Root:
    def _get(self):
        cherrypy.response.headers["Content-Type"] = "text/html; charset=utf-8"
        cherrypy.response.status = "200 OK"
        rows = ["<html><body><table>", "<tr><th>V</th><th>certificate</th><th>IP address</th><th>updated</th></tr>"]
        rows.extend("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % item for item in _store.read())
        rows.append("</table></body></html>")
        return "\n".join(rows)

    def _map(self, real_ip, client_crt_cn):
        _store.hit(real_ip, client_crt_cn)
        cherrypy.response.headers["Content-Type"] = "text/plain; charset=utf-8"
        cherrypy.response.status = "202 Accepted"
        return "Your IP: %s\nYour certificate: %s\n" % (real_ip, client_crt_cn)

    @staticmethod
    def _request_ip():
        return ipaddress.ip_address(cherrypy.request.headers["X-Real-IP"])

    def _post(self):
        authorization = cherrypy.request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            raise cherrypy.HTTPError(http.HTTPStatus.UNAUTHORIZED.value, "Authorization header required")
        token = authorization[7:]
        try:
            header = jwt.get_unverified_header(token)
            _verify_dt(header["dt"])
            certificate = _certificate_from_x5c(header["x5c"][0])
            if not _verify_certificate(certificate, _store.known_ca):
                raise cherrypy.HTTPError(http.HTTPStatus.UNAUTHORIZED.value, "Certificate is not trusted")
            jwt.decode(token, certificate.public_key(), algorithms=[header["alg"]])
            real_ip = self._request_ip()
            client_crt_cn = certificate.subject.get_attributes_for_oid(
                cryptography.x509.oid.NameOID.COMMON_NAME
            )[0].value
        except cherrypy.HTTPError:
            raise
        except (KeyError, ValueError, jwt.PyJWTError):
            raise cherrypy.HTTPError(http.HTTPStatus.UNAUTHORIZED.value, "Invalid JWT")
        return self._map(real_ip, client_crt_cn)

    @cherrypy.expose
    def index(self):
        if cherrypy.request.method == "MAP":
            return self._map(
                self._request_ip(),
                cryptography.x509.load_pem_x509_certificate(
                    urllib.parse.unquote(
                        cherrypy.request.headers["X-SSL-Client-Certificate"]
                    ).encode("ascii"),
                    cryptography.hazmat.backends.default_backend(),
                ).subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)[0].value,
            )
        if cherrypy.request.method == "POST":
            return self._post()
        if cherrypy.request.method == "GET":
            return self._get()
        raise cherrypy.HTTPError(http.HTTPStatus.METHOD_NOT_ALLOWED.value, http.HTTPStatus.METHOD_NOT_ALLOWED.phrase)


def run():
    global _store
    with sqlite3.connect(_store.db) as db_connection:
        db_connection.execute(
            "CREATE TABLE IF NOT EXISTS maps (ver VARCHAR, cert VARCHAR, address VARCHAR, dt DATETIME, PRIMARY KEY (ver, cert))"
        )
    cherrypy.config.update({"engine.autoreload.on": False})
    cherrypy.tree.mount(Root())
    cherrypy.engine.start()
    cherrypy.engine.block()


wsgiapp = cherrypy.tree.mount(Root())

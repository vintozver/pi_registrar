import base64
import datetime
import http
import ipaddress
import logging
import os
import sqlite3
import typing

import cherrypy
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.asymmetric.ec
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
    DB = os.environ.get("PI_REGISTRAR_DB", "hostreg.db")
    CONFIG = os.environ.get("PI_REGISTRAR_CONFIG", "config.yaml")

    def __init__(self):
        self.dns_zone = None
        self.dns_ttl = 0
        self.dns_keyring = None
        self.known_ca = None
        try:
            with open(self.CONFIG, "rt", encoding="utf-8") as config_file:
                config = yaml.safe_load(config_file) or {}
        except (OSError, yaml.YAMLError) as err:
            logging.warning("Config read failed: %s", err)
            config = {}

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
        dt = datetime.datetime.utcnow()
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

        with sqlite3.connect(self.DB) as db_connection:
            cursor = db_connection.cursor()
            cursor.execute("DELETE FROM maps WHERE dt < ?", (dt + dateutil.relativedelta.relativedelta(days=-1),))
            cursor.execute("DELETE FROM maps WHERE ver = ? AND cert = ?", (ip_addr.version, cert))
            cursor.execute(
                "INSERT INTO maps (ver, cert, address, dt) VALUES (?, ?, ?, ?)",
                (ip_addr.version, cert, str(ip_addr), dt),
            )

    def read(self):
        with sqlite3.connect(self.DB) as db_connection:
            for row in db_connection.execute("SELECT ver, cert, address, dt FROM maps ORDER BY dt DESC"):
                yield tuple(map(str, row))


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
    try:
        known_ca.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except Exception:
        try:
            known_ca.public_key().verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                cryptography.hazmat.primitives.asymmetric.ec.ECDSA(certificate.signature_hash_algorithm),
            )
        except Exception:
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

    def _post(self):
        authorization = cherrypy.request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            raise cherrypy.HTTPError(http.HTTPStatus.UNAUTHORIZED.value, "Authorization header required")
        token = authorization[7:]
        try:
            header = jwt.get_unverified_header(token)
            certificate = _certificate_from_x5c(header["x5c"][0])
            if not _verify_certificate(certificate, _store.known_ca):
                raise cherrypy.HTTPError(http.HTTPStatus.UNAUTHORIZED.value, "Certificate is not trusted")
            payload = jwt.decode(token, certificate.public_key(), algorithms=[header["alg"]])
            real_ip = ipaddress.ip_address(payload["ip"])
            client_crt_cn = str(payload["certificate"])
        except cherrypy.HTTPError:
            raise
        except (KeyError, ValueError, jwt.PyJWTError):
            raise cherrypy.HTTPError(http.HTTPStatus.UNAUTHORIZED.value, "Invalid JWT")
        return self._map(real_ip, client_crt_cn)

    @cherrypy.expose
    def index(self):
        if cherrypy.request.method == "MAP":
            return self._map(
                ipaddress.ip_address(cherrypy.request.headers["X-Real-IP"]),
                cryptography.x509.load_pem_x509_certificate(
                    cherrypy.request.headers["X-SSL-Client-Certificate"].encode("ascii"),
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
    with sqlite3.connect(Store.DB) as db_connection:
        db_connection.execute(
            "CREATE TABLE IF NOT EXISTS maps (ver VARCHAR, cert VARCHAR, address VARCHAR, dt DATETIME, PRIMARY KEY (ver, cert))"
        )
    cherrypy.config.update({"engine.autoreload.on": False})
    cherrypy.tree.mount(Root())
    cherrypy.engine.start()
    cherrypy.engine.block()


wsgiapp = cherrypy.tree.mount(Root())

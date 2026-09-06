import argparse
import base64
import ipaddress
import socket
import ssl
import urllib.parse
import urllib.request

import cryptography.hazmat.backends
import cryptography.hazmat.primitives.serialization
import cryptography.x509
import cryptography.x509.oid
import jwt


def _resolve(endpoint, ipv4=False):
    parsed = urllib.parse.urlparse(endpoint)
    family = socket.AF_INET if ipv4 else socket.AF_INET6
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, family, socket.SOCK_STREAM)
    if not addresses:
        raise OSError("Endpoint has no address for requested IP family")
    address = addresses[0][4][0]
    host = "[%s]" % address if ":" in address else address
    return parsed._replace(netloc="%s:%s" % (host, parsed.port or 443)).geturl()


def _make_token(certificate_path, ip):
    with open(certificate_path, "rb") as certificate_file:
        pem = certificate_file.read()
    certificate = cryptography.x509.load_pem_x509_certificate(
        pem, cryptography.hazmat.backends.default_backend()
    )
    private_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(
        pem, None, backend=cryptography.hazmat.backends.default_backend()
    )
    cn = certificate.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)[0].value
    token = jwt.encode(
        {"ip": str(ip), "certificate": cn},
        private_key,
        algorithm="RS256",
        headers={
            "x5c": [
                base64.b64encode(
                    certificate.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER)
                ).decode("ascii")
            ]
        },
    )
    return token


def _local_address(host, port, family):
    address = socket.getaddrinfo(host, port, family, socket.SOCK_DGRAM)[0][4]
    with socket.socket(family, socket.SOCK_DGRAM) as connection:
        connection.connect(address)
        return connection.getsockname()[0]


def run(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--ipv4", action="store_true")
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--certificate", required=True)
    args = parser.parse_args(argv)
    endpoint = _resolve(args.endpoint, args.ipv4)
    parsed = urllib.parse.urlparse(endpoint)
    family = socket.AF_INET if args.ipv4 else socket.AF_INET6
    local_ip = _local_address(parsed.hostname, parsed.port, family)
    token = _make_token(args.certificate, ipaddress.ip_address(local_ip))
    request = urllib.request.Request(
        endpoint, method="POST", headers={"Authorization": "Bearer " + token}
    )
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, context=context) as response:
        return response.read().decode()

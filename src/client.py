import argparse
import base64
import socket
import ssl
import urllib.parse
import urllib.request

import cryptography.hazmat.backends
import cryptography.hazmat.primitives.serialization
import cryptography.x509
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


def _make_token(certificate_path):
    with open(certificate_path, "rb") as certificate_file:
        pem = certificate_file.read()
    certificate = cryptography.x509.load_pem_x509_certificate(
        pem, cryptography.hazmat.backends.default_backend()
    )
    private_key = cryptography.hazmat.primitives.serialization.load_pem_private_key(
        pem, None, backend=cryptography.hazmat.backends.default_backend()
    )
    token = jwt.encode(
        {},
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


def run(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--ipv4", action="store_true")
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--certificate", required=True)
    args = parser.parse_args(argv)
    endpoint = _resolve(args.endpoint, args.ipv4)
    token = _make_token(args.certificate)
    request = urllib.request.Request(
        endpoint, method="POST", headers={"Authorization": "Bearer " + token}
    )
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, context=context) as response:
        return response.read().decode()

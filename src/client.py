import argparse
import base64
import socket
import ssl
import http.client
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
    return endpoint, address


class _HTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, address, **kwargs):
        super().__init__(host, **kwargs)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, address, context):
        super().__init__(context=context)
        self.address = address

    def https_open(self, request):
        return self.do_open(
            lambda host, **kwargs: _HTTPSConnection(host, self.address, **kwargs),
            request,
            context=self._context,
        )


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
    endpoint, address = _resolve(args.endpoint, args.ipv4)
    token = _make_token(args.certificate)
    request = urllib.request.Request(
        endpoint, method="POST", headers={"Authorization": "Bearer " + token}
    )
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(_HTTPSHandler(address, context))
    with opener.open(request) as response:
        return response.read().decode()

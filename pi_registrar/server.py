import typing
import ipaddress
import cherrypy
import http
import datetime
import cryptography.x509
import cryptography.hazmat.backends
from threading import Lock


class Store(object):
    def __init__(self):
        self.lock = Lock()

        self.clients = list()
        # map client_id to
        # {ip_addr: {'cert': str, 'dt': utc_dt}
        self.ip_to_cert = dict()
        # {cert: {'ip': str, 'dt': utc_dt}
        self.cert_to_ip = dict()

    def hit(self, ip_addr: typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address], cert: str):
        dt = datetime.datetime.utcnow()
        self.ip_to_cert[ip_addr] = {'cert': cert, 'dt': dt}
        self.cert_to_ip[cert] = {'ip': ip_addr, 'dt': dt}


_store = Store()


class Root(object):
    def _get(self):
        cherrypy.response.headers['Content-Type'] = 'text/plain; encoding=utf-8'
        cherrypy.response.status = '200 OK'
        yield 'IP to certificate mappings\n'
        for ip, cert_info in _store.ip_to_cert.items():
            yield '%48s | %128s | %s' % (
                ip,
                ', '.join([subj_item.value for subj_item in cert_info['cert'].subject]),
                cert_info['dt'].isoformat()
            )

    def _post(self):
        real_ip = ipaddress.ip_address(cherrypy.request.headers['X-Real-IP'])
        client_crt = cryptography.x509.load_pem_x509_certificate(
            cherrypy.request.headers['X-SSL-Client-Certificate'].encode('ascii'),
            cryptography.hazmat.backends.default_backend()
        )
        _store.hit(real_ip, client_crt)
        cherrypy.response.headers['Content-Type'] = 'text/plain; encoding=utf-8'
        cherrypy.response.status = '202 Accepted'
        yield 'Your IP: %s\nYour certificate: %s' % (
            real_ip, ', '.join([subj_item.value for subj_item in client_crt.subject])
        )

    @cherrypy.expose
    def index(self):
        method = cherrypy.request.method
        if method == 'MAP':
            return self._post()
        elif method == 'GET':
            return self._get()
        else:
            raise cherrypy.HTTPError(
                http.HTTPStatus.METHOD_NOT_ALLOWED.value, http.HTTPStatus.METHOD_NOT_ALLOWED.phrase
            )
    _post.index = {'response.stream': True}


cherrypy.config.update({'engine.autoreload.on': False})
cherrypy.server.unsubscribe()
cherrypy.engine.start()


wsgiapp = cherrypy.tree.mount(Root())

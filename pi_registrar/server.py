import typing
import ipaddress
import cherrypy
import http
import datetime
import dateutil.relativedelta
import cryptography.x509
import cryptography.hazmat.backends
import sqlite3


class Store(object):
    DB = 'hostreg.db'

    def hit(self, ip_addr: typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address], cert: str):
        dt = datetime.datetime.utcnow()

        with sqlite3.connect(self.DB) as db_connection:
            db_cursor = db_connection.cursor()
            db_cursor.execute(
                '''DELETE FROM maps WHERE dt < ?''',
                (dt + dateutil.relativedelta.relativedelta(days=-1), )
            )
            db_cursor.execute(
                '''DELETE FROM maps WHERE address = ? AND cert = ?''',
                (str(ip_addr), cert)
            )
            db_cursor.execute(
                '''INSERT INTO maps (address, cert, dt) VALUES (?, ?, ?)''',
                (str(ip_addr), cert, dt)
            )

    def read(self):
        with sqlite3.connect(self.DB) as db_connection:
            db_cursor = db_connection.cursor()
            for row in db_cursor.execute('SELECT * FROM maps'):
                yield str(row)


_store = Store()


class Root(object):
    def _get(self):
        cherrypy.response.headers['Content-Type'] = 'text/plain; encoding=utf-8'
        cherrypy.response.status = '200 OK'
        return _store.read()

    def _post(self):
        real_ip = ipaddress.ip_address(cherrypy.request.headers['X-Real-IP'])
        client_crt = cryptography.x509.load_pem_x509_certificate(
            cherrypy.request.headers['X-SSL-Client-Certificate'].encode('ascii'),
            cryptography.hazmat.backends.default_backend()
        )
        _store.hit(real_ip, ', '.join([subj_item.value for subj_item in client_crt.subject]))
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


with sqlite3.connect(Store.DB) as db_connection:
    db_cursor = db_connection.cursor()
    try:
        db_cursor.execute(
            '''
CREATE TABLE maps (address VARCHAR, cert TEXT, dt DATETIME, PRIMARY KEY (address, cert))
'''
        )
    except sqlite3.OperationalError as err:
        print(err)


cherrypy.config.update({'engine.autoreload.on': False})
cherrypy.server.unsubscribe()
cherrypy.engine.start()


wsgiapp = cherrypy.tree.mount(Root())

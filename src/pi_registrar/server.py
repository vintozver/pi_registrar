import typing
import ipaddress
import cherrypy
import http
import datetime
import dateutil.relativedelta
import cryptography.x509
import cryptography.x509.oid
import cryptography.hazmat.backends
import sqlite3
import configparser
import dns.tsig
import dns.tsigkeyring
import dns.resolver
import dns.rcode
import dns.query
import dns.update
import logging


class Store(object):
    CONFIG = 'config.txt'
    DB = 'hostreg.db'

    def __init__(self):
        cfg = configparser.ConfigParser()
        try:
            cfg.read_file(open(self.CONFIG, 'rt'))
        except configparser.Error as err:
            logging.warn('Config read failed: %s' % err)

        self.dns_zone = None
        self.dns_ttl = 0
        self.dns_keyring = None

        if cfg.has_section('dns'):
            cfg_dns = cfg['dns']

            self.dns_zone = cfg_dns['zone']
            self.dns_ttl = int(cfg_dns['ttl'])

            dnskey_name = cfg_dns['key_name']
            dnskey_alg = cfg_dns['key_alg']
            dnskey_secret = cfg_dns['key_secret']

            self.dns_keyring = dns.tsigkeyring.from_text({dnskey_name: (dnskey_alg, dnskey_secret)})
        else:
            logging.warn('Config contains no "dns" section; skipped DNS update functionality')

    def hit(self, ip_addr: typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address], cert: str):
        dt = datetime.datetime.utcnow()

        if self.dns_zone is not None and self.dns_ttl > 0 and self.dns_keyring is not None:
            soa_server = None  # DNS SOA server name - to send updates to
            dns_answer = dns.resolver.resolve(self.dns_zone, 'SOA')
            if dns_answer.response.rcode() == dns.rcode.NOERROR:
                if len(dns_answer.response.answer) >= 1:
                    dns_answer_rrset = dns_answer.response.answer[0]
                    if len(dns_answer_rrset) >= 1:
                        soa_server = str(dns_answer_rrset[0].mname)

            soa_server_ip = None  # DNS SOA server IP - to send updates to
            if soa_server is not None:
                dns_answer = dns.resolver.resolve(soa_server, 'AAAA')
                if dns_answer.response.rcode() == dns.rcode.NOERROR:
                    if len(dns_answer.response.answer) >= 1:
                        dns_answer_rrset = dns_answer.response.answer[0]
                        if len(dns_answer_rrset) >= 1:
                            soa_server_ip = ipaddress.IPv6Address(dns_answer_rrset[0].to_text())

            if soa_server_ip is not None:
                dns_update = dns.update.Update(self.dns_zone, keyring=self.dns_keyring)
                if ip_addr.version == 4:
                    dns_update.replace(cert, self.dns_ttl, 'A', str(ip_addr))
                elif ip_addr.version == 6:
                    dns_update.replace(cert, self.dns_ttl, 'AAAA', str(ip_addr))
                else:
                    pass
                response = dns.query.tcp(dns_update, str(soa_server_ip), timeout=5)

        with sqlite3.connect(self.DB) as db_connection:
            db_cursor = db_connection.cursor()
            db_cursor.execute(
                '''DELETE FROM maps WHERE dt < ?''',
                (dt + dateutil.relativedelta.relativedelta(days=-1), )
            )
            db_cursor.execute(
                '''DELETE FROM maps WHERE ver = ? AND cert = ?''',
                (ip_addr.version, cert)
            )
            db_cursor.execute(
                '''INSERT INTO maps (ver, cert, address, dt) VALUES (?, ?, ?, ?)''',
                (ip_addr.version, cert, str(ip_addr), dt)
            )

    def read(self):
        with sqlite3.connect(self.DB) as db_connection:
            db_cursor = db_connection.cursor()
            for row in db_cursor.execute('SELECT ver, cert, address, dt FROM maps ORDER BY dt DESC'):
                yield str(row[0]), str(row[1]), str(row[2]), str(row[3])


_store = Store()


class Root(object):
    def _get(self):
        cherrypy.response.headers['Content-Type'] = 'text/html; encoding=utf-8'
        cherrypy.response.status = '200 OK'
        yield '<html>\n'
        yield '''<style>
table, th, td {
    border: 1px solid grey;
}
</style>'''
        yield '<body>\n'
        yield '<table>\n'
        yield '<tr><th>V</th><th>certificate</th><th>IP address</th><th>updated</th></tr>\n'
        for item in _store.read():
            yield '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' % item
        yield '</table>\n'
        yield '</body>\n'
        yield '</html>\n'
        return _store.read()

    def _post(self):
        real_ip = ipaddress.ip_address(cherrypy.request.headers['X-Real-IP'])
        client_crt = cryptography.x509.load_pem_x509_certificate(
            cherrypy.request.headers['X-SSL-Client-Certificate'].encode('ascii'),
            cryptography.hazmat.backends.default_backend()
        )
        client_crt_cn = client_crt.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)[0].value
        _store.hit(real_ip, client_crt_cn)
        cherrypy.response.headers['Content-Type'] = 'text/plain; encoding=utf-8'
        cherrypy.response.status = '202 Accepted'
        yield 'Your IP: %s\nYour certificate: %s\n' % (real_ip, client_crt_cn)

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
CREATE TABLE maps (ver VARCHAR, cert VARCHAR, address VARCHAR, dt DATETIME, PRIMARY KEY (ver, cert))
'''
        )
    except sqlite3.OperationalError as err:
        print(err)


cherrypy.config.update({'engine.autoreload.on': False})
cherrypy.server.unsubscribe()
cherrypy.engine.start()


wsgiapp = cherrypy.tree.mount(Root())

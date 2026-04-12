import sys, time, socket, logging
try:
    import Queue
except ImportError:
    import queue as Queue
try:
    import cStringIO
except ImportError:
    import io as cStringIO
try:
    from io import BytesIO
except ImportError:
    BytesIO = cStringIO.StringIO
from netlib import tcp, certutils, test
import mock
import tutils

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)

PYTHON2 = sys.version_info < (3,)

class SNIHandler(tcp.BaseHandler):
    sni = None
    def handle_sni(self, connection):
        self.sni = connection.get_servername()

    def handle(self):
        self.wfile.write(self.sni)
        self.wfile.flush()


class EchoHandler(tcp.BaseHandler):
    sni = None
    def handle_sni(self, connection):
        self.sni = connection.get_servername()

    def handle(self):
        v = self.rfile.readline()
        self.wfile.write(v)
        self.wfile.flush()


class CertHandler(tcp.BaseHandler):
    sni = None
    def handle_sni(self, connection):
        self.sni = connection.get_servername()

    def handle(self):
        self.wfile.write("%s\n"%self.clientcert.serial)
        self.wfile.flush()


class DisconnectHandler(tcp.BaseHandler):
    def handle(self):
        self.close()


class HangHandler(tcp.BaseHandler):
    def handle(self):
        while 1:
            time.sleep(1)


class TimeoutHandler(tcp.BaseHandler):
    def handle(self):
        self.timeout = False
        self.settimeout(0.01)
        try:
            self.rfile.read(10)
        except tcp.NetLibTimeout:
            self.timeout = True


class TestServer(test.ServerTestBase):
    handler = EchoHandler
    def test_echo(self):
        testval = 'echo!\n'
        c = tcp.TCPClient('127.0.0.1', self.port)
        c.connect()
        c.wfile.write(testval)
        c.wfile.flush()
        seen = c.rfile.readline().decode()
        logging.debug('TestServer.test_echo: testval=%r, seen=%r',
                      testval, seen)
        assert seen == testval



class FinishFailHandler(tcp.BaseHandler):
    def handle(self):
        logging.debug('FinishFailHandler.handle: attempting readline()')
        v = self.rfile.readline()
        logging.debug('FinishFailHandler.handle: attempting write()')
        self.wfile.write(v)
        self.wfile.flush()
        o = mock.MagicMock()
        self.wfile.close()
        self.rfile.close()
        self.close = mock.MagicMock(side_effect=socket.error)


class TestFinishFail(test.ServerTestBase):
    '''
    This tests a difficult-to-trigger exception in the .finish() method of
    the handler.
    '''
    handler = FinishFailHandler
    def test_disconnect_in_finish(self):
        c = tcp.TCPClient('127.0.0.1', self.port)
        c.connect()
        c.settimeout(10.0)  # added by jc@unternet.net to prevent hanging
        logging.debug('test_disconnect_in_finish: connected')
        c.wfile.write('foo\n')
        c.wfile.flush()
        c.rfile.read(4)
        h = self.last_handler
        logging.debug('test_disconnect_in_finish: finishing')
        h.finish()


class TestDisconnect(test.ServerTestBase):
    handler = EchoHandler
    def test_echo(self):
        testval = 'echo!\n'
        c = tcp.TCPClient('127.0.0.1', self.port)
        c.connect()
        c.wfile.write(testval)
        c.wfile.flush()
        seen = c.rfile.readline().decode()
        logging.debug('TestDisconnect.test_echo: testval=%r, seen=%r',
                      testval, seen)
        assert seen == testval


class TestServerSSL(test.ServerTestBase):
    handler = EchoHandler
    ssl = dict(
                cert = tutils.test_data.path('data/server.crt'),
                key = tutils.test_data.path('data/server.key'),
                request_client_cert = False,
                v3_only = False
            )
    def test_echo(self):
        c = tcp.TCPClient('127.0.0.1', self.port)
        c.connect()
        c.convert_to_ssl(sni=b'foo.com', options=tcp.OP_ALL)
        testval = 'echo!\n'
        c.wfile.write(testval)
        c.wfile.flush()
        seen = c.rfile.readline().decode()
        logging.debug('TestServerSSL.test_echo: testval=%r, seen=%r',
                      testval, seen)
        assert seen == testval

    def test_get_remote_cert(self):
        # can't set timeout without establishing connection first...
        # python2 may lock up on this test.
        if not PYTHON2:
            assert certutils.get_remote_cert(
                "127.0.0.1", self.port, None
            ).digest("sha1")


class TestSSLv3Only(test.ServerTestBase):
    handler = EchoHandler
    ssl = dict(
        cert = tutils.test_data.path("data/server.crt"),
        key = tutils.test_data.path("data/server.key"),
        request_client_cert = False,
        v3_only = True
    )
    def test_failure(self):
        c = tcp.TCPClient("127.0.0.1", self.port)
        c.connect()
        logging.debug('TestSSLv3Only.test_failure: connected: %s', vars(c))
        c.settimeout(10.0)  # added by jc@unternet.net to prevent hanging
        tutils.raises(tcp.NetLibError, c.convert_to_ssl, sni=b'foo.com', method=tcp.TLSv1_METHOD)
        logging.debug('TestSSLv3Only.test_failure: complete')


class TestSSLClientCert(test.ServerTestBase):
    handler = CertHandler
    ssl = dict(
        cert = tutils.test_data.path("data/server.crt"),
        key = tutils.test_data.path("data/server.key"),
        request_client_cert = True,
        v3_only = False
    )
    def test_clientcert(self):
        c = tcp.TCPClient("127.0.0.1", self.port)
        c.connect()
        c.convert_to_ssl(cert=tutils.test_data.path(
            "data/clientcert/client.pem")
        )
        assert c.rfile.readline().strip() == b"1"

    def test_clientcert_err(self):
        c = tcp.TCPClient("127.0.0.1", self.port)
        c.connect()
        tutils.raises(
            tcp.NetLibError,
            c.convert_to_ssl,
            cert=tutils.test_data.path("data/clientcert/make")
        )


class TestSNI(test.ServerTestBase):
    handler = SNIHandler
    ssl = dict(
        cert = tutils.test_data.path("data/server.crt"),
        key = tutils.test_data.path("data/server.key"),
        request_client_cert = False,
        v3_only = False
    )
    def test_echo(self):
        # hangs on python2 as of some time April 1-3 2026
        logging.debug('TestSNI.test_echo: starting')
        c = tcp.TCPClient("127.0.0.1", self.port)
        logging.debug('TestSNI.test_echo: connecting')
        c.connect()
        logging.debug('TestSNI.test_echo: convert_to_ssl')
        logging.debug('TestSNI.test_echo: if this is the last'
                      ' TestSNI.test_echo debugging message you see,'
                      ' it probably means the connection timed out')
        c.convert_to_ssl(sni=b'foo.com')
        logging.debug('TestSNI.test_echo: done convert_to_ssl')
        line = c.rfile.readline()
        logging.debug('TestSNI.test_echo: line=%r', line)
        assert line == b'foo.com'


class TestSSLDisconnect(test.ServerTestBase):
    handler = DisconnectHandler
    ssl = dict(
        cert = tutils.test_data.path("data/server.crt"),
        key = tutils.test_data.path("data/server.key"),
        request_client_cert = False,
        v3_only = False
    )
    def test_echo(self):
        c = tcp.TCPClient("127.0.0.1", self.port)
        c.connect()
        c.convert_to_ssl()
        # Excercise SSL.ZeroReturnError
        c.rfile.read(10)
        c.close()
        tutils.raises(tcp.NetLibDisconnect, c.wfile.write, "foo")
        tutils.raises(Queue.Empty, self.q.get_nowait)


class TestDisconnectAgain(test.ServerTestBase):
    def test_echo(self):
        c = tcp.TCPClient("127.0.0.1", self.port)
        c.connect()
        c.rfile.read(10)
        c.wfile.write("foo")
        c.close()
        c.close()


class TestServerTimeOut(test.ServerTestBase):
    handler = TimeoutHandler
    def test_timeout(self):
        c = tcp.TCPClient("127.0.0.1", self.port)
        c.connect()
        time.sleep(0.3)
        assert self.last_handler.timeout


class TestTimeOut(test.ServerTestBase):
    handler = HangHandler
    def test_timeout(self):
        c = tcp.TCPClient("127.0.0.1", self.port)
        c.connect()
        c.settimeout(0.1)
        assert c.gettimeout() == 0.1
        tutils.raises(tcp.NetLibTimeout, c.rfile.read, 10)


class TestSSLTimeOut(test.ServerTestBase):
    handler = HangHandler
    ssl = dict(
        cert = tutils.test_data.path("data/server.crt"),
        key = tutils.test_data.path("data/server.key"),
        request_client_cert = False,
        v3_only = False
    )
    def test_timeout_client(self):
        c = tcp.TCPClient("127.0.0.1", self.port)
        c.connect()
        c.convert_to_ssl()
        c.settimeout(0.1)
        tutils.raises(tcp.NetLibTimeout, c.rfile.read, 10)


class TestTCPClient:
    def test_conerr(self):
        c = tcp.TCPClient("127.0.0.1", 0)
        tutils.raises(tcp.NetLibError, c.connect)


class TestFileLike:
    def test_blocksize(self):
        s = BytesIO(b'1234567890abcdefghijklmnopqrstuvwxyz')
        s = tcp.Reader(s)
        s.BLOCKSIZE = 2
        assert s.read(1) == b'1'
        assert s.read(2) == b'23'
        assert s.read(3) == b'456'
        assert s.read(4) == b'7890'
        d = s.read(-1)
        assert d.startswith(b'abc') and d.endswith(b'xyz')

    def test_wrap(self):
        s = BytesIO(b'foobar\nfoobar')
        s.flush()
        s = tcp.Reader(s)
        assert s.readline() == b'foobar\n'
        assert s.readline() == b'foobar'
        # Test __getattr__
        assert s.isatty

    def test_limit(self):
        s = BytesIO(b'foobar\nfoobar')
        s = tcp.Reader(s)
        assert s.readline(3) == b'foo'

    def test_limitless(self):
        s = BytesIO(b'f' * (50 * 1024))
        s = tcp.Reader(s)
        ret = s.read(-1)
        assert len(ret) == 50 * 1024

    def test_readlog(self):
        s = BytesIO(b'foobar\nfoobar')
        s = tcp.Reader(s)
        assert not s.is_logging()
        s.start_log()
        assert s.is_logging()
        s.readline()
        assert s.get_log() == b'foobar\n'
        s.read(1)
        assert s.get_log() == b'foobar\nf'
        s.start_log()
        assert s.get_log() == b''
        s.read(1)
        assert s.get_log() == b'o'
        s.stop_log()
        tutils.raises(ValueError, s.get_log)

    def test_writelog(self):
        s = BytesIO()
        s = tcp.Writer(s)
        s.start_log()
        assert s.is_logging()
        s.write('x')
        assert s.get_log() == b'x'
        s.write('x')
        assert s.get_log() == b'xx'

    def test_writer_flush_error(self):
        s = cStringIO.StringIO()
        s = tcp.Writer(s)
        o = mock.MagicMock()
        o.flush = mock.MagicMock(side_effect=socket.error)
        s.o = o
        tutils.raises(tcp.NetLibDisconnect, s.flush)

    def test_reader_read_error(self):
        s = cStringIO.StringIO("foobar\nfoobar")
        s = tcp.Reader(s)
        o = mock.MagicMock()
        o.read = mock.MagicMock(side_effect=socket.error)
        s.o = o
        tutils.raises(tcp.NetLibDisconnect, s.read, 10)

    def test_reset_timestamps(self):
        s = cStringIO.StringIO("foobar\nfoobar")
        s = tcp.Reader(s)
        s.first_byte_timestamp = 500
        s.reset_timestamps()
        assert not s.first_byte_timestamp

    def test_first_byte_timestamp_updated_on_read(self):
        s = BytesIO(b'foobar\nfoobar')
        s = tcp.Reader(s)
        s.read(1)
        assert s.first_byte_timestamp
        expected = s.first_byte_timestamp
        s.read(5)
        assert s.first_byte_timestamp == expected

    def test_first_byte_timestamp_updated_on_readline(self):
        s = BytesIO(b'foobar\nfoobar\nfoobar')
        s = tcp.Reader(s)
        s.readline()
        assert s.first_byte_timestamp
        expected = s.first_byte_timestamp
        s.readline()
        assert s.first_byte_timestamp == expected


import os, logging
from netlib import certutils
import tutils

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)

try:
    file
except NameError:
    file = open

def test_dummy_ca():
    with tutils.tmpdir() as d:
        path = os.path.join(d, "foo/cert.cnf")
        assert certutils.dummy_ca(path)
        assert os.path.exists(path)

        path = os.path.join(d, "foo/cert2.pem")
        assert certutils.dummy_ca(path)
        assert os.path.exists(path)
        assert os.path.exists(os.path.join(d, "foo/cert2-cert.pem"))
        assert os.path.exists(os.path.join(d, "foo/cert2-cert.p12"))


class TestCertStore:
    def test_create_explicit(self):
        with tutils.tmpdir() as d:
            ca = os.path.join(d, "ca")
            assert certutils.dummy_ca(ca)
            c = certutils.CertStore()

    def test_create_tmp(self):
        with tutils.tmpdir() as d:
            ca = os.path.join(d, "ca")
            assert certutils.dummy_ca(ca)
            if __debug__:
                with open(ca, 'rb') as testfile:
                    logging.debug('test cert %s: %r', ca, testfile.read())
            c = certutils.CertStore()
            logging.debug('TestCertStore.test_create_tmp: c=%r', vars(c))
            assert c.get_cert(b'foo.com', [], ca)
            assert c.get_cert(b'foo.com', [], ca)
            assert c.get_cert(b'*.foo.com', [], ca)

    def test_check_domain(self):
        c = certutils.CertStore()
        assert c.check_domain(b'foo')
        assert c.check_domain(b'\x01foo')
        assert not c.check_domain(b'\xfefoo')
        assert not c.check_domain(b'xn--\0')
        assert not c.check_domain(b'foo..foo')
        assert not c.check_domain(b'foo/foo')


class TestDummyCert:
    def test_with_ca(self):
        with tutils.tmpdir() as d:
            cacert = os.path.join(d, "cacert")
            assert certutils.dummy_ca(cacert)
            r = certutils.dummy_cert(
                cacert,
                b'foo.com',
                [b'one.com', b'two.com', b'*.three.com']
            )
            #logging.debug('TestDummyCert.test_with_ca: r: %s', vars(r))
            logging.debug('TestDummyCert.test_with_ca: r.cn: %r', r.cn)
            assert r.cn == 'foo.com'


class TestSSLCert:
    def test_simple(self):
        c = certutils.SSLCert.from_pem(file(tutils.test_data.path("data/text_cert"), "rb").read())
        assert c.cn == 'google.com'
        #logging.debug('TestSSLCert.test_simple: cert c: %r', vars(c))
        #logging.debug('TestSSLCert.test_simple: cert c: %s', c.altnames)
        assert len(c.altnames) == 436

        c = certutils.SSLCert.from_pem(file(tutils.test_data.path(
            "data/text_cert_2"), "rb").read())
        assert c.cn == 'www.inode.co.nz'
        assert len(c.altnames) == 2
        assert c.digest(b'sha1')
        assert c.notbefore
        assert c.notafter
        assert c.subject
        assert c.keyinfo == ("RSA", 2048)
        assert c.serial
        assert c.issuer
        assert c.to_pem()
        c.has_expired

    def test_err_broken_sans(self):
        c = certutils.SSLCert.from_pem(file(tutils.test_data.path("data/text_cert_weird1"), "rb").read())
        # This breaks unless we ignore a decoding error.
        c.altnames

    def test_der(self):
        d = file(tutils.test_data.path("data/dercert"),"rb").read()
        s = certutils.SSLCert.from_der(d)
        assert s.cn

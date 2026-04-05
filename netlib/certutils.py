from __future__ import unicode_literals
import os, ssl, time, datetime, tempfile, shutil, logging
from pyasn1.type import univ, constraint, char, namedtype, tag
from pyasn1.codec.der.decoder import decode
from pyasn1.error import PyAsn1Error

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)

try:
    import OpenSSL
except ImportError:
    from . import openssl_compat as OpenSSL
try:
    import tcp
except ImportError:
    from . import tcp  # python3 syntax
try:
    file
except NameError:
    file = open

def create_ca():
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 1024)
    ca = OpenSSL.crypto.X509()
    ca.set_serial_number(int(time.time()*10000))
    ca.set_version(2)
    ca.get_subject().CN = b'mitmproxy'
    ca.get_subject().O = b'mitmproxy'
    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(24 * 60 * 60 * 720)
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(key)
    ca.add_extensions([
      # OpenSSL.crypto.X509Extension has args:
      #  type_name: bytes
      #  critical: bool
      #  value: bytes
      #  subject: 'X509 | None', default None
      #  issuer: 'X509 | None', default None
      OpenSSL.crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
      OpenSSL.crypto.X509Extension(b'nsCertType', True, b'sslCA'),
      OpenSSL.crypto.X509Extension(
          b'extendedKeyUsage',
          True,
          b'serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,'
          b'msCodeCom,msCTLSign,msSGC,msEFS,nsSGC'
      ),
      OpenSSL.crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
      OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash',
                                   subject=ca),
      ])
    ca.sign(key, "sha1")
    return key, ca


def dummy_ca(path):
    dirname = os.path.dirname(path)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    if path.endswith(".pem"):
        basename, _ = os.path.splitext(path)
        basename = os.path.basename(basename)
    else:
        basename = os.path.basename(path)

    key, ca = create_ca()

    # Dump the CA plus private key
    f = open(path, "wb")
    f.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
    f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
    f.close()

    # Dump the certificate in PEM format
    f = open(os.path.join(dirname, basename + "-cert.pem"), "wb")
    f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
    f.close()

    # Create a .cer file with the same contents for Android
    f = open(os.path.join(dirname, basename + "-cert.cer"), "wb")
    f.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
    f.close()

    # Dump the certificate in PKCS12 format for Windows devices
    f = open(os.path.join(dirname, basename + "-cert.p12"), "wb")
    p12 = OpenSSL.crypto.PKCS12()
    p12.set_certificate(ca)
    p12.set_privatekey(key)
    f.write(p12.export())
    f.close()
    return True


def dummy_cert(ca, name, sans):
    """
        Generates and writes a certificate to fp.

        ca: Path to the certificate authority file, or None.
        name: Common name for the generated certificate.
        sans: A list of Subject Alternate Names.

        Returns cert path if operation succeeded, None if not.
    """
    ss = []
    # assuming the subject alternate names are provided as strings not bytes
    for i in sans:
        ss.append('DNS: %s' % i)
    ss = ', '.join(ss).encode()  # turn it into bytes here

    raw = open(ca, 'rb').read()
    ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, raw)
    key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, raw)

    req = OpenSSL.crypto.X509Req()
    subj = req.get_subject()
    subj.CN = name
    req.set_pubkey(ca.get_pubkey())
    req.sign(key, "sha1")
    if ss:
        req.add_extensions([OpenSSL.crypto.X509Extension(
            b'subjectAltName', True, ss)]
        )
    cert = OpenSSL.crypto.X509()
    cert.gmtime_adj_notBefore(-3600)
    cert.gmtime_adj_notAfter(60 * 60 * 24 * 30)
    cert.set_issuer(ca.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_serial_number(int(time.time()*10000))
    if ss:
        cert.set_version(2)
        cert.add_extensions([OpenSSL.crypto.X509Extension(
            b'subjectAltName', True, ss)])
    cert.set_pubkey(req.get_pubkey())
    cert.sign(key, "sha1")
    return SSLCert(cert)


class CertStore:
    """
        Implements an in-memory certificate store.
    """
    def __init__(self):
        self.certs = {}

    def check_domain(self, name):
        '''
        check that common name is valid

        * must decode as 'idna' format
        * must decode as 'ascii' format
        * must not contain `..` nor `/`
        '''
        try:
            name.decode("idna")
            name.decode("ascii")
        except:
            return False
        if b'..' in name:
            return False
        if b'/' in name:
            return False
        return True

    def get_cert(self, name, sans, cacert):
        """
            Returns an SSLCert object.

            name: Common name for the generated certificate. Must be a
            valid, plain-ASCII, IDNA-encoded domain name.

            sans: A list of Subject Alternate Names.

            cacert: The path to a CA certificate.

            Return None if the certificate could not be found or generated.
        """
        logging.debug('CertStore.get_cert requested for %r', name)
        if not self.check_domain(name):
            logging.debug('CertStore.get_cert: name %r not in store', name)
            return None
        if name in self.certs:
            return self.certs[name]
        logging.debug('CertStore.get_cert: creating dummy cert for %r', name)
        c = dummy_cert(cacert, name, sans)
        self.certs[name] = c
        return c


class _GeneralName(univ.Choice):
    # We are only interested in dNSNames. We use a default handler to ignore
    # other types.
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('dNSName', char.IA5String().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )
        ),
    )


class _GeneralNames(univ.SequenceOf):
    componentType = _GeneralName()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, 1024)


class SSLCert:
    def __init__(self, cert):
        """
            Returns a (common name, [subject alternative names]) tuple.
        """
        self.x509 = cert

    @classmethod
    def from_pem(klass, txt):
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, txt)
        return klass(x509)

    @classmethod
    def from_der(klass, der):
        pem = ssl.DER_cert_to_PEM_cert(der)
        return klass.from_pem(pem)

    def to_pem(self):
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.x509)

    def digest(self, name):
        return self.x509.digest(name)

    @property
    def issuer(self):
        return self.x509.get_issuer().get_components()

    @property
    def notbefore(self):
        t = self.x509.get_notBefore().decode()
        return datetime.datetime.strptime(t, "%Y%m%d%H%M%SZ")

    @property
    def notafter(self):
        t = self.x509.get_notAfter().decode()
        return datetime.datetime.strptime(t, "%Y%m%d%H%M%SZ")

    @property
    def has_expired(self):
        return self.x509.has_expired()

    @property
    def subject(self):
        return self.x509.get_subject().get_components()

    @property
    def serial(self):
        return self.x509.get_serial_number()

    @property
    def keyinfo(self):
        pk = self.x509.get_pubkey()
        types = {
            OpenSSL.crypto.TYPE_RSA: "RSA",
            OpenSSL.crypto.TYPE_DSA: "DSA",
        }
        return (
            types.get(pk.type(), "UNKNOWN"),
            pk.bits()
        )

    @property
    def cn(self):
        c = None
        for i in self.subject:
            #logging.debug('SSLCert.cn: subject: %r', i)
            if i[0] == b'CN':
                c = i[1]
        return c

    @property
    def altnames(self):
        altnames = []
        count = self.x509.get_extension_count()
        #logging.debug('SSLCert.altnames: count=%s', count)
        for i in range(count or 0):
            ext = self.x509.get_extension(i)
            #logging.debug('extension: %r', dir(ext))
            # each extension has get_short_name, get_critical, get_data
            short_name = ext.get_short_name()
            data = ext.get_data()
            #logging.debug('short_name: %r, data: %r', short_name, data)
            if short_name == b'subjectAltName':
                try:
                    dec = decode(data, asn1Spec=_GeneralNames())
                    #logging.debug('decoded altnames: %r', dec)
                except PyAsn1Error:
                    logging.error('PyAsn1Error decoding altnames')
                    continue
                for i in dec[0]:
                    altnames.append(i[0].asOctets())
        return altnames


def get_remote_cert(host, port, sni):
    c = tcp.TCPClient(host, port)
    c.connect()
    c.convert_to_ssl(sni=sni)
    return c.cert

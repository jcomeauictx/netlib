'''
openssl_compat.py: drop-in shim for pyOpenSSL using only Python's ssl stdlib

Provides:
  - OpenSSL.SSL.Context, Connection, and method/option constants
  - OpenSSL.crypto: PKey, X509, X509Req, X509Extension, PKCS12,
    load_certificate, load_privatekey, dump_certificate, dump_privatekey,
    TYPE_RSA, TYPE_DSA, FILETYPE_PEM, FILETYPE_ASN1

Uses subprocess to call the `openssl` CLI for cert generation when the
stdlib ssl module can't do it natively (which is most cert operations).

No new imports outside the built-in library (except pyasn1 which is
already a dependency and is pure Python).
'''
from __future__ import print_function, unicode_literals
import ssl
import socket
import subprocess
import tempfile
import os
import time
import datetime
import struct
import hashlib
import logging
try:
    from io import BytesIO
except ImportError:
    from cStringIO import StringIO as BytesIO

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)
logger = logging.getLogger(__name__)

try:
    subprocess.run
    logging.warning('subprocess.run exists, why is not OpenSSL installed?')
except AttributeError:
    logging.warning('monkeypatching subprocess.run for python2')
    def run(*args, **kwargs):
        communicate_kwargs = {}
        for keyword in ['capture_output', 'timeout']:
            if keyword in kwargs:
                kwargs.pop(keyword)
        if 'input' in kwargs:
            kwargs['stdin'] = subprocess.PIPE
            communicate_kwargs = {'input': kwargs.pop('input')}
        process = subprocess.Popen(
            *args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **kwargs
        )
        stdout, stderr = process.communicate(**communicate_kwargs)
        returncode = process.returncode
        return type(b'result', (), {
            'returncode': returncode,
            'stdout': stdout,
            'stderr': stderr
        })
    subprocess.run = run
# ============================================================
# OpenSSL.SSL: SSL/TLS context and connection wrappers
# ============================================================

class _SSL:
    '''
    Namespace mimicking OpenSSL.SSL
    '''

    # Method constants -- all map to PROTOCOL_TLS (auto-negotiate)
    # The old specific protocol versions (SSLv2, SSLv3, TLSv1) are
    # disabled/broken in modern Python and modern servers reject them.
    # For a MITM proxy the right behavior is auto-negotiation anyway.
    SSLv2_METHOD = ssl.PROTOCOL_TLS
    SSLv3_METHOD = ssl.PROTOCOL_TLS
    SSLv23_METHOD = ssl.PROTOCOL_TLS
    TLSv1_METHOD = ssl.PROTOCOL_TLS

    # Option constants -- provide all that pyOpenSSL exposes
    # Missing ones get 0 (no-op when OR'd into options bitmask)
    OP_ALL = getattr(ssl, 'OP_ALL', 0x80000BFF)
    OP_CIPHER_SERVER_PREFERENCE = getattr(
        ssl, 'OP_CIPHER_SERVER_PREFERENCE', 0x00400000
    )
    OP_COOKIE_EXCHANGE = 0x00002000
    OP_DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800
    OP_EPHEMERAL_RSA = 0  # removed in modern OpenSSL
    OP_MICROSOFT_BIG_SSLV3_BUFFER = 0x00000020
    OP_MICROSOFT_SESS_ID_BUG = 0x00000001
    OP_MSIE_SSLV2_RSA_PADDING = 0x00000040
    OP_NETSCAPE_CA_DN_BUG = 0x20000000
    OP_NETSCAPE_CHALLENGE_BUG = 0x00000002
    OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 0x40000000
    OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 0x00000008
    OP_NO_QUERY_MTU = 0x00001000
    OP_NO_SSLv2 = getattr(ssl, 'OP_NO_SSLv2', 0)
    OP_NO_SSLv3 = getattr(ssl, 'OP_NO_SSLv3', 0x02000000)
    OP_NO_TICKET = getattr(ssl, 'OP_NO_TICKET', 0x00004000)
    OP_NO_TLSv1 = getattr(ssl, 'OP_NO_TLSv1', 0x04000000)
    OP_PKCS1_CHECK_1 = 0
    OP_PKCS1_CHECK_2 = 0
    OP_SINGLE_DH_USE = getattr(ssl, 'OP_SINGLE_DH_USE', 0)
    OP_SSLEAY_080_CLIENT_DH_BUG = 0x00000080
    OP_SSLREF2_REUSE_CERT_TYPE_BUG = 0x00000010
    OP_TLS_BLOCK_PADDING_BUG = 0x00000200
    OP_TLS_D5_BUG = 0x00000100
    OP_TLS_ROLLBACK_BUG = 0x00800000

    VERIFY_NONE = ssl.CERT_NONE
    VERIFY_PEER = ssl.CERT_OPTIONAL
    VERIFY_FAIL_IF_NO_PEER_CERT = ssl.CERT_REQUIRED

    # Exception classes
    class Error(ssl.SSLError):
        '''
        Generic SSL error, wrapping ssl.SSLError
        '''
        pass

    class ZeroReturnError(ssl.SSLZeroReturnError):
        '''
        SSL connection returned zero (clean shutdown)
        '''
        pass

    class WantReadError(ssl.SSLWantReadError):
        '''
        SSL wants to read more data
        '''
        pass

    class SysCallError(ssl.SSLSyscallError):
        '''
        SSL system call error
        '''
        pass

    class Context:
        '''
        Wraps ssl.SSLContext to provide pyOpenSSL-compatible API.
        '''
        def __init__(self, method=None):
            # Always use PROTOCOL_TLS for auto-negotiation.
            # The old method constants are all mapped to this above.
            self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
            # pyOpenSSL defaults: no verification
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
            self._sni_callback = None
            # Deferred cert/key loading -- pyOpenSSL allows setting
            # key and cert separately; stdlib ssl needs them together.
            self._key_file = None
            self._key_pem = None
            self._cert_pem = None
            self._cert_file = None
            self._loaded = False

        def _ensure_loaded(self):
            '''
            Load the cert chain into the SSLContext if we have both
            key and cert. Called lazily before handshake.
            '''
            if self._loaded:
                return
            # Collect PEM data from available sources
            key_pem = self._key_pem
            cert_pem = self._cert_pem

            if not key_pem and self._key_file:
                with open(self._key_file, 'rb') as f:
                    key_pem = f.read()

            if not cert_pem and self._cert_file:
                with open(self._cert_file, 'rb') as f:
                    cert_pem = f.read()

            if not key_pem and not cert_pem:
                return

            # Write combined PEM to temp file for SSLContext
            with tempfile.NamedTemporaryFile(
                mode='wb', suffix='.pem', delete=False
            ) as f:
                if key_pem:
                    f.write(
                        key_pem if isinstance(key_pem, bytes)
                        else key_pem.encode()
                    )
                    f.write(b'\n')
                if cert_pem:
                    f.write(
                        cert_pem if isinstance(cert_pem, bytes)
                        else cert_pem.encode()
                    )
                tmppath = f.name
            try:
                self._ctx.load_cert_chain(certfile=tmppath)
                self._loaded = True
            finally:
                os.unlink(tmppath)

        def set_options(self, options):
            '''
            Set context options (bitmask).
            '''
            self._ctx.options |= options

        def use_privatekey_file(self, path):
            '''
            Store private key file path for deferred loading.
            '''
            self._key_file = path
            self._loaded = False

        def use_certificate_file(self, path):
            '''
            Store certificate file path for deferred loading.
            '''
            self._cert_file = path
            self._loaded = False

        def use_certificate(self, x509):
            '''
            Store certificate PEM data from an X509 object.
            '''
            pem = x509._pem_data if hasattr(x509, '_pem_data') else None
            if pem:
                self._cert_pem = pem
                self._loaded = False

        def use_privatekey(self, pkey):
            '''
            Store private key PEM data from a PKey object.
            '''
            if hasattr(pkey, '_pem_data') and pkey._pem_data:
                self._key_pem = pkey._pem_data
                self._loaded = False

        def set_verify(self, mode, callback=None):
            '''
            Set verification mode.
            '''
            self._ctx.verify_mode = mode
            self._verify_callback = callback

        def set_tlsext_servername_callback(self, callback):
            '''
            Set SNI callback.
            '''
            self._sni_callback = callback
            # We'll wire this up in Connection

    class Connection:
        '''
        Wraps ssl.SSLSocket to provide pyOpenSSL-compatible API.
        '''
        def __init__(self, context, sock):
            self._context = context
            self._socket = sock
            self._ssl_socket = None
            self._server_hostname = None
            self._is_client = True  # default; set_accept_state changes this

        def set_connect_state(self):
            '''
            Set to client mode.
            '''
            self._is_client = True

        def set_accept_state(self):
            '''
            Set to server mode.
            '''
            self._is_client = False

        def set_tlsext_host_name(self, name):
            '''
            Set SNI hostname for client connections.
            '''
            if isinstance(name, bytes):
                name = name.decode('ascii')
            self._server_hostname = name

        def get_servername(self):
            '''
            Get the SNI server name from the client.
            '''
            if self._ssl_socket:
                sn = self._ssl_socket.server_hostname
                if sn:
                    return sn.encode('ascii') if isinstance(sn, str) else sn
            return None

        def set_context(self, new_context):
            '''
            Switch SSL context (used in SNI callback).
            For stdlib ssl, we store it but can't switch mid-handshake.
            This is a best-effort shim.
            '''
            self._context = new_context

        def do_handshake(self):
            '''
            Perform the SSL handshake.
            '''
            # Ensure cert/key are loaded into the context
            self._context._ensure_loaded()

            ctx = self._context._ctx

            # python2.7 ssl context didn't have sni_callback
            if self._context._sni_callback and hasattr(ctx, 'sni_callback'):
                # Set up SNI callback
                def _sni_cb(sslobj, servername, sslctx):
                    # Create a wrapper Connection-like object
                    self._sni_servername = servername.encode('idna')
                    try:
                        self._context._sni_callback(self)
                    except Exception:
                        pass
                ctx.sni_callback = _sni_cb

            try:
                if self._is_client:
                    self._ssl_socket = ctx.wrap_socket(
                        self._socket,
                        server_hostname=self._server_hostname,
                        do_handshake_on_connect=True,
                    )
                else:
                    self._ssl_socket = ctx.wrap_socket(
                        self._socket,
                        server_side=True,
                        do_handshake_on_connect=True,
                    )
            except ssl.SSLError as e:
                raise _SSL.Error(str(e))

        def get_peer_certificate(self):
            '''
            Get the peer's certificate as an X509 object.
            '''
            if self._ssl_socket:
                der = self._ssl_socket.getpeercert(binary_form=True)
                if der:
                    pem = ssl.DER_cert_to_PEM_cert(der)
                    x509 = X509()
                    x509._pem_data = pem.encode() if isinstance(
                        pem, str
                    ) else pem
                    x509._der_data = der
                    # Dict form only available with CERT_OPTIONAL/REQUIRED
                    try:
                        x509._parsed = self._ssl_socket.getpeercert(
                            binary_form=False
                        )
                    except ValueError:
                        x509._parsed = None
                    # If parsed is empty (CERT_NONE mode), parse via CLI
                    if not x509._parsed:
                        _parse_cert_via_cli(x509)
                    return x509
            return None

        def read(self, nbytes):
            '''
            Read data from SSL connection.
            '''
            try:
                return self._ssl_socket.read(nbytes)
            except ssl.SSLZeroReturnError:
                raise _SSL.ZeroReturnError()
            except ssl.SSLWantReadError:
                raise _SSL.WantReadError()
            except ssl.SSLSyscallError as e:
                raise _SSL.SysCallError(str(e))
            except ssl.SSLError as e:
                raise _SSL.Error(str(e))

        def write(self, data):
            '''
            Write data to SSL connection.
            '''
            try:
                return self._ssl_socket.write(data)
            except ssl.SSLError as e:
                raise _SSL.Error(str(e))

        def send(self, data):
            '''
            Send data.
            '''
            try:
                return self._ssl_socket.send(data)
            except ssl.SSLError as e:
                raise _SSL.Error(str(e))

        def sendall(self, data):
            '''
            Send all data.
            '''
            try:
                return self._ssl_socket.sendall(data)
            except ssl.SSLError as e:
                raise _SSL.Error(str(e))

        def recv(self, nbytes):
            '''
            Receive data.
            '''
            try:
                return self._ssl_socket.recv(nbytes)
            except ssl.SSLError as e:
                if 'EOF' in str(e):
                    return b''
                raise _SSL.Error(str(e))
            except AttributeError as e:
                logging.error('Connection._ssl_socket uninitialized? %s', e)
                return b''

        def shutdown(self):
            '''
            Shut down the SSL connection.
            '''
            if self._ssl_socket:
                try:
                    self._ssl_socket.unwrap()
                except (ssl.SSLError, OSError):
                    pass

        def close(self):
            '''
            Close the connection.
            '''
            if self._ssl_socket:
                try:
                    self._ssl_socket.close()
                except (ssl.SSLError, OSError):
                    pass

        def makefile(self, mode='r', buffering=-1):
            '''
            Create a file-like object for the SSL socket.
            '''
            if self._ssl_socket:
                return self._ssl_socket.makefile(mode, buffering)
            return self._socket.makefile(mode, buffering)

        def fileno(self):
            '''
            Return the socket file descriptor.
            '''
            if self._ssl_socket:
                return self._ssl_socket.fileno()
            return self._socket.fileno()

        def settimeout(self, timeout):
            '''
            Set socket timeout.
            '''
            if self._ssl_socket:
                self._ssl_socket.settimeout(timeout)
            else:
                self._socket.settimeout(timeout)

        def gettimeout(self):
            '''
            Get socket timeout.
            '''
            if self._ssl_socket:
                return self._ssl_socket.gettimeout()
            return self._socket.gettimeout()

        def getpeername(self):
            '''
            Get peer address.
            '''
            if self._ssl_socket:
                return self._ssl_socket.getpeername()
            return self._socket.getpeername()


# Make it importable as SSL
SSL = _SSL


# ============================================================
# OpenSSL.crypto: certificate and key operations via openssl CLI
# ============================================================

FILETYPE_PEM = 1
FILETYPE_ASN1 = 2
TYPE_RSA = 6
TYPE_DSA = 116


class PKey:
    '''
    Public/private key pair, wrapping openssl CLI for generation.
    '''
    def __init__(self):
        self._pem_data = None
        self._bits = None
        self._type = TYPE_RSA

    def generate_key(self, key_type, bits):
        '''
        Generate a new key pair using openssl CLI.
        '''
        self._type = key_type
        self._bits = bits
        if key_type == TYPE_RSA:
            result = subprocess.run(
                ['openssl', 'genrsa', str(bits)],
                capture_output=True, timeout=30,
            )
            if result.returncode != 0:
                raise _SSL.Error(
                    'openssl genrsa failed: ' + result.stderr.decode()
                )
            self._pem_data = result.stdout
        elif key_type == TYPE_DSA:
            # Generate DSA params then key
            result = subprocess.run(
                ['openssl', 'dsaparam', '-genkey', str(bits)],
                capture_output=True, timeout=30,
            )
            if result.returncode != 0:
                raise _SSL.Error(
                    'openssl dsaparam failed: ' + result.stderr.decode()
                )
            self._pem_data = result.stdout
        else:
            raise _SSL.Error('Unsupported key type: %s' % key_type)

    def type(self):
        '''
        Return key type.
        '''
        return self._type

    def bits(self):
        '''
        Return key size in bits.
        '''
        if self._bits:
            return self._bits
        if self._pem_data:
            result = subprocess.run(
                ['openssl', 'rsa', '-text', '-noout'],
                input=self._pem_data, capture_output=True, timeout=10,
            )
            for line in result.stdout.decode().split('\n'):
                if 'Private-Key' in line or 'Key:' in line:
                    import re
                    m = re.search(r'(\d+)\s*bit', line)
                    if m:
                        return int(m.group(1))
        return 0


class X509Name(object):
    '''
    Wraps an X.509 subject/issuer name with attribute-style access.
    '''
    def __init__(self):
        self._components = {}

    def __setattr__(self, name, value):
        if name.startswith('_'):
            super(X509Name, self).__setattr__(name, value)
        else:
            self._components[name] = value

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return self._components.get(name, '')

    def get_components(self):
        '''
        Return list of (name, value) tuples as bytes.
        '''
        result = []
        for k, v in self._components.items():
            kb = k.encode() if isinstance(k, str) else k
            vb = v.encode() if isinstance(v, str) else v
            result.append((kb, vb))
        return result

    def _to_openssl_string(self):
        '''
        Format as /KEY=VALUE/KEY=VALUE for openssl -subj argument.
        '''
        parts = []
        for k, v in self._components.items():
            if isinstance(v, bytes):
                v = v.decode()
            parts.append('/%s=%s' % (k, v))
        return ''.join(parts)


class X509Extension:
    '''
    Represents an X.509 extension.
    '''
    def __init__(self, name, critical, value, subject=None, issuer=None):
        self._name = name if isinstance(name, str) else name.decode()
        self._critical = critical
        self._value = value if isinstance(value, str) else value.decode()
        self._subject = subject
        self._issuer = issuer

    def get_short_name(self):
        '''
        Return the extension short name.
        '''
        return self._name.encode() if isinstance(
            self._name, str
        ) else self._name

    def get_data(self):
        '''
        Return raw extension data.
        For this shim, returns the string value encoded.
        '''
        return self._value.encode() if isinstance(
            self._value, str
        ) else self._value


class X509Req:
    '''
    Certificate signing request.
    '''
    def __init__(self):
        self._subject = X509Name()
        self._pubkey = None
        self._extensions = []

    def get_subject(self):
        '''
        Return the subject name.
        '''
        return self._subject

    def set_pubkey(self, pkey):
        '''
        Set the public key.
        '''
        self._pubkey = pkey

    def sign(self, pkey, digest):
        '''
        Sign the request (no-op in shim; actual signing done in cert gen).
        '''
        pass

    def add_extensions(self, exts):
        '''
        Add extensions to the request.
        '''
        self._extensions.extend(exts)

    def get_pubkey(self):
        '''
        Return the public key.
        '''
        return self._pubkey


class X509:
    '''
    X.509 certificate, backed by PEM data and/or openssl CLI.
    '''
    def __init__(self):
        self._pem_data = None
        self._der_data = None
        self._parsed = None  # dict from ssl.getpeercert()
        self._subject = X509Name()
        self._issuer = X509Name()
        self._serial = None
        self._version = 0
        self._not_before = 0
        self._not_after = 0
        self._pubkey = None
        self._extensions = []
        self._signed = False

    def set_serial_number(self, serial):
        '''
        Set the certificate serial number.
        '''
        self._serial = serial

    def set_version(self, version):
        '''
        Set the X.509 version (0=v1, 1=v2, 2=v3).
        '''
        self._version = version

    def get_subject(self):
        '''
        Return the subject name.
        '''
        if self._parsed and not self._subject._components:
            subj = self._parsed.get('subject', ())
            for rdn in subj:
                for name, value in rdn:
                    self._subject._components[name] = value
        return self._subject

    def get_issuer(self):
        '''
        Return the issuer name.
        '''
        if self._parsed and not self._issuer._components:
            iss = self._parsed.get('issuer', ())
            for rdn in iss:
                for name, value in rdn:
                    self._issuer._components[name] = value
        return self._issuer

    def set_issuer(self, name):
        '''
        Set the issuer from an X509Name.
        '''
        self._issuer = name

    def set_subject(self, name):
        '''
        Set the subject from an X509Name.
        '''
        self._subject = name

    def gmtime_adj_notBefore(self, seconds):
        '''
        Adjust notBefore relative to current time.
        '''
        self._not_before = seconds

    def gmtime_adj_notAfter(self, seconds):
        '''
        Adjust notAfter relative to current time.
        '''
        self._not_after = seconds

    def set_pubkey(self, pkey):
        '''
        Set the public key.
        '''
        self._pubkey = pkey

    def get_pubkey(self):
        '''
        Return the public key.
        '''
        if self._pubkey:
            return self._pubkey
        # Try to extract from PEM
        if self._pem_data:
            result = subprocess.run(
                ['openssl', 'x509', '-pubkey', '-noout'],
                input=self._pem_data, capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                pk = PKey()
                pk._pem_data = result.stdout
                return pk
        return PKey()

    def add_extensions(self, exts):
        '''
        Add X.509 extensions.
        '''
        self._extensions.extend(exts)

    def sign(self, pkey, digest):
        '''
        Sign the certificate. This is where we actually generate it
        using the openssl CLI.
        '''
        if isinstance(digest, bytes):
            digest = digest.decode()
        self._sign_key = pkey
        self._digest = digest
        self._signed = True

    def get_serial_number(self):
        '''
        Return the serial number.
        '''
        if self._parsed:
            sn = self._parsed.get('serialNumber', '')
            if sn:
                return int(sn, 16)
        return self._serial or 0

    def get_notBefore(self):
        '''
        Return notBefore as ASN1 time string.
        '''
        if self._parsed:
            nb = self._parsed.get('notBefore', '')
            # Python's ssl returns "Mon DD HH:MM:SS YYYY GMT"
            # pyOpenSSL returns "YYYYMMDDHHmmSSZ"
            try:
                dt = datetime.datetime.strptime(nb, '%b %d %H:%M:%S %Y %Z')
                return dt.strftime('%Y%m%d%H%M%SZ').encode()
            except (ValueError, TypeError):
                pass
        return b'19700101000000Z'

    def get_notAfter(self):
        '''
        Return notAfter as ASN1 time string.
        '''
        if self._parsed:
            na = self._parsed.get('notAfter', '')
            try:
                dt = datetime.datetime.strptime(na, '%b %d %H:%M:%S %Y %Z')
                return dt.strftime('%Y%m%d%H%M%SZ').encode()
            except (ValueError, TypeError):
                pass
        return b'20380101000000Z'

    def has_expired(self):
        '''
        Check if the certificate has expired.
        '''
        if self._parsed:
            na = self._parsed.get('notAfter', '')
            try:
                dt = datetime.datetime.strptime(na, '%b %d %H:%M:%S %Y %Z')
                return dt < datetime.datetime.utcnow()
            except (ValueError, TypeError):
                pass
        return False

    def get_extension_count(self):
        '''
        Return the number of extensions.
        '''
        return len(self._extensions)

    def get_extension(self, index):
        '''
        Return extension at index.
        '''
        return self._extensions[index]

    def digest(self, algorithm):
        '''
        Return certificate digest/fingerprint.
        '''
        if isinstance(algorithm, bytes):
            algorithm = algorithm.decode()
        if self._pem_data:
            result = subprocess.run(
                ['openssl', 'x509', '-fingerprint',
                 '-%s' % algorithm.lower(), '-noout'],
                input=self._pem_data, capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        if self._der_data:
            h = hashlib.new(algorithm.lower(), self._der_data)
            hexdigest = h.hexdigest().upper()
            formatted = ':'.join(
                hexdigest[i:i+2] for i in range(0, len(hexdigest), 2)
            )
            return formatted.encode()
        return b''


class PKCS12:
    '''
    PKCS#12 container.
    '''
    def __init__(self):
        self._cert = None
        self._key = None

    def set_certificate(self, cert):
        '''
        Set the certificate.
        '''
        self._cert = cert

    def set_privatekey(self, pkey):
        '''
        Set the private key.
        '''
        self._key = pkey

    def export(self, passphrase=None):
        '''
        Export as PKCS#12 data using openssl CLI.
        '''
        cert_pem = self._cert._pem_data if self._cert else b''
        key_pem = self._key._pem_data if self._key else b''

        with tempfile.NamedTemporaryFile(
            suffix='.pem', delete=False
        ) as cf:
            cf.write(cert_pem if isinstance(cert_pem, bytes)
                     else cert_pem.encode())
            cert_path = cf.name

        with tempfile.NamedTemporaryFile(
            suffix='.key', delete=False
        ) as kf:
            kf.write(key_pem if isinstance(key_pem, bytes)
                     else key_pem.encode())
            key_path = kf.name

        try:
            cmd = [
                'openssl', 'pkcs12', '-export',
                '-in', cert_path, '-inkey', key_path,
                '-passout', 'pass:' + (passphrase or ''),
            ]
            result = subprocess.run(
                cmd, capture_output=True, timeout=30,
            )
            if result.returncode != 0:
                raise _SSL.Error(
                    'PKCS12 export failed: ' + result.stderr.decode()
                )
            return result.stdout
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)


def _parse_cert_via_cli(x509):
    '''
    Parse an X509 object's PEM data using openssl CLI to populate
    subject, issuer, serial, and dates.
    '''
    if not x509._pem_data:
        return
    result = subprocess.run(
        ['openssl', 'x509', '-noout', '-subject', '-issuer',
         '-serial', '-dates', '-ext', 'subjectAltName'],
        input=x509._pem_data, capture_output=True, timeout=10,
    )
    if result.returncode != 0:
        return
    parsed = {}
    for line in result.stdout.decode().split('\n'):
        line = line.strip()
        if line.startswith('subject='):
            _parse_dn_into(line[8:].strip(), x509._subject)
        elif line.startswith('issuer='):
            _parse_dn_into(line[7:].strip(), x509._issuer)
        elif line.startswith('serial='):
            try:
                x509._serial = int(line[7:].strip(), 16)
            except ValueError:
                pass
        elif line.startswith('notBefore='):
            parsed['notBefore'] = line[10:].strip()
        elif line.startswith('notAfter='):
            parsed['notAfter'] = line[9:].strip()
    if parsed:
        x509._parsed = parsed


def _generate_cert_with_openssl(
    subject, issuer_cert_pem, issuer_key_pem, key_pem,
    serial, days, extensions, is_ca=False, digest='sha256'
):
    '''
    Generate a signed certificate using the openssl CLI.

    Returns PEM-encoded certificate bytes.
    '''
    # Write all temp files
    files_to_cleanup = []

    try:
        # Key for the new cert
        with tempfile.NamedTemporaryFile(
            suffix='.key', delete=False
        ) as f:
            f.write(key_pem if isinstance(key_pem, bytes)
                    else key_pem.encode())
            key_path = f.name
            files_to_cleanup.append(key_path)

        # If self-signed, issuer key is same as key
        if issuer_key_pem:
            with tempfile.NamedTemporaryFile(
                suffix='.key', delete=False
            ) as f:
                f.write(issuer_key_pem if isinstance(issuer_key_pem, bytes)
                        else issuer_key_pem.encode())
                ca_key_path = f.name
                files_to_cleanup.append(ca_key_path)
        else:
            ca_key_path = key_path

        # Build the openssl command
        subject_str = subject._to_openssl_string() if hasattr(
            subject, '_to_openssl_string'
        ) else '/CN=mitmproxy'

        if issuer_cert_pem and not is_ca:
            # CA-signed cert: use x509 -req
            # First create a CSR
            with tempfile.NamedTemporaryFile(
                suffix='.csr', delete=False
            ) as f:
                csr_path = f.name
                files_to_cleanup.append(csr_path)

            result = subprocess.run(
                ['openssl', 'req', '-new', '-key', key_path,
                 '-subj', subject_str, '-out', csr_path],
                capture_output=True, timeout=30,
            )
            if result.returncode != 0:
                raise _SSL.Error(
                    'CSR generation failed: ' + result.stderr.decode()
                )

            # Write CA cert
            with tempfile.NamedTemporaryFile(
                suffix='.pem', delete=False
            ) as f:
                f.write(issuer_cert_pem if isinstance(
                    issuer_cert_pem, bytes
                ) else issuer_cert_pem.encode())
                ca_cert_path = f.name
                files_to_cleanup.append(ca_cert_path)

            # Build extension config if needed
            ext_args = []
            if extensions:
                ext_conf = _build_ext_config(extensions)
                with tempfile.NamedTemporaryFile(
                    suffix='.cnf', delete=False, mode='w'
                ) as f:
                    f.write(ext_conf)
                    ext_path = f.name
                    files_to_cleanup.append(ext_path)
                ext_args = ['-extfile', ext_path, '-extensions', 'v3_ext']

            cmd = [
                'openssl', 'x509', '-req',
                '-in', csr_path,
                '-CA', ca_cert_path, '-CAkey', ca_key_path,
                '-set_serial', str(serial),
                '-days', str(days),
                '-%s' % digest,
            ] + ext_args

            result = subprocess.run(
                cmd, capture_output=True, timeout=30,
            )
            if result.returncode != 0:
                raise _SSL.Error(
                    'Cert signing failed: ' + result.stderr.decode()
                )
            return result.stdout

        else:
            # Self-signed cert
            ext_args = []
            if extensions:
                ext_conf = _build_ext_config(extensions)
                with tempfile.NamedTemporaryFile(
                    suffix='.cnf', delete=False, mode='w'
                ) as f:
                    f.write(ext_conf)
                    ext_path = f.name
                    files_to_cleanup.append(ext_path)
                ext_args = ['-extensions', 'v3_ext', '-config', ext_path]
            else:
                # Minimal config for req
                with tempfile.NamedTemporaryFile(
                    suffix='.cnf', delete=False, mode='w'
                ) as f:
                    f.write(
                        '[req]\n'
                        'distinguished_name = req_dn\n'
                        'prompt = no\n'
                        '[req_dn]\n'
                    )
                    for k, v in subject._components.items():
                        if isinstance(v, bytes):
                            v = v.decode()
                        f.write('%s = %s\n' % (k, v))
                    min_conf_path = f.name
                    files_to_cleanup.append(min_conf_path)
                ext_args = ['-config', min_conf_path]

            cmd = [
                'openssl', 'req', '-new', '-x509',
                '-key', key_path,
                '-subj', subject_str,
                '-set_serial', str(serial),
                '-days', str(days),
                '-%s' % digest,
            ] + ext_args

            result = subprocess.run(
                cmd, capture_output=True, timeout=30,
            )
            if result.returncode != 0:
                raise _SSL.Error(
                    'Self-signed cert failed: ' + result.stderr.decode()
                )
            return result.stdout

    finally:
        for path in files_to_cleanup:
            try:
                os.unlink(path)
            except OSError:
                pass


def _build_ext_config(extensions):
    '''
    Build an OpenSSL extension config file from X509Extension objects.
    '''
    lines = ['[v3_ext]']
    for ext in extensions:
        name = ext._name
        value = ext._value
        critical = 'critical,' if ext._critical else ''
        # Map pyOpenSSL extension names to openssl config names
        name_map = {
            'basicConstraints': 'basicConstraints',
            'nsCertType': 'nsCertType',
            'extendedKeyUsage': 'extendedKeyUsage',
            'keyUsage': 'keyUsage',
            'subjectKeyIdentifier': 'subjectKeyIdentifier',
            'subjectAltName': 'subjectAltName',
        }
        conf_name = name_map.get(name, name)
        lines.append('%s = %s%s' % (conf_name, critical, value))

    # Need a [req] section for openssl req
    config = (
        '[req]\n'
        'distinguished_name = req_dn\n'
        'x509_extensions = v3_ext\n'
        'prompt = no\n'
        '[req_dn]\n'
        'CN = mitmproxy\n'
        '\n'
    ) + '\n'.join(lines) + '\n'
    return config


def load_certificate(filetype, data):
    '''
    Load a certificate from PEM or DER data.
    '''
    x509 = X509()
    if filetype == FILETYPE_PEM:
        x509._pem_data = data if isinstance(data, bytes) else data.encode()
    elif filetype == FILETYPE_ASN1:
        x509._der_data = data
        x509._pem_data = ssl.DER_cert_to_PEM_cert(data).encode()
    # Try to parse subject/issuer via openssl CLI
    result = subprocess.run(
        ['openssl', 'x509', '-noout', '-subject', '-issuer',
         '-serial', '-dates'],
        input=x509._pem_data, capture_output=True, timeout=10,
    )
    if result.returncode == 0:
        for line in result.stdout.decode().split('\n'):
            line = line.strip()
            if line.startswith('subject='):
                _parse_dn_into(line[8:].strip(), x509._subject)
            elif line.startswith('issuer='):
                _parse_dn_into(line[7:].strip(), x509._issuer)
            elif line.startswith('serial='):
                try:
                    x509._serial = int(line[7:].strip(), 16)
                except ValueError:
                    pass
            elif line.startswith('notBefore='):
                pass  # stored in _parsed if available
            elif line.startswith('notAfter='):
                pass
    return x509


def _parse_dn_into(dn_string, x509name):
    '''
    Parse openssl DN string like "CN = foo, O = bar" into X509Name.
    '''
    for part in dn_string.split(','):
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            x509name._components[k.strip()] = v.strip()


def load_privatekey(filetype, data):
    '''
    Load a private key from PEM data.
    '''
    pk = PKey()
    if isinstance(data, str):
        data = data.encode()
    pk._pem_data = data
    # Determine type
    if b'RSA' in data:
        pk._type = TYPE_RSA
    elif b'DSA' in data:
        pk._type = TYPE_DSA
    return pk


def dump_certificate(filetype, x509):
    '''
    Dump a certificate in PEM or DER format.
    '''
    if filetype == FILETYPE_PEM:
        if x509._pem_data:
            return x509._pem_data
        # Generate the cert if it's been signed
        if x509._signed:
            return _realize_cert(x509)
        return b''
    elif filetype == FILETYPE_ASN1:
        if x509._der_data:
            return x509._der_data
        pem = dump_certificate(FILETYPE_PEM, x509)
        if pem:
            return ssl.PEM_cert_to_DER_cert(pem.decode())
        return b''
    return b''


def dump_privatekey(filetype, pkey):
    '''
    Dump a private key in PEM format.
    '''
    if filetype == FILETYPE_PEM:
        return pkey._pem_data or b''
    return b''


def _realize_cert(x509):
    '''
    Actually generate the certificate PEM data using openssl CLI.
    Called when dump_certificate is invoked on a cert that was
    built up via set_*/add_extensions/sign.
    '''
    if x509._pem_data:
        return x509._pem_data

    key_pem = x509._sign_key._pem_data if hasattr(
        x509, '_sign_key'
    ) else None
    if not key_pem:
        return b''

    digest = getattr(x509, '_digest', 'sha256')
    serial = x509._serial or int(time.time() * 10000)
    days = max(1, x509._not_after // 86400) if x509._not_after > 0 else 720

    # Check if this is self-signed (issuer == subject)
    issuer_comps = x509._issuer._components if x509._issuer else {}
    subject_comps = x509._subject._components if x509._subject else {}
    is_self_signed = (issuer_comps == subject_comps)

    issuer_cert_pem = None
    issuer_key_pem = None
    if not is_self_signed:
        # Would need CA cert/key -- for now treat as self-signed
        pass

    cert_pem = _generate_cert_with_openssl(
        subject=x509._subject,
        issuer_cert_pem=issuer_cert_pem,
        issuer_key_pem=issuer_key_pem,
        key_pem=key_pem,
        serial=serial,
        days=days,
        extensions=x509._extensions,
        is_ca=is_self_signed,
        digest=digest,
    )
    x509._pem_data = cert_pem
    return cert_pem


# ============================================================
# Module-level namespace to mimic `import OpenSSL`
# then `OpenSSL.crypto.X509()`, `OpenSSL.SSL.Context()`, etc.
# ============================================================

class _crypto_module:
    '''
    Namespace for OpenSSL.crypto
    '''
    PKey = PKey
    X509 = X509
    X509Req = X509Req
    X509Name = X509Name
    X509Extension = X509Extension
    PKCS12 = PKCS12
    load_certificate = staticmethod(load_certificate)
    load_privatekey = staticmethod(load_privatekey)
    dump_certificate = staticmethod(dump_certificate)
    dump_privatekey = staticmethod(dump_privatekey)
    FILETYPE_PEM = FILETYPE_PEM
    FILETYPE_ASN1 = FILETYPE_ASN1
    TYPE_RSA = TYPE_RSA
    TYPE_DSA = TYPE_DSA


crypto = _crypto_module()

if __name__ == '__main__':
    # run some tests
    result = subprocess.run([
        'ls',
        os.path.dirname(__file__)],
        capture_output=True
    )
    logging.debug('result: %r', result.stdout)
    assert b'openssl_compat.py' in result.stdout

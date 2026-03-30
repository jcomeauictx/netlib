from __future__ import unicode_literals
import string, binascii, logging
try:
    import odict, utils
except ImportError:
    from . import odict, utils  # python3 syntax
try:
    import urlparse
except ImportError:
    from urllib import parse as urlparse  # python3
logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)

# python3 compatibility
try:
    string.split('')
except AttributeError:
    string.split = str.split
    string.rsplit = str.rsplit

class HttpError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg

    def __str__(self):
        return "HttpError(%s, %s)"%(self.code, self.msg)


class HttpErrorConnClosed(HttpError): pass


def _is_valid_port(port):
    if not 0 <= port <= 65535:
        return False
    return True


def _is_valid_host(host):
    '''
    checks validity of host (passed as string)
    '''
    try:
        host.encode().decode('idna')
    except ValueError:
        return False
    if '\0' in host:
        return None
    return True


def parse_url(url):
    '''
    returns a (scheme, host, port, path) tuple, or None on error.

    checks that:
        port is an integer 0-65535
        host is a valid IDNA-encoded hostname with no null-bytes
        path is valid ASCII

    input is a string, output is strings and integers
    '''
    try:
        scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
    except ValueError:
        return None
    if not scheme:
        return None
    if ':' in netloc:
        host, port = string.rsplit(netloc, ':', maxsplit=1)
        try:
            port = int(port)
        except ValueError:
            return None
    else:
        host = netloc
        if scheme == 'https':
            port = 443
        else:
            port = 80
    path = urlparse.urlunparse(('', '', path, params, query, fragment))
    if not path.startswith('/'):
        path = '/' + path
    if not _is_valid_host(host):
        return None
    if not utils.isascii(path):
        return None
    if not _is_valid_port(port):
        return None
    return scheme, host, port, path

def read_headers(fp):
    '''
    read a set of headers from a file pointer, stopping on a blank line.
    return a ODictCaseless object, or None if headers are invalid.
    '''
    ret = []
    name = ''
    while 1:
        line = fp.readline()
        if line in ('', '\r\n', '\n'):
            break
        if line[0] in ' \t':
            if not ret:
                return None
            # continued header
            ret[-1][1] = ret[-1][1] + '\r\n ' + line.strip()
        else:
            i = line.find(':')
            # We're being liberal in what we accept, here.
            if i > 0:
                name = line[:i]
                value = line[i+1:].strip()
                ret.append([name, value])
            else:
                return None
    return odict.ODictCaseless(ret)


def read_chunked(code, fp, limit):
    '''
    Read a chunked HTTP body.

    May raise HttpError.
    '''
    content = ''
    total = 0
    while 1:
        line = fp.readline(128)
        logging.debug('http.read_chunked: pre-content line=%r', line)
        if line == '':
            raise HttpErrorConnClosed(code, "Connection closed prematurely")
        if line not in ('\r\n', '\n'):
            try:
                length = int(line, 16)
                logging.debug('http.read_chunked: chunk length=%d', length)
            except ValueError:
                # FIXME: Not strictly correct - this could be from the server, in which
                # case we should send a 502.
                raise HttpError(
                    code,
                    'Invalid chunked encoding length: %r' % line
                )
            if not length:
                logging.debug('http.read_chunked: 0-chunk, end of content')
                break
            total += length
            if limit is not None and total > limit:
                msg = (
                    'HTTP Body too large. Limit is %s, '
                    'chunked content length was at least %s'
                ) % (limit, total)
                raise HttpError(code, msg)
            content += fp.read(length)
            logging.debug('http.read_chunked: content=%r', content)
            line = fp.readline(5)
            logging.debug('http.read_chunked: post-content endline=%r', line)
            if line != '\r\n':
                raise HttpError(code, 'Malformed chunked body')
    while 1:
        line = fp.readline()
        logging.debug('http.read_chunked: post-content line=%r', line)
        if line == '':
            logging.debug('http.read_chunked: found "" where eol expected')
            raise HttpErrorConnClosed(code, 'Connection closed prematurely')
        if line in ('\r\n', '\n'):
            logging.debug('http.read_chunked: closing normally')
            break
    return content


def get_header_tokens(headers, key):
    """
        Retrieve all tokens for a header key. A number of different headers
        follow a pattern where each header line can containe comma-separated
        tokens, and headers can be set multiple times.
    """
    toks = []
    for i in headers[key]:
        for j in i.split(b','):
            toks.append(j.strip())
    return toks


def has_chunked_encoding(headers):
    return "chunked" in [i.lower() for i in get_header_tokens(headers, "transfer-encoding")]


def read_http_body(code, rfile, headers, all, limit):
    """
        Read an HTTP body:

            code: The HTTP error code to be used when raising HttpError
            rfile: A file descriptor to read from
            headers: An ODictCaseless object
            all: Should we read all data?
            limit: Size limit.
    """
    if has_chunked_encoding(headers):
        content = read_chunked(code, rfile, limit)
    elif "content-length" in headers:
        try:
            l = int(headers["content-length"][0])
        except ValueError:
            # FIXME: Not strictly correct - this could be from the server, in which
            # case we should send a 502.
            raise HttpError(code, "Invalid content-length header: %s"%headers["content-length"])
        if limit is not None and l > limit:
            raise HttpError(code, "HTTP Body too large. Limit is %s, content-length was %s"%(limit, l))
        content = rfile.read(l)
    elif all:
        content = rfile.read(limit if limit else -1)
    else:
        content = ""
    return content


def parse_http_protocol(s):
    '''
    parse an HTTP protocol declaration.

    expects a string and returns (major, minor) tuple, or None.
    '''
    logging.debug('parse_http_protocol: line=%r', s)
    if not s.startswith('HTTP/'):
        return None
    _, version = s.split('/', 1)
    if '.' not in version:
        return None
    major, minor = version.split('.', 1)
    try:
        major = int(major)
        minor = int(minor)
    except ValueError:
        return None
    return major, minor


def parse_http_basic_auth(s):
    words = s.split()
    if len(words) != 2:
        return None
    scheme = words[0]
    try:
        user = binascii.a2b_base64(words[1])
    except binascii.Error:
        return None
    parts = user.split(':')
    if len(parts) != 2:
        return None
    return scheme, parts[0], parts[1]


def assemble_http_basic_auth(scheme, username, password):
    v = binascii.b2a_base64(username + ':' + password)
    return scheme + b' ' + v


def parse_init(line):
    '''
    parse request line and return as strings
    '''
    logging.debug('parse_init %r', line)
    try:
        method, url, protocol = line.rstrip().decode().split()
    except ValueError:
        return None
    httpversion = parse_http_protocol(protocol)
    if not httpversion:
        return None
    if not utils.isascii(method):
        return None
    logging.debug('parse_init returning %s', {
        'method': method, 'url': url, 'httpversion': httpversion
    })
    return method, url, httpversion


def parse_init_connect(line):
    logging.debug('parse_init_connect: %r', line)
    v = parse_init(line)
    if not v:
        return None
    method, url, httpversion = v

    if method.upper() != 'CONNECT':
        return None
    try:
        host, port = url.split(':')
    except ValueError:
        return None
    try:
        port = int(port)
    except ValueError:
        return None
    if not _is_valid_port(port):
        return None
    if not _is_valid_host(host):
        return None
    return host, port, httpversion


def parse_init_proxy(line):
    logging.debug('parse_init_proxy: %r', line)
    v = parse_init(line)
    if not v:
        return None
    logging.debug('parse_init_proxy: first parse: %r', v)
    method, url, httpversion = v
    parts = parse_url(url)
    if not parts:
        return None
    logging.debug('parse_init_proxy: second parse: %r', parts)
    scheme, host, port, path = parts
    return method, scheme, host, port, path, httpversion


def parse_init_http(line):
    '''
    returns (method, url, httpversion) as strings
    '''
    logging.debug('parse_init_http: %r', line)
    v = parse_init(line)
    if not v:
        return None
    method, url, httpversion = v
    if not utils.isascii(url):
        return None
    if not (url.startswith('/') or url == '*'):
        return None
    return method, url, httpversion


def request_connection_close(httpversion, headers):
    '''
    checks the request to see if the client connection should be closed.
    '''
    if 'connection' in headers:
        toks = get_header_tokens(headers, 'connection')
        if 'close' in toks:
            return True
        elif 'keep-alive' in toks:
            return False
    # HTTP 1.1 connections are assumed to be persistent
    if httpversion == (1, 1):
        return False
    return True


def response_connection_close(httpversion, headers):
    '''
    checks the response to see if the client connection should be closed.
    '''
    if request_connection_close(httpversion, headers):
        return True
    elif (not has_chunked_encoding(headers)) and 'content-length' in headers:
        return False
    return True


def read_http_body_request(rfile, wfile, headers, httpversion, limit):
    '''
    read the HTTP body from a client request.
    '''
    if 'expect' in headers:
        # FIXME: Should be forwarded upstream
        if '100-continue' in headers['expect'] and httpversion >= (1, 1):
            wfile.write(b'HTTP/1.1 100 Continue\r\n')
            wfile.write(b'\r\n')
            del headers['expect']
    return read_http_body(400, rfile, headers, False, limit)


def read_http_body_response(rfile, headers, limit):
    '''
    read the HTTP body from a server response.
    '''
    all = 'close' in get_header_tokens(headers, 'connection')
    return read_http_body(500, rfile, headers, all, limit)


def parse_response_line(line):
    parts = line.strip().split(' ', 2)
    if len(parts) == 2: # handle missing message gracefully
        parts.append(b'')
    if len(parts) != 3:
        return None
    proto, code, msg = parts
    try:
        code = int(code)
    except ValueError:
        return None
    return (proto, code, msg)


def read_response(rfile, method, body_size_limit):
    '''
    return an (httpversion, code, msg, headers, content) tuple.
    '''
    line = rfile.readline().decode()
    if line in ('\r\n', '\n'): # Possible leftover from previous message
        line = rfile.readline()
    if not line:
        raise HttpErrorConnClosed(502, 'Server disconnect.')
    parts = parse_response_line(line)
    if not parts:
        raise HttpError(502, 'Invalid server response: %r' % line)
    proto, code, msg = parts
    httpversion = parse_http_protocol(proto)
    if httpversion is None:
        raise HttpError(502, 'Invalid HTTP version in line: %s' % proto)
    headers = read_headers(rfile)
    if headers is None:
        raise HttpError(502, 'Invalid headers.')
    if code >= 100 and code <= 199:
        return read_response(rfile, method, body_size_limit)
    if method == 'HEAD' or code == 204 or code == 304:
        content = ''
    else:
        content = read_http_body_response(rfile, headers, body_size_limit)
    return httpversion, code, msg, headers, content

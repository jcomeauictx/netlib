from __future__ import unicode_literals
# python2/3 compatibility

def isascii(s):
    '''
    ensures string is valid ASCII
    '''
    try:
        s.encode().decode('ascii')
    except ValueError:
        return False
    return True


def clean_bin(s, fixspacing=False):
    '''
    cleans binary data to make it safe to display. if fixspacing is True,
    tabs, newlines and so forth will be maintained, if not, they will be
    replaced with a placeholder.

    takes bytes or a string, returns same type as it got
    '''
    if isinstance(s, bytes):
        replacement = b'.'
        joiner = b''
        pass_ok = b'\t\n'
    else:
        replacement = '.'
        joiner = ''
        pass_ok = '\t\n'
    parts = []
    for i in range(len(s)):
        c = s[i:i + 1]
        o = ord(c)
        if (o > 31 and o < 127):
            parts.append(c)
        elif c in pass_ok and not fixspacing:
            parts.append(c)
        else:
            parts.append(replacement)
    return joiner.join(parts)


def hexdump(s):
    '''
    returns a set of tuples: (offset, hex, str)

    called with a bytes object

    returns, e.g. [(
     '0000000000',  # offset into bytes
     'ff ff ff ff ee ee ee ee dd dd dd dd 55 55 55 55',  # hex, len=47
     '............UUUU'  # "clean" binary output
    )]
    '''
    if not isinstance(s, bytes):
        raise ValueError('hexdump must be called with bytes object')
    parts = []
    chunksize = 16
    hexsize = (chunksize * 3) - 1  # spaces between each hexbyte
    for index in range(0, len(s), chunksize):
        offset = '%.10x' % index
        part = s[index:index + chunksize]
        hexstring = ' '.join('%.2x' % ord(part[i:i + 1])
                             for i in range(len(part)))
        parts.append(
            (offset, hexstring.rjust(hexsize), clean_bin(part, True).decode())
        )
    return parts

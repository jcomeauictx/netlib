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


def cleanBin(s, fixspacing=False):
    '''
    cleans binary data to make it safe to display. if fixspacing is True,
    tabs, newlines and so forth will be maintained, if not, they will be
    replaced with a placeholder.
    '''
    parts = []
    for i in range(len(s)):
        c = s[i:i + 1]
        o = ord(c)
        if (o > 31 and o < 127):
            parts.append(c)
        elif c in '\n\t' and not fixspacing:
            parts.append(c)
        else:
            parts.append(b'.')
    return b''.join(parts)


def hexdump(s):
    '''
    returns a set of tuples: (offset, hex, str)
    '''
    parts = []
    for i in range(0, len(s), 16):
        o = '%.10x' % i
        part = s[i:i + 16]
        x = ' '.join('%.2x' % ord(i) for i in part)
        if len(part) < 16:
            x += ' '
            x += ' '.join('  ' for i in range(16 - len(part)))
        parts.append(
            (o, x, cleanBin(part, True))
        )
    return parts

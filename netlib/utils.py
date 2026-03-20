from __future__ import unicode_literals
def isascii(s):
    '''
    ensures string is valid ASCII
    '''
    try:
        s.encode().decode(u'ascii')
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
    for i in s:
        o = ord(i)
        if (o > 31 and o < 127):
            parts.append(i)
        elif i in u'\n\t' and not fixspacing:
            parts.append(i)
        else:
            parts.append(u'.')
    return u''.join(parts)


def hexdump(s):
    '''
    returns a set of tuples: (offset, hex, str)
    '''
    parts = []
    for i in range(0, len(s), 16):
        o = u'%.10x' % i
        part = s[i:i + 16]
        x = u' '.join('%.2x' % ord(i) for i in part)
        if len(part) < 16:
            x += u' '
            x += u' '.join('  ' for i in range(16 - len(part)))
        parts.append(
            (o, x, cleanBin(part, True))
        )
    return parts

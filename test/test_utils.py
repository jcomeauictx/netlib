from __future__ import unicode_literals
from netlib import utils


def test_hexdump():
    assert utils.hexdump(b'one\0' * 10)


def test_cleanBin():
    assert utils.cleanBin(b'one') == 'one'
    assert utils.cleanBin(b'\00ne') == '.ne'
    assert utils.cleanBin(b'\nne') == '\nne'
    assert utils.cleanBin(b'\nne', True) == '.ne'


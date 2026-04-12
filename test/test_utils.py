from netlib import utils


def test_hexdump():
    assert utils.hexdump(b'one\0' * 10)


def test_clean_bin():
    assert utils.clean_bin(b'one') == b'one'
    assert utils.clean_bin(b'\00ne') == b'.ne'
    assert utils.clean_bin(b'\nne') == b'\nne'
    assert utils.clean_bin(b'\nne', True) == b'.ne'
    assert utils.clean_bin('one') == 'one'
    assert utils.clean_bin('\00ne') == '.ne'
    assert utils.clean_bin('\nne') == '\nne'
    assert utils.clean_bin('\nne', True) == '.ne'


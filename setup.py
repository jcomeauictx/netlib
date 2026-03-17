# this version is for alpine 3.14.3/iSH (shell app for iPhone with emulator)
# it comes with python3.9.16
# python2.7.18 is available for installation
from __future__ import unicode_literals
from distutils.core import setup, setup_keywords
import fnmatch, os, re, logging
from netlib import version
# python3 compatibility shims
try:
    file(os.devnull)
except NameError:
    file = open
logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)

def _fnmatch(name, patternList):
    for i in patternList:
        if fnmatch.fnmatch(name, i):
            return True
    return False


def _splitAll(path):
    parts = []
    h = path
    while 1:
        if not h:
            break
        h, t = os.path.split(h)
        parts.append(t)
    parts.reverse()
    return parts


def findPackages(path, dataExclude=[]):
    """
        Recursively find all packages and data directories rooted at path. Note
        that only data _directories_ and their contents are returned -
        non-Python files at module scope are not, and should be manually
        included.

        dataExclude is a list of fnmatch-compatible expressions for files and
        directories that should not be included in pakcage_data.

        Returns a (packages, package_data) tuple, ready to be passed to the
        corresponding distutils.core.setup arguments.
    """
    packages = []
    datadirs = []
    for root, dirs, files in os.walk(path, topdown=True):
        if "__init__.py" in files:
            p = _splitAll(root)
            packages.append(".".join(p))
        else:
            dirs[:] = []
            if packages:
                datadirs.append(root)

    # Now we recurse into the data directories
    package_data = {}
    for i in datadirs:
        if not _fnmatch(i, dataExclude):
            parts = _splitAll(i)
            module = ".".join(parts[:-1])
            acc = package_data.get(module, [])
            for root, dirs, files in os.walk(i, topdown=True):
                sub = os.path.join(*_splitAll(root)[1:])
                if not _fnmatch(sub, dataExclude):
                    for fname in files:
                        path = os.path.join(sub, fname)
                        if not _fnmatch(path, dataExclude):
                            acc.append(path)
                else:
                    dirs[:] = []
            package_data[module] = acc
    return packages, package_data


long_description = file("README").read()
packages, package_data = findPackages("netlib")
setup_args = dict(
        name = "netlib",
        version = version.VERSION,
        description = "A collection of network utilities used by pathod and mitmproxy.",
        long_description = long_description,
        author = "Aldo Cortesi",
        author_email = "aldo@corte.si",
        url = "http://cortesi.github.com/netlib",
        packages = packages,
        package_data = package_data,
        classifiers = [
            "License :: OSI Approved :: MIT License",
            "Development Status :: 3 - Alpha",
            "Operating System :: POSIX",
            "Programming Language :: Python",
            "Topic :: Internet",
            "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
            "Topic :: Software Development :: Testing",
            "Topic :: Software Development :: Testing :: Traffic Generation",
            "Topic :: Internet :: WWW/HTTP",
        ],
        install_requires=["pyasn1>0.1.2", "pyopenssl>=0.12"],
)
# shim for older versions of distutils like iSH's
if 'install_requires' not in setup_keywords:
    setup_args['requires'] = setup_args.pop('install_requires')
    logging.debug('before: requires: %s', setup_args['requires'])
    for index in range(len(setup_args['requires'])):
        requirement = setup_args['requires'][index]
        parts = re.split('([<>!=])', requirement, maxsplit=1)
        logging.debug('parts: %s', parts)
        if len(parts) > 1:
            name = parts[0] + ' (' + ''.join(parts[1:]) + ')'
            setup_args['requires'][index] = name
    logging.debug('after: requires: %s', setup_args['requires'])
setup(**setup_args)
# vim: tabstop=8 shiftwidth=4 softtabstop=4 expandtabs

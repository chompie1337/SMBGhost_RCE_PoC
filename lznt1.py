import struct
import copy


def _decompress_chunk(chunk):
    out = bytearray()
    while chunk:
        flags = chunk[0]
        chunk = chunk[1:]
        for i in range(8):
            if not (flags >> i & 1):
                out += chunk[0].to_bytes(length=1, byteorder='little')
                chunk = chunk[1:]
            else:
                flag = struct.unpack('<H', chunk[:2])[0]
                pos = len(out) - 1
                l_mask = 0xFFF
                o_shift = 12
                while pos >= 0x10:
                    l_mask >>= 1
                    o_shift -= 1
                    pos >>= 1

                length = (flag & l_mask) + 3
                offset = (flag >> o_shift) + 1

                if length >= offset:
                    tmp = out[-offset:] * int(0xFFF / len(out[-offset:]) + 1)
                    out += tmp[:length]
                else:
                    out += out[-offset:-offset+length]
                chunk = chunk[2:]
            if len(chunk) == 0:
                break
    return out


def decompress(buf, length_check=True):
    out = bytearray()
    while buf:
        header = struct.unpack('<H', bytes(buf[:2]))[0]
        length = (header & 0xFFF) + 1
        if length_check and length > len(buf[2:]):
            raise ValueError('invalid chunk length')
        else:
            chunk = buf[2:2+length]
            if header & 0x8000:
                out += _decompress_chunk(chunk)
            else:
                out += chunk
        buf = buf[2+length:]
    return out


def _find(src, target, max_len):
    result_offset = 0
    result_length = 0
    for i in range(1, max_len):
        offset = src.rfind(target[:i])
        if offset == -1:
            break
        tmp_offset = len(src) - offset
        tmp_length = i
        if tmp_offset == tmp_length:
            tmp = src[offset:] * int(0xFFF / len(src[offset:]) + 1)
            for j in range(i, max_len+1):
                offset = tmp.rfind(target[:j])
                if offset == -1:
                    break
                tmp_length = j
        if tmp_length > result_length:
            result_offset = tmp_offset
            result_length = tmp_length

    if result_length < 3:
        return 0, 0
    return result_offset, result_length


def _compress_chunk(chunk):
    blob = copy.copy(chunk)
    out = b""
    pow2 = 0x10
    l_mask3 = 0x1002
    o_shift = 12
    while len(blob) > 0:
        bits = 0
        tmp = b""
        for i in range(8):
            bits >>= 1
            while pow2 < (len(chunk) - len(blob)):
                pow2 <<= 1
                l_mask3 = (l_mask3 >> 1) + 1
                o_shift -= 1
            if len(blob) < l_mask3:
                max_len = len(blob)
            else:
                max_len = l_mask3

            offset, length = _find(chunk[:len(chunk) -
                                   len(blob)], blob, max_len)

            # try to find more compressed pattern
            offset2, length2 = _find(chunk[:len(chunk) -
                                     len(blob)+1], blob[1:], max_len)
            if length < length2:
                length = 0

            if length > 0:
                symbol = ((offset-1) << o_shift) | (length - 3)
                tmp += struct.pack('<H', symbol)
                # set the highest bit
                bits |= 0x80
                blob = blob[length:]
            else:
                tmp += bytes([blob[0]])
                blob = blob[1:]
            if len(blob) == 0:
                break

        out += struct.pack('B', bits >> (7 - i))
        out += tmp

    return out


def compress(buf, chunk_size=0x1000):
    out = b""
    while buf:
        chunk = buf[:chunk_size]
        compressed = _compress_chunk(chunk)
        # chunk is compressed
        if len(compressed) < len(chunk):
            flags = 0xB000
            header = struct.pack('<H', flags | (len(compressed)-1))
            out += header + compressed
        else:
            flags = 0x3000
            header = struct.pack('<H', flags | (len(chunk)-1))
            out += header + chunk
        buf = buf[chunk_size:]

    return out


def compress_evil(buf, chunk_size=0x1000):
    out = b""
    while buf:
        chunk = buf[:chunk_size]
        compressed = _compress_chunk(chunk)

        # always use the compressed chunk, even if it's larger >:)
        flags = 0xB000
        header = struct.pack('<H', flags | (len(compressed)-1))
        out += header + compressed
        buf = buf[chunk_size:]

    # corrupt the "next" chunk
    out += struct.pack('<H', 0x1337)
    return out

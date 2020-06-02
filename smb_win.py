#!/usr/bin/env python

import struct


class Smb2Header:
    def __init__(self, cmd, msg_id):
        self.protocol_id = b"\xfeSMB"
        self.header_length = struct.pack("<H", 0x40)
        self.credit_charge = struct.pack("<H", 0x0)
        self.channel_sequence = struct.pack("<H", 0x0)
        self.reserved = struct.pack("<H", 0x0)
        self.command = struct.pack("<H", cmd)
        self.credits_requested = struct.pack("<H", 0x0)
        self.flags = struct.pack("<L", 0x0)
        self.chain_offset = struct.pack("<L", 0x0)
        self.message_id = struct.pack("<Q", msg_id)
        self.process_id = struct.pack("<L", 0x0)
        self.tree_id = struct.pack("<L", 0x0)
        self.session_id = struct.pack("<Q", 0x0)
        self.signature = b"\x00"*0x10

    def raw_bytes(self):
        header_bytes = self.protocol_id + self.header_length + \
                       self.credit_charge + self.channel_sequence + \
                       self.reserved + self.command + \
                       self.credits_requested + self.flags + \
                       self.chain_offset + self.message_id + \
                       self.process_id + self.tree_id + self.session_id + \
                       self.signature
        return header_bytes


class Smb2PreauthContext:
    def __init__(self):
        self.type = struct.pack("<H", 0x1)
        self.data_length = struct.pack("<H", 0x26)
        self.reserved = struct.pack("<L", 0x0)
        self.hash_algorithm_count = struct.pack("<H", 0x1)
        self.salt_length = struct.pack("<H", 0x20)
        self.hash_algorithm = struct.pack("<H", 0x1)
        self.salt = b"\x00"*0x20
        self.padding = struct.pack("<H", 0x0)

    def raw_bytes(self):
        preauth_cxt_bytes = self.type + self.data_length + self.reserved + \
                            self.hash_algorithm_count + self.salt_length + \
                            self.hash_algorithm + self.salt + self.padding
        return preauth_cxt_bytes


class Smb2CompressionContext:
    def __init__(self):
        self.type = struct.pack("<H", 0x3)
        self.data_length = struct.pack("<H", 0xA)
        self.reserved = struct.pack("<L", 0x0)
        self.compression_algorithm_count = struct.pack("<H", 0x1)
        self.flags = b"\x00\x00\x01\x00\x00\x00"
        self.compression_algorithm_id = struct.pack("<H", 0x1)

    def raw_bytes(self):
        compress_cxt_bytes = self.type + self.data_length + \
                             self.reserved + \
                             self.compression_algorithm_count + \
                             self.flags + self.compression_algorithm_id
        return compress_cxt_bytes


class Smb2NegotiateRequestPacket:
    def __init__(self):
        self.header = Smb2Header(0x0, 0x0)
        self.structure_size = struct.pack("<H", 0x24)
        self.dialect_count = struct.pack("<H", 0x5)
        self.security_mode = struct.pack("<H", 0x0)
        self.reserved = struct.pack("<H", 0x0)
        self.capabilities = struct.pack("<L", 0x44)
        self.client_guid = b"\x13\x37\xC0\xDE"*0x4
        self.negotiate_context_offset = struct.pack("<L", 0x70)
        self.negotiate_context_count = struct.pack("<H", 0x2)
        self.dialects = b"\x02\x02" + b"\x10\x02" + b"\x00\x03" + \
                        b"\x02\x03" + b"\x11\x03"
        self.padding = struct.pack("<H", 0x0)
        self.preauth_context = Smb2PreauthContext()
        self.compression_context = Smb2CompressionContext()

    def raw_bytes(self):
        negotiate_bytes = self.header.raw_bytes() + self.structure_size + \
                          self.dialect_count + self.security_mode + \
                          self.reserved + self.capabilities + \
                          self.client_guid + self.negotiate_context_offset + \
                          self.negotiate_context_count + self.reserved + \
                          self.dialects + self.padding + \
                          self.preauth_context.raw_bytes() + \
                          self.compression_context.raw_bytes()
        return negotiate_bytes


class NetBiosSessionPacket:
    def __init__(self, data):
        self.session_message = b"\x00"
        self.length = struct.pack(">L", len(data))[1:]
        self.data = data

    def raw_bytes(self):
        netbios_session_bytes = self.session_message + self.length + self.data
        return netbios_session_bytes


class Smb2CompressedTransform:
    def __init__(self, compressed_data, decompressed_size, data):
        self.protocol_id = b"\xfcSMB"
        self.original_decompressed_size = struct.pack('<L', decompressed_size)
        self.compression_algorithm = struct.pack('<H', 0x1)
        self.flags = struct.pack('<H', 0x0)
        self.offset = struct.pack('<L', len(data))
        self.data = data + compressed_data

    def raw_bytes(self):
        compress_transform_bytes = self.protocol_id + \
                                   self.original_decompressed_size + \
                                   self.compression_algorithm + self.flags + \
                                   self.offset + self.data
        return compress_transform_bytes


def smb_negotiate(sock):
    neg_bytes = Smb2NegotiateRequestPacket().raw_bytes()
    netbios_packet = NetBiosSessionPacket(neg_bytes).raw_bytes()
    sock.send(netbios_packet)


def smb_compress(sock, compressed_data, decompressed_size, data):
    comp = Smb2CompressedTransform(compressed_data, decompressed_size, data)
    comp_bytes = comp.raw_bytes()
    compressed_packet = NetBiosSessionPacket(comp_bytes).raw_bytes()
    sock.send(compressed_packet)

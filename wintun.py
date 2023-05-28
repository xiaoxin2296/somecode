import time, struct
from threading import Thread
from ctypes import *
import socket

class GUID_TYPE(Structure):
    _fields_ = [('Data1', c_uint32),
                ('Data2', c_uint16),
                ('Data3', c_uint16),
                ('Data4', c_uint8 * 8)]

class SOCKADDR_IN(Structure):
    _fields_ = [('sin_family', c_uint16),
                ('sin_port', c_uint16),
                ('sin_addr', c_uint8 * 4),
                ('sin_zero', c_uint8 * 8)]

class SOCKADDR_IN6(Structure):
    _fields_ = [('sin6_family', c_uint16),
                ('sin6_port', c_uint16),
                ('sin6_flowinfo', c_uint32),
                ('sin6_addr', c_uint8 * 16),
                ('sin6_scope_id', c_uint32)]

class SOCKADDR_INET(Union):
    _fields_ = [('Ipv4', SOCKADDR_IN),
                ('Ipv6', SOCKADDR_IN6)]

class MIB_UNICASTIPADDRESS_ROW(Structure):
    _fields_ = [('Address', SOCKADDR_INET),
                ('InterfaceLuid', c_uint64),
                ('InterfaceIndex', c_uint32),
                ('PrefixOrigin', c_uint32),
                ('SuffixOrigin', c_uint32),
                ('ValidLifetime', c_uint32),
                ('PreferredLifetime', c_uint32),
                ('OnLinkPrefixLength', c_uint8),
                ('SkipAsSource', c_bool),
                ('Reserved', c_uint16),
                ('DadState', c_uint32),
                ('ScopeId', c_uint32),
                ('CreationTimeStamp', c_uint64),
                ]

def ConsoleLogger(level, ts, line):
    print(f'[{level}] [{ts}] {line}')

def threadit(f, *args, **kwargs):
    t = Thread(target=f, args=args, kwargs=kwargs)
    t.start()
    return t

def make_icmp4(packet):
    packet[0] = 0x45
    packet[3] = 28
    packet[8] = 255
    packet[9] = 1
    packet[10] = 0x99
    packet[11] = 0xC6
    packet[12] = 10
    packet[13] = 6
    packet[14] = 7
    packet[15] = 8
    packet[16] = 10
    packet[17] = 6
    packet[18] = 7
    packet[19] = 7
    packet[20] = 8
    packet[22] = 0xF7
    packet[23] = 0xFF

def print_packet(packet, size):
    packbuf = cast(packet, POINTER(c_uint8))
    buf = string_at(packbuf, size)

    ipver = buf[0] >> 4
    dict_prot = {17: 'UDP', 58: 'ICMPv6', 6: 'TCP', 2: 'IGMP', 1: 'ICMP'}
    if ipver == 4:
        packtype = 'IPv4'
        length, prot = struct.unpack('>2xH5xB', buf[:10])
        srcip = socket.inet_ntoa(buf[12:16])
        dstip = socket.inet_ntoa(buf[16:20])
    elif ipver == 6:
        packtype = 'IPv6'
        length, = struct.unpack('>H', buf[4:6])
        srcip = socket.inet_ntop(socket.AF_INET6, buf[8:24])
        dstip = socket.inet_ntop(socket.AF_INET6, buf[24:40])
        prot = buf[6]
        if prot == 0:
            prot = buf[40]
    else:
        print(f'Unknown ip type, raw data {buf}')
        return

    if prot in dict_prot:
        print(f'Received {packtype} {dict_prot[prot]} packet from {srcip} to {dstip}, packet length {length}')
    else:
        print(f'Received {packtype} unknown protocol {prot}, raw data {buf}')

def recv_tun_pack_loop(sess, recv_pack, release_pack):
    print(f'Enter Recv loop, sess {sess}')

    i = 0
    while i < 300:
        packsize = c_uint32(0)
        packet = recv_pack(sess, byref(packsize))
        if packet:
            print_packet(packet, packsize.value)
            release_pack(sess, packet)
            i += 1

def send_tun_pack(sess, alloc_pack, send_pack):
    packet = alloc_pack(sess, 28)
    packet_buf = cast(packet, POINTER(c_uint8))
    make_icmp4(packet_buf)
    send_pack(sess, packet)

def wintun():
    tdll = WinDLL('d:/msvc/bin/wintun.dll')
    WintunCreateAdapter = tdll.WintunCreateAdapter
    # WintunSetLogger = tdll.WintunSetLogger
    # log_cb_type = WINFUNCTYPE(None, c_uint32, c_uint64, c_wchar_p)
    # log_cb = log_cb_type(ConsoleLogger)
    # WintunSetLogger(log_cb)

    guid = GUID_TYPE()
    guid.Data1 = 0xdeadbabe
    guid.Data2 = 0xcafe
    guid.Data3 = 0xbeef
    array_type = c_uint8 * 8
    guid.Data4 = array_type(0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef)
    adapt = WintunCreateAdapter('Demo', 'Example', byref(guid))

    InitializeUnicastIpAddressEntry = windll.Iphlpapi.InitializeUnicastIpAddressEntry
    WintunGetAdapterLUID = tdll.WintunGetAdapterLUID
    CreateUnicastIpAddressEntry = windll.Iphlpapi.CreateUnicastIpAddressEntry

    mib = MIB_UNICASTIPADDRESS_ROW()
    InitializeUnicastIpAddressEntry(byref(mib))
    luid = c_uint64()
    WintunGetAdapterLUID(adapt, byref(luid))
    mib.InterfaceLuid = luid
    mib.Address.Ipv4.sin_family = socket.AF_INET
    mib.Address.Ipv4.sin_addr = (c_uint8 * 4).from_buffer(bytearray(socket.inet_aton('10.6.7.7')))  # socket.htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0))
    mib.OnLinkPrefixLength = 24
    mib.DadState = 4
    lasterror = CreateUnicastIpAddressEntry(byref(mib))
    print(f'laseerror: {lasterror}')

    InitializeUnicastIpAddressEntry(byref(mib))
    luid = c_uint64()
    WintunGetAdapterLUID(adapt, byref(luid))
    mib.InterfaceLuid = luid
    mib.Address.Ipv6.sin6_family = socket.AF_INET6
    # ipv6addr_type = c_uint8 * 16
    mib.Address.Ipv6.sin6_addr = (c_uint8 * 16).from_buffer(bytearray(socket.inet_pton(socket.AF_INET6, '3001::3:8'))) # ipv6addr_type(0x30, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 8)
    mib.OnLinkPrefixLength = 64
    mib.DadState = 4
    lasterror = CreateUnicastIpAddressEntry(byref(mib))
    print(f'laseerror: {lasterror}')

    WintunStartSession = tdll.WintunStartSession
    sess = WintunStartSession(adapt, 0x400000)
    print(f'sess: {sess}')

    WintunReceivePacket = tdll.WintunReceivePacket
    WintunReleaseReceivePacket = tdll.WintunReleaseReceivePacket

    threadit(recv_tun_pack_loop, sess, WintunReceivePacket, WintunReleaseReceivePacket)

    WintunAllocateSendPacket = tdll.WintunAllocateSendPacket
    WintunSendPacket = tdll.WintunSendPacket

    i = 0
    while i < 300:
        # send_tun_pack(sess, WintunAllocateSendPacket, WintunSendPacket)
        time.sleep(1)
        i += 1

def open_adapt():
    tdll = WinDLL('d:/msvc/bin/wintun.dll')
    WintunOpenAdapter = tdll.WintunOpenAdapter

    adapt = WintunOpenAdapter('Demo')

    WintunStartSession = tdll.WintunStartSession
    sess = WintunStartSession(adapt, 0x400000)
    print(f'sess: {sess}')

    WintunReceivePacket = tdll.WintunReceivePacket
    WintunReleaseReceivePacket = tdll.WintunReleaseReceivePacket

    threadit(recv_tun_pack_loop, sess, WintunReceivePacket, WintunReleaseReceivePacket)

    WintunAllocateSendPacket = tdll.WintunAllocateSendPacket
    WintunSendPacket = tdll.WintunSendPacket

    i = 0
    while i < 300:
        # send_tun_pack(sess, WintunAllocateSendPacket, WintunSendPacket)
        time.sleep(1)
        i += 1

def memmove():
    packet_type = c_uint8 * 20
    # buf = b'\x08' * 20
    # packet = packet_type.from_buffer(bytearray(buf))
    # t = string_at(packet, 20)
    # print(t)

    pack = packet_type.from_buffer(bytearray(b'\x88' * 20))
    print(string_at(pack, 20))

class SOCKADDR_IN_NEW(Structure):
    _fields_ = [('sin_family', c_uint16),
                ('sin_port', c_uint16),
                ('sin_addr', c_uint8 * 4),
                ('sin_zero', c_uint8 * 8)]

class SOCKADDR_IN6_NEW(Structure):
    _fields_ = [('sin6_family', c_uint16),
                ('sin6_port', c_uint16),
                ('sin6_flowinfo', c_uint32),
                ('sin6_addr', c_uint8 * 16),
                ('sin6_scope_id', c_uint32)]

def ip_unpack():
    # buf = b'E\x00\x006\x1e\xe8\x00\x00\x01\x11\xa8\xc7\n\x06\x07\x07\xe0\x00\x00\xfb\x14\xe9\x14\xe9\x00"+\x90\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02hy\x05local\x00\x00\xff\x00\x01'
    buf = b'`\r^\x0e\x00d\x11\x01\xfe\x80\x00\x00\x00\x00\x00\x00!\x9f(\x00\x97x\xa5\xe3\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfb\x14\xe9\x14\xe9\x00d\xcc\xd4\x00\x00\x84\x00\x00\x00\x00\x03\x00\x00\x00\x00\x02hy\x05local\x00\x00\x1c\x00\x01\x00\x00\x00<\x00\x100\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x08\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00<\x00\x10\xfe\x80\x00\x00\x00\x00\x00\x00!\x9f(\x00\x97x\xa5\xe3\xc0\x0c\x00\x01\x00\x01\x00\x00\x00<\x00\x04\n\x06\x07\x07'
    ipver = buf[0] >> 4

    dict_prot = {17: 'UDP', 58: 'ICMPv6', 6: 'TCP', 2: 'IGMP', 1: 'ICMP'}
    if ipver == 4:
        length, prot = struct.unpack('>2xH5xB', buf[:10])
        srcip = socket.inet_ntoa(buf[12:16])
        dstip = socket.inet_ntoa(buf[16:20])
        packtype = 'IPv4'
    elif ipver == 6:
        length,  = struct.unpack('>H', buf[4:6])
        srcip = socket.inet_ntop(socket.AF_INET6, buf[8:24])
        dstip = socket.inet_ntop(socket.AF_INET6, buf[24:40])
        prot = buf[6]
        if prot == 0:
            prot = buf[40]
        packtype = 'IPv6'
    else:
        pass

    print(f'Received {packtype} {dict_prot[prot]} packet from {srcip} to {dstip}, packet length {length}')


    # srcip = '.'.join(map(str, buf[12:16]))
    # dstip = '.'.join(map(str, buf[16:20]))
    # print(srcip, dstip)

    # srcip = socket.inet_ntoa(buf[12:16])
    # print(srcip)
    # print(socket.inet_aton(srcip))
    # print(socket.inet_ntop(socket.AF_INET, buf[12:16]))

    # addr = SOCKADDR_IN_NEW()
    # addr.sin_family = socket.AF_INET
    # addr.sin_port = socket.htons(21)
    # addr.sin_addr = (c_uint8 * 4).from_buffer(bytearray(buf[12:16]))
    # print(string_at(byref(addr), sizeof(addr)))

if __name__ == '__main__':
    # wintun()
    open_adapt()
    # memmove()
    # ip_unpack()
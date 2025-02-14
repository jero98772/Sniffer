import ctypes
import os
import time
import threading

DNS_NAME_SIZE = 1025  # NI_MAXHOST

class PacketInfo(ctypes.Structure):
    _fields_ = [
        ("packet_number", ctypes.c_int),
        ("dest_mac", ctypes.c_ubyte * 6),
        ("src_mac", ctypes.c_ubyte * 6),
        ("eth_proto", ctypes.c_ushort),
        ("src_ip", ctypes.c_char * 16),
        ("dst_ip", ctypes.c_char * 16),
        ("total_length", ctypes.c_uint),
        ("ttl", ctypes.c_ubyte),
        ("protocol", ctypes.c_ubyte),
        ("src_port", ctypes.c_ushort),
        ("dst_port", ctypes.c_ushort),
        ("seq", ctypes.c_uint),
        ("ack", ctypes.c_uint),
        ("tcp_flags", ctypes.c_ubyte),
        ("src_dns", ctypes.c_char * DNS_NAME_SIZE),
        ("payload", ctypes.POINTER(ctypes.c_ubyte)),
        ("payload_size", ctypes.c_int),
        ("capture_time", ctypes.c_long)
    ]

# Load the shared library
lib_path = os.path.join(os.getcwd(), "libpacket_capture.so")
packet_lib = ctypes.CDLL(lib_path)

# Set the return types for getter functions.
packet_lib.get_packet_count.restype = ctypes.c_int
packet_lib.get_packet_info.restype = ctypes.POINTER(PacketInfo)

# Run capture in a thread so Python can later get the packets.
def run_capture():
    packet_lib.start_capture()

capture_thread = threading.Thread(target=run_capture, daemon=True)
capture_thread.start()

# Let it capture for a while.
time.sleep(5)

count = packet_lib.get_packet_count()
print("Packets captured:", count)

for i in range(count):
    pkt_ptr = packet_lib.get_packet_info(i)
    pkt = pkt_ptr.contents
    # Format MAC addresses
    src_mac = ":".join(f"{b:02X}" for b in pkt.src_mac)
    dst_mac = ":".join(f"{b:02X}" for b in pkt.dest_mac)
    src_ip = pkt.src_ip.decode('utf-8').strip('\0')
    dst_ip = pkt.dst_ip.decode('utf-8').strip('\0')
    # Get DNS for source IP from the new field.
    src_dns = pkt.src_dns.decode('utf-8').strip('\0')
    print(f"Packet {pkt.packet_number}: {src_ip} -> {dst_ip}, Src MAC: {src_mac}, Dst MAC: {dst_mac}, Protocol: {pkt.protocol} {src_dns}")

# main.py
from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import ctypes
import os
import time
import threading
from collections import Counter
from typing import List, Dict, Optional
import json
import asyncio
from datetime import datetime

# Your existing PacketInfo structure
DNS_NAME_SIZE = 1025
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

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

# Global variables for packet storage
packets = []
dns_counter = Counter()
active_connections: List[WebSocket] = []

def check_root_privileges():
    return os.geteuid() == 0

# Load the shared library
lib_path = os.path.join(os.getcwd(), "libpacket_capture.so")
packet_lib = ctypes.CDLL(lib_path)
packet_lib.get_packet_count.restype = ctypes.c_int
packet_lib.get_packet_info.restype = ctypes.POINTER(PacketInfo)

def format_packet(pkt: PacketInfo) -> dict:
    """Convert PacketInfo to dictionary format"""
    src_mac = ":".join(f"{b:02X}" for b in pkt.src_mac)
    dst_mac = ":".join(f"{b:02X}" for b in pkt.dest_mac)
    src_ip = pkt.src_ip.decode('utf-8').strip('\0')
    dst_ip = pkt.dst_ip.decode('utf-8').strip('\0')
    src_dns = pkt.src_dns.decode('utf-8').strip('\0')
    
    return {
        "packet_number": pkt.packet_number,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": pkt.protocol,
        "src_dns": src_dns,
        "src_port": pkt.src_port,
        "dst_port": pkt.dst_port,
        "total_length": pkt.total_length,
        "timestamp": datetime.fromtimestamp(pkt.capture_time).strftime('%Y-%m-%d %H:%M:%S')
    }

async def packet_capture_loop():
    """Background task to capture packets and broadcast to clients"""
    if not check_root_privileges():
        print("Warning: Application running without root privileges. Packet capture may not work.")
        return

    def run_capture():
        try:
            packet_lib.start_capture()
        except Exception as e:
            print(f"Error starting capture: {e}")
    
    capture_thread = threading.Thread(target=run_capture, daemon=True)
    capture_thread.start()
    
    last_count = 0
    while True:
        try:
            count = packet_lib.get_packet_count()
            if count > last_count:
                for i in range(last_count, count):
                    pkt_ptr = packet_lib.get_packet_info(i)
                    pkt = pkt_ptr.contents
                    packet_dict = format_packet(pkt)
                    packets.append(packet_dict)
                    dns_counter[packet_dict["src_dns"]] += 1
                    
                    # Broadcast to all connected clients
                    for connection in active_connections[:]:  # Create a copy of the list
                        try:
                            await connection.send_json({
                                "type": "new_packet",
                                "data": packet_dict
                            })
                        except:
                            if connection in active_connections:
                                active_connections.remove(connection)
                
                last_count = count
        except Exception as e:
            print(f"Error in packet capture loop: {e}")
        await asyncio.sleep(0.1)

@app.on_event("startup")
async def startup_event():
    if not check_root_privileges():
        print("WARNING: Application must be run with sudo privileges for packet capture!")
    asyncio.create_task(packet_capture_loop())

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except:
        if websocket in active_connections:
            active_connections.remove(websocket)

@app.get("/")
async def get_html():
    with open("static/index.html") as f:
        return HTMLResponse(f.read())

@app.get("/api/packets")
async def get_packets(
    limit: int = 100,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    sort_by: str = "packet_number",
    order: str = "desc"
):
    filtered_packets = packets.copy()
    
    # Apply filters
    if src_ip:
        filtered_packets = [p for p in filtered_packets if src_ip in p["src_ip"]]
    if dst_ip:
        filtered_packets = [p for p in filtered_packets if dst_ip in p["dst_ip"]]
    if protocol and protocol.isdigit():
        protocol_num = int(protocol)
        filtered_packets = [p for p in filtered_packets if p["protocol"] == protocol_num]
    
    # Sort
    reverse = order.lower() == "desc"
    filtered_packets.sort(key=lambda x: x[sort_by], reverse=reverse)
    
    return filtered_packets[-limit:]

@app.get("/api/dns_stats")
async def get_dns_stats(limit: int = 10):
    return dict(dns_counter.most_common(limit))

@app.get("/api/status")
async def get_status():
    return {
        "root_privileges": check_root_privileges(),
        "packet_count": len(packets),
        "active_connections": len(active_connections)
    }
#!/usr/bin/env python3
import os
import socket
import threading
import time
import json
import struct
from datetime import datetime
from collections import deque, defaultdict
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from flask import Flask, render_template_string, jsonify, request, send_from_directory

# New imports for serial/chat
try:
    import serial
    from serial.serialutil import SerialException
except Exception:
    serial = None
from queue import Queue
import signal

from photo_manager import PhotoManager
from photo_sender import send_photo_bytes, PhotoSendError, parse_resize
from local_command_manager import LocalCommandManager, LocalCommandTimeout
from ip4c_utils import CODING_LOCAL_COMMAND

# Flask setup
app = Flask(__name__)

# Configuration
UDP_IP = "0.0.0.0"
UDP_PORT = 9000
MAX_HISTORY = 1000  # Maximum number of frames to keep in history

# Chat configuration
CHAT_PORT = os.getenv("IP400_CHAT_PORT", "/dev/serial0")
CHAT_BAUD = int(os.getenv("IP400_CHAT_BAUD", "115200"))
CHAT_MAX_HISTORY = 500

# Photo transmission configuration
PHOTO_SPI_HOST = os.getenv("IP400_SPI_HOST", "127.0.0.1")
PHOTO_SPI_PORT = int(os.getenv("IP400_SPI_PORT", "8400"))
PHOTO_DEFAULT_FROM_PORT = int(os.getenv("IP400_FROM_PORT", "100"))
PHOTO_DEFAULT_TO_PORT = int(os.getenv("IP400_TO_PORT", "100"))
PHOTO_MAX_PAYLOAD = int(os.getenv("IP400_PHOTO_MAX_PAYLOAD", "900"))
PHOTO_DELAY = float(os.getenv("IP400_PHOTO_DELAY", "0.3"))

# Data structures
frame_history = deque(maxlen=MAX_HISTORY)
node_history = defaultdict(dict)  # node_id -> {last_seen, rssi, location, etc.}

# Chat data structures
chat_history = defaultdict(lambda: deque(maxlen=CHAT_MAX_HISTORY))  # node_id -> deque of messages
chat_outgoing = Queue()
recent_sent_messages = deque(maxlen=10)  # Track recently sent messages for echo suppression

# Photo storage
photo_manager = PhotoManager(storage_dir="photos", history=12)
local_command_manager: Optional[LocalCommandManager] = None

# Thread coordination flags
chat_should_run = threading.Event()
chat_should_run.set()  # Chat thread runs by default
chat_paused = threading.Event()
console_active = threading.Event()

# Node Info
node_info = {}  # stores this node's info from menu A
node_info_cache = {}  # cache for node info

# Console data structures and state
class IP400State:
    def __init__(self):
        self.state = "UNKNOWN"  # UNKNOWN, MAIN_MENU, CHAT_MODE, SETTINGS_MENU, etc.
        self.last_command = None
        self.last_command_time = 0
        self.expected_prompt = None
        self.serial_lock = threading.Lock()
        self.in_settings = False  # Track if we're in settings menu

console_state = IP400State()
console_output = Queue()
console_commands = Queue()

# Global serial connection for console
ser = None

def process_console_line(line):
    """Process a single line of console output and update state"""
    line = line.strip()
    if not line:
        return
    
    # Debug log the line being processed
    print(f"[CONSOLE DEBUG] Processing line: {line}")
    
    # Update state based on output
    if "Select an item->" in line:
        console_state.state = "MAIN_MENU"
        console_state.expected_prompt = None
        console_state.in_settings = False
    elif "Welcome to chat" in line:
        console_state.state = "CHAT_MODE"
        console_state.expected_prompt = None
        console_state.in_settings = False
    elif "Menu A - List setup parameters" in line:
        console_state.state = "PARAMETERS_MENU"
        console_state.in_settings = False
    # Add detection for settings menu
    elif "Settings Menu" in line or "Settings ->" in line:
        console_state.state = "SETTINGS_MENU"
        console_state.in_settings = True
    # Check for settings submenu prompts
    elif any(prompt in line for prompt in ["Enter new value", 
                                         "Press ENTER to continue",
                                         "Select an option"]):
        console_state.expected_prompt = line.strip()
    
    # Add to output queue once
    console_output.put(line)
    print(f"[CONSOLE] {line}")

def send_console_command(cmd, timeout=2.0, expect_prompt=None):
    """Send a command to the IP400 console and handle the response"""
    global ser
    if not ser or not ser.is_open:
        print("[CONSOLE] Cannot send command - serial port not open")
        return False
    
    with console_state.serial_lock:
        try:
            # Clear any pending input
            ser.reset_input_buffer()
            
            # Store command context
            console_state.last_command = cmd
            console_state.expected_prompt = expect_prompt
            console_state.last_command_time = time.time()
            
            print(f"[CONSOLE] Sending command: {cmd}")
            ser.write((cmd + '\r\n').encode('utf-8'))
            return True
            
        except Exception as e:
            print(f"[CONSOLE] Error sending command: {e}")
            return False

def navigate_to_menu(target_menu):
    """Safely navigate to a specific menu (e.g., 'S' for settings)"""
    with console_state.serial_lock:
        print(f"[NAVIGATE] Current state: {console_state.state}, Target: {target_menu}")
        
        # If already in the target menu, just send a newline to refresh
        if (target_menu.upper() == 'S' and console_state.state == "SETTINGS_MENU") or \
           (target_menu.upper() == 'C' and console_state.state == "CHAT_MODE"):
            print("[NAVIGATE] Already in target menu, refreshing...")
            return send_console_command('')
            
        # If in settings menu, try to exit it first
        if console_state.in_settings:
            print("[NAVIGATE] Exiting settings menu...")
            send_console_command('\x1b')  # ESC key
            time.sleep(0.5)
            
        # If not in main menu, try to get back to it
        if console_state.state != "MAIN_MENU" and console_state.state != "UNKNOWN":
            print("[NAVIGATE] Returning to main menu...")
            send_console_command('\x1b')  # ESC key
            time.sleep(0.5)
            send_console_command('')  # Newline to get to main menu
            time.sleep(0.5)
            
        # Now send the target menu command
        print(f"[NAVIGATE] Sending menu command: {target_menu}")
        return send_console_command(target_menu)

@dataclass
class Beacon:
    """Class to represent a beacon frame with all its metadata."""
    timestamp: str
    raw_data: bytes
    from_call: str = ""
    from_port: int = 0
    to_call: str = ""
    to_port: int = 0
    hop_count: int = 0
    coding: int = 0
    flags: int = 0
    rssi: Optional[int] = None
    snr: Optional[float] = None
    frequency: Optional[float] = None
    location: Optional[Tuple[float, float]] = None
    payload: bytes = b''
    frame_type: str = "unknown"
    status: int = 0
    offset: int = 0
    length: int = 0

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        result = {
            'timestamp': self.timestamp,
            'from_call': self.from_call,
            'from_port': self.from_port,
            'to_call': self.to_call,
            'to_port': self.to_port,
            'hop_count': self.hop_count,
            'coding': self.coding,
            'flags': self.flags,
            'status': self.status,
            'offset': self.offset,
            'length': self.length,
            'rssi': self.rssi,
            'snr': float(self.snr) if self.snr is not None else None,
            'frequency': float(self.frequency) if self.frequency is not None else None,
            'location': list(self.location) if self.location else None,
            'frame_type': self.frame_type,
            'raw_data': self.raw_data.hex() if isinstance(self.raw_data, (bytes, bytearray)) else str(self.raw_data),
            'payload_hex': self.payload.hex() if isinstance(self.payload, (bytes, bytearray)) else str(self.payload),
            'payload_ascii': self.payload.decode('ascii', errors='replace') if isinstance(self.payload, (bytes, bytearray)) else str(self.payload),
        }
        # Ensure all values are JSON serializable
        for k, v in list(result.items()):
            if v is not None and not isinstance(v, (str, int, float, bool, list, dict)):
                result[k] = str(v)
        return result

# ---------------------------
# Helper functions (callsign/GPS parsing / frame parse)
# ---------------------------

def decode_excess40_callsign(call_bytes: bytes) -> str:
    if len(call_bytes) != 4:
        return "INVALID"
    
    try:
        value = struct.unpack('>I', call_bytes)[0]
        
        char_map = "0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ_-@"
        
        if value == 0xFFFFFFFF:
            return "BROADCAST"
        if value == 0:
            return "EMPTY"
        
        # Try big-endian first
        decoded_chars = []
        for i in range(6):
            if value == 0:
                break
            char_index = value % 40
            decoded_chars.append(char_map[char_index])
            value //= 40
        
        callsign = "".join(reversed(decoded_chars)).strip()
        
        # If big-endian didn't work well, try little-endian
        value = struct.unpack('<I', call_bytes)[0]
        
        decoded_chars = []
        for _ in range(6):
            if value == 0:
                break
            char_index = value % 40
            decoded_chars.append(char_map[char_index])
            value //= 40
        
        # Return the little-endian result
        return "".join(reversed(decoded_chars)).strip()
        
    except Exception as e:
        return f"0x{call_bytes.hex()}"

def parse_gps_coords(coord_str: str) -> Optional[float]:
    if not coord_str:
        return None
    try:
        direction = coord_str[-1].upper()
        if direction not in 'NSEW':
            return None
        coord = coord_str[:-1]
        # allow leading zeros and decimals
        coord_float = float(coord)
        deg = int(coord_float // 100)
        minutes = coord_float - (deg * 100)
        dec_deg = deg + (minutes / 60.0)
        if direction in 'SW':
            dec_deg = -dec_deg
        return round(dec_deg, 6)
    except Exception:
        return None

def parse_beacon_payload(payload: bytes) -> dict:
    try:
        payload_str = payload.decode('ascii', errors='ignore').strip('\x00').rstrip(',')
        parts = payload_str.split(',')
        if len(parts) < 3:
            return {'raw': payload_str}
        result = {
            'source': parts[0] if len(parts) > 0 else '',
            'latitude_raw': parts[1] if len(parts) > 1 else '',
            'longitude_raw': parts[2] if len(parts) > 2 else '',
            'speed': parts[3] if len(parts) > 3 and parts[3] else None,
            'fix_time': parts[4] if len(parts) > 4 and parts[4] else None,
            'grid_square': parts[5] if len(parts) > 5 and parts[5] else None,
            'raw': payload_str
        }
        if result['latitude_raw'] and result['longitude_raw']:
            lat = parse_gps_coords(result['latitude_raw'])
            lon = parse_gps_coords(result['longitude_raw'])
            if lat is not None and lon is not None:
                result['latitude'] = lat
                result['longitude'] = lon
        return result
    except Exception:
        return {'raw': payload.decode('ascii', errors='replace')}

def get_packet_type_name(coding: int) -> str:
    packet_types = {
        0x00: "UTF-8 Text",
        0x01: "Compressed Audio",
        0x02: "H.264 Video",
        0x03: "Data Packet",
        0x04: "Beacon",
        0x05: "IP Encapsulated",
        0x06: "AX.25",
        0x07: "DTMF",
        0x08: "DMR",
        0x09: "D-Star",
        0x0A: "Project 25",
        0x0B: "NXDN",
        0x0C: "M17",
        0x0F: "Local Command"
    }
    return packet_types.get(coding & 0x0F, f"Unknown ({coding & 0x0F})")

def parse_ip400_frame(frame: bytes) -> Optional[Beacon]:
    if len(frame) < 24:
        return None
    try:
        beacon = Beacon(timestamp=datetime.utcnow().isoformat() + 'Z', raw_data=frame)
        if not frame.startswith(b'IP4C'):
            return None
        beacon.frame_type = "IP4C"
        beacon.status = frame[4]
        beacon.offset = (frame[5] << 8) | frame[6]
        beacon.length = (frame[7] << 8) | frame[8]
        from_call_bytes = frame[9:13]
        beacon.from_call = decode_excess40_callsign(from_call_bytes)
        beacon.from_port = struct.unpack('>H', frame[13:15])[0]
        to_call_bytes = frame[15:19]
        beacon.to_call = decode_excess40_callsign(to_call_bytes)
        beacon.to_port = struct.unpack('>H', frame[19:21])[0]
        beacon.coding = frame[21]
        beacon.hop_count = frame[22]
        beacon.flags = frame[23]
        payload_start = 24
        if beacon.flags & 0x20:
            hop_table_size = beacon.hop_count * 4
            payload_start += hop_table_size
        if payload_start < len(frame):
            beacon.payload = frame[payload_start:]
            if (beacon.coding & 0x0F) == 0x04:
                beacon_info = parse_beacon_payload(beacon.payload)
                if 'latitude' in beacon_info and 'longitude' in beacon_info:
                    beacon.location = (beacon_info['latitude'], beacon_info['longitude'])
        return beacon
    except Exception as e:
        print(f"Error parsing IP400 frame: {e}")
        import traceback
        traceback.print_exc()
        return None

# Node Info

import re

node_info_cache = {}

def read_ip400_node_info():
    """Read node info using the working ip400_read_parameters function."""
    global node_info, node_info_cache
    
    print("[NODEINFO] Fetching node info from IP400...")
    
    # First try to load from the temp file (which is updated by ip400_read_parameters)
    if os.path.exists("/tmp/ip400_node.json"):
        try:
            with open("/tmp/ip400_node.json", "r") as f:
                info = json.load(f)
                if info:  # Only use if we got valid data
                    print("[NODEINFO] Loaded from /tmp/ip400_node.json")
                    node_info_cache = info
                    node_info = info
                    # Also update our local cache
                    with open("nodeinfo.json", "w") as f_cache:
                        json.dump(info, f_cache, indent=2)
                    return info
        except Exception as e:
            print(f"[NODEINFO] Error loading from temp file: {e}")
    
    # If we still don't have info, try the local cache
    if not info and os.path.exists("nodeinfo.json"):
        try:
            with open("nodeinfo.json", "r") as f:
                info = json.load(f)
                print("[NODEINFO] Loaded from cache")
        except Exception as e:
            print(f"[NODEINFO] Error loading cache: {e}")
    
    # If we got info, save it to our cache
    if info:
        node_info_cache = info
        node_info = info
        with open("nodeinfo.json", "w") as f:
            json.dump(info, f, indent=2)
        print(f"[NODEINFO] Updated node info: {info}")
    else:
        print("[NODEINFO] Could not read node info from any source")
    
    return info


def get_local_callsign(default: str = "N0CALL") -> str:
    """Best-effort lookup of the local station callsign."""
    candidates = [
        node_info.get("Station Callsign") if isinstance(node_info, dict) else None,
        node_info_cache.get("Station Callsign") if isinstance(node_info_cache, dict) else None,
        os.getenv("IP400_LOCAL_CALLSIGN"),
    ]
    for value in candidates:
        if value:
            return str(value).strip() or default
    return default


local_command_manager = LocalCommandManager(
    spi_host=PHOTO_SPI_HOST,
    spi_port=PHOTO_SPI_PORT,
    callsign_provider=get_local_callsign,
    from_port=PHOTO_DEFAULT_FROM_PORT,
    to_port=PHOTO_DEFAULT_TO_PORT,
)

# ---------------------------
# UDP listener
# ---------------------------

def udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"Listening on UDP {UDP_IP}:{UDP_PORT}...")
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            beacon = parse_ip400_frame(data)
            if beacon:
                if (beacon.coding & 0x0F) == CODING_LOCAL_COMMAND:
                    if beacon.payload:
                        local_command_manager.handle_response(beacon.payload)
                    continue
                frame_history.appendleft(beacon)
                node_id = f"{beacon.from_call}:{beacon.from_port}"
                node_history[node_id] = {
                    'last_seen': beacon.timestamp,
                    'rssi': beacon.rssi,
                    'location': beacon.location,
                    'frame_count': node_history.get(node_id, {}).get('frame_count', 0) + 1,
                    'last_data': data.hex(),
                    'packet_type': get_packet_type_name(beacon.coding),
                    # optionally mark local if matches configured callsign (not set here)
                }
                try:
                    if (beacon.coding & 0x0F) == 0x03 and beacon.payload:
                        photo_info = photo_manager.handle_frame(beacon.from_call or "UNKNOWN", beacon.payload)
                        if photo_info:
                            print(f"[PHOTO] New image available: {photo_info['original_name']} ({photo_info['size']} bytes)")
                except Exception as exc:
                    print(f"[PHOTO] Error handling data frame: {exc}")
            else:
                # Not an IP4C frame; ignore
                pass
        except Exception as e:
            print(f"Error in UDP listener: {e}")
            import traceback
            traceback.print_exc()

# Node Info Parse

import re

def ip400_read_parameters():
    """Query IP400 'A' menu and parse setup parameters into a dict."""
    if serial is None:
        print("[PARAMS] pyserial not available")
        return {}

    print("[PARAMS] Starting to read parameters from IP400...")
    
    try:
        print(f"[PARAMS] Opening serial port {CHAT_PORT} at {CHAT_BAUD} baud...")
        ser = serial.Serial(CHAT_PORT, CHAT_BAUD, timeout=0.5)
        time.sleep(0.2)
        
        print("[PARAMS] Clearing input buffer...")
        ser.reset_input_buffer()
        
        print("[PARAMS] Sending 'A' command...")
        ser.write(b"A\r\n")
        time.sleep(1.2)  # Give it time to respond

        output = b""
        t0 = time.time()
        print("[PARAMS] Reading response...")
        
        while time.time() - t0 < 5.0:  # Increased timeout to 5 seconds
            chunk = ser.read(1024)
            if chunk:
                output += chunk
                print(f"[PARAMS] Read {len(chunk)} bytes")
                if b"Output Power" in output or b"Select an item" in output:
                    print("[PARAMS] Found menu in response")
                    break
            else:
                time.sleep(0.1)  # Slightly longer delay between reads

        text = output.decode(errors="ignore")
        print(f"[PARAMS RAW]\n{text}\n")

        # Try different patterns to extract data
        data = {}
        # Try the original pattern first
        matches = re.findall(r'([A-Za-z0-9 _/]+)->([^\r\n]+)', text)
        if matches:
            data = {k.strip(): v.strip() for k, v in matches}
            print("[PARAMS] Successfully parsed parameters with original pattern")
        else:
            # Try alternative patterns if the first one fails
            print("[PARAMS] Trying alternative parsing patterns...")
            # Try pattern like "Station Callsign : N0CALL"
            alt_matches = re.findall(r'([A-Za-z ]+)[:]+\s*([^\r\n]+)', text)
            if alt_matches:
                data = {k.strip(): v.strip() for k, v in alt_matches}
                print("[PARAMS] Successfully parsed parameters with alternative pattern")
            else:
                print("[PARAMS] Could not parse any parameters from response")

        # return to menu root
        try:
            ser.write(b"\r\n")
            time.sleep(0.3)
            ser.close()
        except:
            pass  # Ignore errors during cleanup

        if data:
            global node_info, node_info_cache
            node_info = data
            node_info_cache = data  # Update cache
            
            # Save for frontend
            try:
                with open("/tmp/ip400_node.json", "w") as f:
                    json.dump(data, f, indent=2)
                print(f"[PARAMS] Node info saved to /tmp/ip400_node.json")
                
                # Also save a local copy
                with open("nodeinfo.json", "w") as f:
                    json.dump(data, f, indent=2)
                print(f"[PARAMS] Node info saved to nodeinfo.json")
            except Exception as e:
                print(f"[PARAMS] Error saving node info: {e}")
            
            return data
        else:
            print("[PARAMS] No valid data received from IP400")
            return {}

    except Exception as e:
        print(f"[PARAMS] Error reading parameters: {str(e)}")
        import traceback
        traceback.print_exc()
        return {}

# ---------------------------
# Serial chat thread
# ---------------------------

def ip400_chat_thread():
    """Background thread to manage chat over serial (enter chat mode with 'C', read/write lines)."""
    if serial is None:
        print("[CHAT] pyserial not available; install with 'sudo apt install python3-serial' or 'pip3 install pyserial'")
        return

    ser = None
    chat_mode_entered = False
    pending_sender = None  # Track sender from previous line for multi-line messages
    
    def send_command(cmd, delay=0.2):
        """Helper to send a command to the serial port with optional delay after"""
        if ser and ser.is_open:
            try:
                ser.write((cmd + '\r\n').encode())
                time.sleep(delay)
                return True
            except Exception as e:
                print(f"[CHAT] Error sending command '{cmd}': {e}")
        return False
    
    while True:
        try:
            # Pause chat operations when console access is active
            if not chat_should_run.is_set():
                if ser and ser.is_open:
                    try:
                        ser.close()
                    except Exception:
                        pass
                ser = None
                if not chat_paused.is_set():
                    chat_paused.set()
                # Block until chat should resume
                chat_should_run.wait()
                # Reset state for fresh chat session
                chat_paused.clear()
                chat_mode_entered = False
                pending_sender = None
                continue

            if ser is None or not ser.is_open:
                try:
                    ser = serial.Serial(CHAT_PORT, CHAT_BAUD, timeout=0.5)
                    time.sleep(0.2)
                    # Always enter chat mode on (re)connect
                    if send_command('C', 0.5):
                        chat_mode_entered = True
                        print(f"[CHAT] Connected to {CHAT_PORT} at {CHAT_BAUD} baud and entered chat mode.")
                    else:
                        print(f"[CHAT] Connected to {CHAT_PORT} but failed to enter chat mode.")
                except Exception as e:
                    print(f"[CHAT] Error connecting to {CHAT_PORT}: {e}")
                    ser = None
                    time.sleep(2)
                    continue

            # Read incoming lines
            try:
                line = ser.readline()
            except SerialException as se:
                print(f"[CHAT] Serial read error: {se}")
                try:
                    ser.close()
                except Exception:
                    pass
                ser = None
                time.sleep(1)
                continue

            if line:
                try:
                    text = line.decode('utf-8', errors='ignore').rstrip('\r\n')
                    
                    # Print EVERYTHING that comes through (for debugging)
                    print(f"[CHAT RAW] {repr(text)}")
                    
                    # Skip empty lines and system/console messages
                    text_stripped = text.strip()
                    if not text_stripped:
                        continue
                    
                    # Skip known system/console messages
                    skip_patterns = [
                        'Welcome to chat', 'ESC to set', 'CTRL/', 'Repeat mode', 
                        'Destination callsign', 'Main Menu', 'Settings', 'Network',
                        'Radio', 'Info', 'Chat Mode', 'Console Mode', 'Enter command',
                        'Invalid command', 'Unknown command', 'Command not found',
                        'Press any key to continue', 'Select an option', 'Option:'
                    ]
                    
                    if any(pattern in text_stripped for pattern in skip_patterns) or \
                       text_stripped in ['C', 'M', 'S', 'N', 'R', 'I']:  # Single-letter menu commands
                        continue
                    
                    # Check if this is an echo of a recently sent message
                    is_echo = False
                    current_time = time.time()
                    
                    # Extract just the message part if it's in the format "CALLSIGN(...) DEST[...]:<message>"
                    message_only = text_stripped
                    if ']:' in text_stripped:
                        parts = text_stripped.split(']:', 1)
                        if len(parts) == 2:
                            message_only = parts[1].strip()
                    
                    # Check against recently sent messages (within last 5 seconds)
                    for sent_msg, sent_time in list(recent_sent_messages):
                        if current_time - sent_time < 5.0:  # 5 second window
                            if message_only == sent_msg or text_stripped.endswith(sent_msg):
                                is_echo = True
                                print(f"[CHAT] Echo suppressed: {message_only}")
                                break
                    
                    if not is_echo:
                        # Only store messages that look like actual chat (not console output)
                        # Look for the pattern of a chat message: CALLSIGN(...) DEST[...]: message
                        if ']' in text_stripped and ':' in text_stripped.split(']')[-1]:
                            entry = {"timestamp": datetime.utcnow().isoformat() + 'Z', "text": text_stripped}
                            chat_history["broadcast"].appendleft(entry)
                            print(f"[CHAT] Stored chat message: {text_stripped}")
                        else:
                            print(f"[CHAT] Filtered console output: {text_stripped}")
                        
                except Exception as e:
                    print(f"[CHAT] Error processing incoming message: {e}")

            # send outgoing messages (non-blocking)
            try:
                msg_data = chat_outgoing.get_nowait()
                try:
                    # msg_data is now a dict with 'node' and 'message'
                    node = msg_data.get('node', 'unknown')
                    msg = msg_data.get('message', '')
                    
                    # Track this message for echo suppression
                    recent_sent_messages.append((msg, time.time()))
                    
                    # Send just the message (the device will broadcast it)
                    # If you need to address a specific node, adjust the format here
                    ser.write((msg + "\r\n").encode('utf-8'))
                    print(f"[CHAT TX to {node}] {msg}")
                except SerialException as se:
                    print(f"[CHAT] Serial write error: {se}")
                    # put it back so it can be retried
                    chat_outgoing.put(msg_data)
                    try:
                        ser.close()
                    except Exception:
                        pass
                    ser = None
                    time.sleep(1)
            except Exception:
                # nothing to send
                pass

            # small sleep to avoid busy loop
            time.sleep(0.05)
        except Exception as e:
            print(f"[CHAT] Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(2)

# ---------------------------
# Serial console thread
# ---------------------------

def ip400_console_thread():
    """Background thread to provide interactive access to the IP400 text menu."""
    global ser
    
    if serial is None:
        print("[CONSOLE] pyserial not available; install with 'sudo apt install python3-serial' or 'pip3 install pyserial'")
        return

    buffer = ""
    
    while True:
        try:
            # Keep console idle unless explicitly activated
            if not console_active.is_set():
                if ser and ser.is_open:
                    try:
                        ser.close()
                    except Exception:
                        pass
                ser = None
                buffer = ""
                time.sleep(0.2)
                continue

            # Handle serial connection
            if ser is None or not ser.is_open:
                try:
                    with console_state.serial_lock:
                        ser = serial.Serial(CHAT_PORT, CHAT_BAUD, timeout=0.2)
                        time.sleep(0.5)  # Give it time to initialize
                        print(f"[CONSOLE] Connected to {CHAT_PORT} at {CHAT_BAUD} baud")
                        # Send a newline to get a prompt
                        ser.write(b'\r\n')
                        time.sleep(0.5)
                except Exception as e:
                    print(f"[CONSOLE] Error connecting to {CHAT_PORT}: {e}")
                    ser = None
                    time.sleep(2)
                    continue

            # Process any queued commands
            try:
                cmd = console_commands.get_nowait()
                if cmd.strip().upper() in ['A', 'B', 'C', 'D', 'E', 'R', 'S', 'T', 'W']:
                    navigate_to_menu(cmd.strip().upper())
                else:
                    send_console_command(cmd)
                time.sleep(0.2)  # Small delay after sending command
            except Exception:
                pass  # No command to send

            # Read and process console output
            try:
                while ser.in_waiting > 0:
                    # Read one byte at a time to properly handle partial lines
                    byte = ser.read(1)
                    if byte:
                        char = byte.decode('utf-8', errors='ignore')
                        if char == '\n' or char == '\r':
                            if buffer.strip():
                                process_console_line(buffer)
                                buffer = ""
                        else:
                            buffer += char
            except Exception as e:
                print(f"[CONSOLE] Error reading from serial: {e}")
                ser = None
                buffer = ""
                continue

            time.sleep(0.05)  # Small sleep to prevent busy waiting

        except Exception as e:
            print(f"[CONSOLE] Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            if ser:
                try:
                    ser.close()
                except:
                    pass
                ser = None
                buffer = ""
            time.sleep(1)
            time.sleep(2)

# ---------------------------
# Flask routes (UI)
# ---------------------------

@app.route("/")
def index():
    return render_template_string("""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
  <title>IP400 Network Monitor</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
  <style>
    #map { height: 300px; width: 100%; margin-bottom: 20px; }
    @media (min-width: 768px) {
      #map { height: 400px; }
    }
   
    .node-badge {
        font-size: 0.7em;
        margin-left: 5px;
        vertical-align: middle;
    }
    .local-node {
        border-left: 3px solid #0d6efd;
        padding-left: 10px;
        margin-bottom: 10px;
    }
    .location-info {
        font-size: 0.85em;
        color: #6c757d;
    }
    .frame-row { cursor: pointer; }
    .frame-row:hover { background-color: #f8f9fa; }
    #frameTable { font-size: 0.9rem; }
    .sidebar { overflow-y: auto; max-height: 80vh; }
    .badge-beacon { background-color: #17a2b8; }
    .badge-text { background-color: #28a745; }
    .badge-data { background-color: #6f42c1; }
    .badge-unknown { background-color: #6c757d; }
    .custom-marker {
      position: relative;
      width: 20px;
      height: 20px;
    }
    .marker-pin {
      width: 20px;
      height: 20px;
      border-radius: 50% 50% 50% 0;
      background: #0d6efd;
      position: absolute;
      transform: rotate(-45deg);
      left: 0;
      top: 0;
      margin: -10px 0 0 -10px;
    }
    .marker-pin.local {
      background: #dc3545;
    }
    .marker-pin::after {
      content: '';
      width: 10px;
      height: 10px;
      margin: 5px 0 0 5px;
      background: #fff;
      position: absolute;
      border-radius: 50%;
    }
    .local-marker {
      z-index: 1000;
    }
    
    /* Console terminal styles */
    #consoleOutput {
      background-color: #1e1e1e;
      color: #d4d4d4;
      font-family: 'Courier New', monospace;
      font-size: 0.9rem;
      padding: 15px;
      height: 400px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-wrap: break-word;
    }
    .console-menu-btn {
      min-width: 120px;
      margin: 5px;
    }
    
    /* Mobile responsive styles */
    @media (max-width: 767px) {
      .navbar-text { font-size: 0.85rem; }
      #frameTable { font-size: 0.75rem; }
      .card-header h5 { font-size: 1rem; }
      .table-responsive { font-size: 0.85rem; }
      #chatMessages { max-height: 200px !important; }
      .form-control-sm { font-size: 0.85rem; }
      #consoleOutput { height: 300px; font-size: 0.8rem; }
    }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container-fluid">
      <a class="navbar-brand" href="#">IP400 Network Monitor</a>
      <div class="d-flex align-items-center">
        <span class="navbar-text me-3" id="frameCount">0 frames</span>
        <button class="btn btn-outline-light btn-sm" data-bs-toggle="modal" data-bs-target="#settingsModal">
          <i class="bi bi-gear"></i> Settings
        </button>
      </div>
    </div>
  </nav>

  <div class="container-fluid mt-3">
    <div class="row">
      <!-- Main content -->
      <div class="col-md-8">
        <div class="card mb-4">
          <div class="card-header">
            <h5 class="mb-0">Network Map</h5>
          </div>
          <div class="card-body p-0">
            <div id="map"></div>
          </div>
        </div>
      </div>

      <!-- Sidebar -->
      <div class="col-md-4">
        <div class="card mb-4">
          <div class="card-header">
            <h5 class="mb-0">Active Nodes</h5>
          </div>
          <div class="card-body p-0">
            <div id="nodeList" class="list-group list-group-flush">
              <!-- Filled by JavaScript -->
            </div>
          </div>
        </div>
        <div class="card mb-4">
          <div class="card-header">
            <h5 class="mb-0">Photo Transfer</h5>
          </div>
          <div class="card-body">
            <form id="photoUploadForm" enctype="multipart/form-data">
              <div class="mb-2">
                <label class="form-label small text-muted">Select Photo</label>
                <input type="file" class="form-control form-control-sm" id="photoFile" name="photo" accept="image/*" required>
              </div>
              <div class="mb-2">
                <label class="form-label small text-muted">From Callsign</label>
                <input type="text" class="form-control form-control-sm" id="photoFromCall" name="fromCall" placeholder="Local call" value="">
              </div>
              <div class="mb-2">
                <label class="form-label small text-muted">Destination Callsign</label>
                <input type="text" class="form-control form-control-sm" id="photoToCall" name="toCall" value="BROADCAST" required>
              </div>
              <div class="accordion mt-3" id="photoAdvancedOptions">
                <div class="accordion-item">
                  <h2 class="accordion-header" id="photoAdvancedHeading">
                    <button class="accordion-button collapsed py-2" type="button" data-bs-toggle="collapse" data-bs-target="#photoAdvancedCollapse" aria-expanded="false" aria-controls="photoAdvancedCollapse">
                      Advanced Options
                    </button>
                  </h2>
                  <div id="photoAdvancedCollapse" class="accordion-collapse collapse" aria-labelledby="photoAdvancedHeading" data-bs-parent="#photoAdvancedOptions">
                    <div class="accordion-body">
                      <div class="row g-2">
                        <div class="col">
                          <label class="form-label small text-muted">Destination Port</label>
                          <input type="number" class="form-control form-control-sm" id="photoToPort" name="toPort" value="100">
                        </div>
                        <div class="col">
                          <label class="form-label small text-muted">Max Payload</label>
                          <input type="number" class="form-control form-control-sm" id="photoMaxPayload" name="maxPayload" value="900">
                        </div>
                      </div>
                      <div class="row g-2 mt-2">
                        <div class="col">
                          <label class="form-label small text-muted">Delay (s)</label>
                          <input type="number" step="0.1" class="form-control form-control-sm" id="photoDelay" name="delay" value="0.3">
                        </div>
                        <div class="col">
                          <label class="form-label small text-muted">Resize (WxH)</label>
                          <input type="text" class="form-control form-control-sm" id="photoResize" name="resize" placeholder="e.g. 320x240">
                        </div>
                      </div>
                      <div class="form-check form-switch mt-2">
                        <input class="form-check-input" type="checkbox" id="photoRepeatable" name="repeatable">
                        <label class="form-check-label small text-muted" for="photoRepeatable">Enable mesh repeat (hop propagation)</label>
                      </div>
                      <div class="form-check form-switch mt-1">
                        <input class="form-check-input" type="checkbox" id="photoConnectionless" name="connectionless" checked>
                        <label class="form-check-label small text-muted" for="photoConnectionless">Connectionless packet</label>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <button type="submit" class="btn btn-sm btn-primary w-100 mt-3">
                <i class="bi bi-upload"></i> Send Photo
              </button>
            </form>
            <div id="photoUploadStatus" class="alert alert-secondary small d-none mt-3" role="alert"></div>
          </div>
          <div class="list-group list-group-flush" id="photoList">
            <div class="list-group-item text-muted small">No photos received yet</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Chat card -->
    <div class="row mt-3">
      <div class="col-12">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="mb-0">IP400 Chat</h5>
            <div class="d-flex align-items-center">
              <label class="me-2 mb-0">To:</label>
              <select id="chatNodeSelect" class="form-select form-select-sm" style="width: auto;">
                <option value="">Select a node...</option>
              </select>
            </div>
          </div>
          <div class="card-body" style="max-height:300px; overflow-y:auto; background-color: #f8f9fa;" id="chatMessages">
            <div class="text-center text-muted py-4">
              <i class="bi bi-chat-dots" style="font-size: 2rem;"></i>
              <p class="mt-2">Select a node to start chatting</p>
            </div>
          </div>
          <div class="card-footer d-flex">
            <input id="chatInput" class="form-control me-2" placeholder="Type message..." disabled>
            <button class="btn btn-primary" id="chatSend" disabled>Send</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Frame history -->
    <div class="row mt-3">
      <div class="col-12">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <div class="d-flex align-items-center">
              <button class="btn btn-sm btn-outline-secondary me-2" type="button"
                      title="Toggle frame history" aria-label="Toggle frame history"
                      data-bs-toggle="collapse" data-bs-target="#frameCollapse"
                      aria-expanded="true" aria-controls="frameCollapse">
                <i class="bi bi-chevron-up" id="frameCollapseIcon"></i>
              </button>
              <h5 class="mb-0">Recent Frames</h5>
            </div>
            <div>
              <input type="text" id="searchInput" class="form-control form-control-sm" placeholder="Search...">
            </div>
          </div>
          <div id="frameCollapse" class="collapse show">
            <div class="table-responsive">
              <table class="table table-sm table-hover mb-0">
                <thead class="table-light">
                  <tr>
                    <th>Time</th>
                    <th>From</th>
                    <th>To</th>
                    <th>Type</th>
                    <th>Hops</th>
                    <th>Flags</th>
                    <th>Size</th>
                  </tr>
                </thead>
                <tbody id="frameTable">
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Frame Details Modal -->
  <div class="modal fade" id="frameModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-lg">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">Frame Details</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <pre id="frameDetails" class="p-3 bg-light rounded"></pre>
        </div>
      </div>
    </div>
  </div>

  <!-- Settings/Console Modal -->
  <div class="modal fade" id="settingsModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">IP400 Settings & Console</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <div class="row">
            <div class="col-md-3">
              <h6 class="mb-3">Quick Menu</h6>
              <div class="d-grid gap-2">
                <button class="btn btn-primary console-menu-btn" onclick="sendConsoleCommand('M')">
                  <i class="bi bi-list"></i> Main Menu
                </button>
                <button class="btn btn-secondary console-menu-btn" onclick="sendConsoleCommand('C')">
                  <i class="bi bi-chat"></i> Chat Mode
                </button>
                <button class="btn btn-secondary console-menu-btn" onclick="sendConsoleCommand('S')">
                  <i class="bi bi-sliders"></i> Settings
                </button>
                <button class="btn btn-secondary console-menu-btn" onclick="sendConsoleCommand('N')">
                  <i class="bi bi-wifi"></i> Network
                </button>
                <button class="btn btn-secondary console-menu-btn" onclick="sendConsoleCommand('R')">
                  <i class="bi bi-broadcast"></i> Radio
                </button>
                <button class="btn btn-secondary console-menu-btn" onclick="sendConsoleCommand('I')">
                  <i class="bi bi-info-circle"></i> Info
                </button>
                <button class="btn btn-warning console-menu-btn" onclick="clearConsole()">
                  <i class="bi bi-trash"></i> Clear
                </button>
                <hr class="my-3">
                <h6 class="mb-3">Server Control</h6>
                <button class="btn btn-danger console-menu-btn" onclick="restartServer()">
                  <i class="bi bi-arrow-clockwise"></i> Restart Server
                </button>
              </div>
            </div>
            <div class="col-md-9">
              <div class="mb-4">
                <div class="d-flex justify-content-between align-items-center">
                  <h6 class="mb-0">Node Settings</h6>
                  <div>
                    <button type="button" class="btn btn-sm btn-outline-secondary" onclick="refreshNodeSettings()">
                      <i class="bi bi-arrow-repeat"></i> Refresh
                    </button>
                    <button type="button" class="btn btn-sm btn-primary ms-2" id="nodeSettingsSaveBtn" onclick="saveNodeSettings()">
                      <i class="bi bi-save"></i> Save
                    </button>
                  </div>
                </div>
                <div id="nodeSettingsStatus" class="alert alert-secondary small d-none mt-2" role="alert"></div>
                <div class="row g-3 mt-1">
                  <div class="col-md-6">
                    <label class="form-label small text-muted">Station Callsign</label>
                    <input type="text" class="form-control form-control-sm" id="settingStationCallsign" data-setting-key="Station Callsign">
                  </div>
                  <div class="col-md-6">
                    <label class="form-label small text-muted">Beacon Interval (mins)</label>
                    <input type="text" class="form-control form-control-sm" id="settingBeaconInterval" data-setting-key="Beacon Interval">
                  </div>
                  <div class="col-md-6">
                    <label class="form-label small text-muted">RF Frequency (MHz)</label>
                    <input type="text" class="form-control form-control-sm" id="settingRfFrequency" data-setting-key="RF Frequency">
                  </div>
                  <div class="col-md-6">
                    <label class="form-label small text-muted">Output Power</label>
                    <input type="text" class="form-control form-control-sm" id="settingOutputPower" data-setting-key="Output Power">
                  </div>
                </div>
                <small class="text-muted d-block mt-2">
                  Changes are queued for the hat; ensure the pending settings file is processed by the control service.
                </small>
              </div>
              <h6 class="mb-3">Console Output</h6>
              <div id="consoleOutput"></div>
              <div class="input-group mt-3">
                <input type="text" id="consoleInput" class="form-control" placeholder="Enter command..." onkeydown="if(event.key==='Enter') sendConsoleInput()">
                <button class="btn btn-primary" onclick="sendConsoleInput()">
                  <i class="bi bi-send"></i> Send
                </button>
              </div>
              <small class="text-muted mt-2 d-block">
                Tip: Use the quick menu buttons or type commands directly. Press Enter to send.
              </small>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <script>
    // Initialize map
    var map = L.map('map').setView([45.4, -75.6], 5);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 13,
      attribution: 'OpenStreetMap contributors'
    }).addTo(map);

    var markers = {};
    var frameModal = new bootstrap.Modal(document.getElementById('frameModal'));
    var frameCollapseElement = document.getElementById('frameCollapse');
    var frameCollapseIcon = document.getElementById('frameCollapseIcon');
    if (frameCollapseElement && frameCollapseIcon) {
      frameCollapseElement.addEventListener('hide.bs.collapse', function () {
        frameCollapseIcon.classList.remove('bi-chevron-up');
        frameCollapseIcon.classList.add('bi-chevron-down');
      });
      frameCollapseElement.addEventListener('show.bs.collapse', function () {
        frameCollapseIcon.classList.remove('bi-chevron-down');
        frameCollapseIcon.classList.add('bi-chevron-up');
      });
    }

    function updateUI() {
      fetch('/api/frames')
        .then(response => response.json())
        .then(data => {
          document.getElementById('frameCount').textContent = data.length + ' frames';
          updateMap(data);
          updateFrameTable(data);
        })
        .catch(err => console.error('Error fetching frames:', err));
      
      fetch('/api/nodes')
        .then(response => response.json())
        .then(nodes => {
          updateNodeList(nodes);
          updateNodeSelector(nodes);
        })
        .catch(err => console.error('Error fetching nodes:', err));

      fetch('/api/photos')
        .then(response => response.json())
        .then(photos => updatePhotoList(photos))
        .catch(err => console.error('Error fetching photos:', err));
    }

    function calculateDistance(loc1, loc2) {
      if (!loc1 || !loc2 || loc1.length !== 2 || loc2.length !== 2) return null;
      const [lat1, lon1] = loc1;
      const [lat2, lon2] = loc2;
      const R = 6371;
      const dLat = (lat2 - lat1) * Math.PI / 180;
      const dLon = (lon2 - lon1) * Math.PI / 180;
      const a = 
        Math.sin(dLat/2) * Math.sin(dLat/2) +
        Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
        Math.sin(dLon/2) * Math.sin(dLon/2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
      const distance = R * c;
      return distance.toFixed(2);
    }

    function updateMap(frames) {
      Object.values(markers).forEach(marker => map.removeLayer(marker));
      markers = {};
      frames.forEach(frame => {
        if (frame.location) {
          const nodeId = `${frame.from_call}:${frame.from_port}`;
          const isLocal = frame.is_local || false;
          const portLabel = frame.from_port ? `<span class="badge bg-secondary ms-1">Port ${frame.from_port}</span>` : '';
          if (!markers[nodeId]) {
            const icon = L.divIcon({
              className: `custom-marker ${isLocal ? 'local-marker' : ''}`,
              html: `<div class="marker-pin ${isLocal ? 'local' : ''}"></div>`,
              iconSize: [20, 20],
              iconAnchor: [10, 20],
              popupAnchor: [0, -20]
            });
            const marker = L.marker([frame.location[0], frame.location[1]], { icon })
              .bindPopup(`
                <b>${frame.from_call || 'Unknown'} ${isLocal ? '(This Device)' : ''}</b>${portLabel}<br>
                ${isLocal ? '<span class="badge bg-primary">This Device</span><br>' : ''}
                ${frame.rssi ? `Signal: ${frame.rssi} dBm<br>` : ''}
                ${frame.timestamp ? `Last seen: ${new Date(frame.timestamp).toLocaleString()}<br>` : ''}
                ${frame.hop_count !== undefined ? `Hops: ${frame.hop_count}<br>` : ''}
                ${frame.flags !== undefined ? `Flags: 0x${frame.flags.toString(16).padStart(2, '0')}<br>` : ''}
                <small>${frame.location[0].toFixed(4)}, ${frame.location[1].toFixed(4)}</small>
              `)
              .addTo(map);
            markers[nodeId] = marker;
          }
        }
      });
      const layers = Object.values(markers);
      if (window.localNodeMarker) {
        layers.push(window.localNodeMarker);
      }
      if (layers.length > 0) {
        const group = new L.featureGroup(layers);
        map.fitBounds(group.getBounds().pad(0.1));
      }
    }
async function loadNodeInfo() {
  try {
    console.log("Loading node info...");
    const r = await fetch("/api/nodeinfo");
    
    if (!r.ok) {
      throw new Error(`HTTP error! status: ${r.status}`);
    }
    
    const info = await r.json();
    console.log("Node info received:", info);

    // Parse coordinates with validation
    const lat = parseFloat(info.Latitude || '0');
    const lon = parseFloat(info.Longitude || '0');

    const fromCallInput = document.getElementById('photoFromCall');
    if (fromCallInput && info['Station Callsign']) {
      fromCallInput.value = info['Station Callsign'];
    }
    
    // Only proceed if we have valid coordinates
    if (isNaN(lat) || isNaN(lon) || lat === 0 || lon === 0) {
      console.warn("Invalid or missing coordinates in node info");
      return;
    }

    console.log(`Creating marker at ${lat}, ${lon}`);
    
    // Create a custom icon for the local node using CSS-based marker
    const localIcon = L.divIcon({
      className: 'custom-marker local-marker',
      html: '<div class=\"marker-pin local\"></div>',
      iconSize: [20, 20],
      iconAnchor: [10, 20],
      popupAnchor: [0, -20]
    });

    // Remove any existing local node marker
    if (window.localNodeMarker) {
      map.removeLayer(window.localNodeMarker);
    }

    // Create and store the marker
    window.localNodeMarker = L.marker([lat, lon], { 
      icon: localIcon,
      zIndexOffset: 1000 // Ensure local node is always on top
    });
    
    // Add marker to map and bind popup
    window.localNodeMarker
      .addTo(map)
      .bindPopup(`
        <b>${info['Station Callsign'] || 'Unknown Station'}</b><br>
        ${info['RF Frequency'] ? `${info['RF Frequency']} MHz<br>` : ''}
        ${info['Description'] || 'No description available'}<br>
        <small>${lat.toFixed(4)}, ${lon.toFixed(4)}</small>
      `);

    // Focus map on the node location
    map.setView([lat, lon], 11);
    console.log("Map view updated to local node location");

    // Update header with node info
    const header = document.getElementById("header");
    if (header) {
      const callsign = info['Station Callsign'] || 'Unknown';
      const freq = info['RF Frequency'] ? `@ ${info['RF Frequency']} MHz` : '';
      header.textContent = `${callsign} ${freq}`.trim();
    }
  } catch (e) {
    console.error("loadNodeInfo failed:", e);
  }
}

loadNodeInfo();

    function updateFrameTable(frames) {
      const tbody = document.getElementById('frameTable');
      if (!tbody) return;
      tbody.innerHTML = '';
      frames.slice(0, 50).forEach((frame, index) => {
        try {
          const fromLabel = frame.from_call || 'N/A';
          const toLabel = frame.to_call || 'N/A';
          const row = document.createElement('tr');
          row.className = 'frame-row';
          row.onclick = () => showFrameDetails(frame);
          const typeClass = getTypeClass(frame.coding || 0);
          const typeBadge = `<span class="badge ${typeClass}">${getTypeName(frame.coding || 0)}</span>`;
          row.innerHTML = `
            <td>${new Date(frame.timestamp).toLocaleTimeString()}</td>
            <td>${fromLabel}</td>
            <td>${toLabel}</td>
            <td>${typeBadge}</td>
            <td>${frame.hop_count || 0}</td>
            <td>0x${(frame.flags || 0).toString(16).padStart(2, '0')}</td>
            <td>${frame.raw_data ? Math.floor(frame.raw_data.length/2) : 0} B</td>
          `;
          tbody.appendChild(row);
        } catch (e) {
          console.error('Error rendering frame', index, ':', e, frame);
        }
      });
    }

    function getSignalStrengthClass(rssi) {
      if (rssi === undefined || rssi === null) return 'signal-unknown';
      if (rssi >= -70) return 'signal-strong';
      if (rssi >= -85) return 'signal-medium';
      return 'signal-weak';
    }

    function formatSignalStrength(rssi) {
      if (rssi === undefined || rssi === null) return 'N/A';
      return `${rssi} dBm`;
    }

    let localNodeId = null;

    function formatLocation(location) {
      if (!location || !Array.isArray(location) || location.length !== 2) return 'Unknown';
      return `${location[0].toFixed(4)}, ${location[1].toFixed(4)}`;
    }

    function splitNodeId(id) {
      if (!id) return { call: id || 'Unknown', port: '' };
      const parts = String(id).split(':');
      return {
        call: parts[0] || id,
        port: parts[1] || ''
      };
    }

    function updateNodeList(nodes) {
      const nodeList = document.getElementById('nodeList');
      nodeList.innerHTML = '';
      Object.entries(nodes).forEach(([id, node]) => {
        if (node.is_local) {
          localNodeId = id;
          return;
        }
      });

      if (localNodeId && nodes[localNodeId]) {
        const localNode = nodes[localNodeId];
        const { call: localCall, port: localPort } = splitNodeId(localNodeId);
        const localItem = document.createElement('div');
        localItem.className = 'list-group-item list-group-item-primary';
        localItem.innerHTML = `
          <div class="local-node">
            <div class="d-flex justify-content-between align-items-center">
              <div>
                <strong>${localCall} <span class="badge bg-primary node-badge">This Device</span></strong><br>
                <div class="location-info">
                  ${localPort ? `<span class="me-2"><i class="bi bi-plug"></i> Port ${localPort}</span>` : ''}
                  <i class="bi bi-geo-alt"></i> ${formatLocation(localNode.location)}
                </div>
              </div>
              <div class="text-end">
                <span class="badge bg-primary">${localNode.frame_count || 0}</span>
              </div>
            </div>
          </div>
        `;
        nodeList.appendChild(localItem);
        const separator = document.createElement('div');
        separator.className = 'list-group-item py-1 bg-light';
        separator.innerHTML = '<small class="text-muted">REMOTE NODES</small>';
        nodeList.appendChild(separator);
      }

      Object.entries(nodes).forEach(([id, node]) => {
        if (id === localNodeId) return;
        const lastSeen = node.last_seen ? new Date(node.last_seen).toLocaleTimeString() : 'Never';
        const signalClass = getSignalStrengthClass(node.rssi);
        const signalText = formatSignalStrength(node.rssi);
        const { call, port } = splitNodeId(id);
        const distanceInfo = localNodeId && node.location && nodes[localNodeId]?.location 
          ? calculateDistance(nodes[localNodeId].location, node.location) 
          : null;
        const item = document.createElement('div');
        item.className = 'list-group-item list-group-item-action';
        item.innerHTML = `
          <div class="d-flex justify-content-between align-items-start">
            <div>
              <div class="d-flex align-items-center">
                <strong>${call}</strong>
                ${port ? `<span class="badge bg-secondary node-badge">Port ${port}</span>` : ''}
                ${node.is_local ? '<span class="badge bg-primary node-badge">This Device</span>' : ''}
              </div>
              <div class="location-info">
                <i class="bi bi-geo-alt"></i> ${formatLocation(node.location)}
                ${distanceInfo ? `<br><i class="bi bi-arrow-right"></i> ${distanceInfo} km away` : ''}
              </div>
              <small class="text-muted">Last: ${lastSeen}</small>
            </div>
            <div class="text-end">
              <span class="badge bg-primary">${node.frame_count || 0}</span>
            </div>
          </div>
        `;
        nodeList.appendChild(item);
      });
    }

    function getTypeClass(coding) {
      const type = coding & 0x0F;
      if (type === 4) return 'badge-beacon';
      if (type === 0) return 'badge-text';
      if (type === 3 || type === 5) return 'badge-data';
      return 'badge-unknown';
    }

    function getTypeName(coding) {
      const types = {
        0: 'Text', 1: 'Audio', 2: 'Video', 3: 'Data', 4: 'Beacon',
        5: 'IP', 6: 'AX.25', 7: 'DTMF', 8: 'DMR', 9: 'D-Star',
        10: 'P25', 11: 'NXDN', 12: 'M17', 15: 'Cmd'
      };
      return types[coding & 0x0F] || 'Unk';
    }

    function showFrameDetails(frame) {
      document.getElementById('frameDetails').textContent = JSON.stringify(frame, null, 2);
      frameModal.show();
    }

    // Search functionality
    document.getElementById('searchInput').addEventListener('input', (e) => {
      const searchTerm = e.target.value.toLowerCase();
      const rows = document.querySelectorAll('#frameTable tr');
      rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchTerm) ? '' : 'none';
      });
    });

    // Chat state
    let selectedNode = null;

    // Chat functions
    function refreshChat() {
      if (!selectedNode) return;
      
      fetch(`/api/chat?node=${encodeURIComponent(selectedNode)}&limit=100`)
        .then(r => r.json())
        .then(msgs => {
          const box = document.getElementById('chatMessages');
          if (msgs.length === 0) {
            box.innerHTML = '<div class="text-center text-muted py-4"><p>No messages yet. Start the conversation!</p></div>';
            return;
          }
          // msgs are returned newest-first; reverse to show oldest at top
          const html = msgs.slice().reverse().map(m => {
            const isOutgoing = m.text.startsWith('> ');
            const msgClass = isOutgoing ? 'text-end' : 'text-start';
            const bubbleClass = isOutgoing ? 'bg-primary text-white' : 'bg-white';
            const text = isOutgoing ? m.text.substring(2) : m.text;
            return `
              <div class="${msgClass} mb-2">
                <div class="d-inline-block px-3 py-2 rounded ${bubbleClass}" style="max-width: 70%;">
                  <div>${escapeHtml(text)}</div>
                  <small class="${isOutgoing ? 'text-white-50' : 'text-muted'}" style="font-size: 0.75rem;">${new Date(m.timestamp).toLocaleTimeString()}</small>
                </div>
              </div>
            `;
          }).join('');
          box.innerHTML = html;
          box.scrollTop = box.scrollHeight;
        })
        .catch(err => console.error('Chat fetch error', err));
    }

    function updateNodeSelector(nodes) {
      const select = document.getElementById('chatNodeSelect');
      const currentValue = select.value;
      
      // Build options list - always include "broadcast" first
      const options = [
        '<option value="">Select a node...</option>',
        '<option value="broadcast">📡 Broadcast (All Messages)</option>'
      ];
      Object.keys(nodes).sort().forEach(nodeId => {
        const { call } = splitNodeId(nodeId);
        const selected = nodeId === currentValue ? 'selected' : '';
        options.push(`<option value="${nodeId}" ${selected}>${call}</option>`);
      });

      select.innerHTML = options.join('');
      
      // Restore selection if it still exists
      if (currentValue) {
        select.value = currentValue;
      }
    }

    function updatePhotoList(photos) {
      const container = document.getElementById('photoList');
      container.innerHTML = '';

      if (!photos || photos.length === 0) {
        container.innerHTML = '<div class="list-group-item text-muted small">No photos received yet</div>';
        return;
      }

      photos.forEach(photo => {
        const sizeKb = (photo.size / 1024).toFixed(1);
        const item = document.createElement('a');
        item.className = 'list-group-item list-group-item-action';
        item.href = `/api/photos/${encodeURIComponent(photo.id)}`;
        item.target = '_blank';
        item.innerHTML = `
          <div class="d-flex justify-content-between align-items-start">
            <div>
              <strong><i class="bi bi-image me-2"></i>${escapeHtml(photo.original_name || photo.stored_name)}</strong>
              <div class="text-muted small">${photo.source} • ${photo.received_at}</div>
            </div>
            <span class="badge bg-secondary">${sizeKb} KB</span>
          </div>
        `;
        container.appendChild(item);
      });
    }

    let nodeSettingsCache = {};
    const nodeSettingsInputsSelector = '[data-setting-key]';

    function setNodeSettingsStatus(message, level = 'secondary') {
      const statusBox = document.getElementById('nodeSettingsStatus');
      if (!statusBox) return;
      if (!message) {
        statusBox.classList.add('d-none');
        return;
      }
      statusBox.className = `alert alert-${level} small mt-2`;
      statusBox.textContent = message;
      statusBox.classList.remove('d-none');
    }

    function populateNodeSettingsForm(settings) {
      nodeSettingsCache = settings || {};
      const inputs = document.querySelectorAll(nodeSettingsInputsSelector);
      inputs.forEach(input => {
        const key = input.dataset.settingKey;
        if (!key) return;
        const value = nodeSettingsCache[key];
        input.value = value !== undefined ? value : '';
      });
    }

    async function refreshNodeSettings() {
      try {
        const response = await fetch('/api/settings');
        if (!response.ok) {
          const text = await response.text();
          throw new Error(text || `HTTP ${response.status}`);
        }
        const data = await response.json();
        if (data.status !== 'ok') {
          throw new Error(data.error || 'Settings command failed');
        }
        populateNodeSettingsForm(data.settings || {});
        setNodeSettingsStatus('Settings synced from hat.', 'secondary');
      } catch (err) {
        console.error('Settings fetch error', err);
        setNodeSettingsStatus(`Error loading settings: ${err.message || err}`, 'danger');
      }
    }

    async function saveNodeSettings() {
      const saveBtn = document.getElementById('nodeSettingsSaveBtn');
      const inputs = document.querySelectorAll(nodeSettingsInputsSelector);
      const updates = [];
      inputs.forEach(input => {
        const key = input.dataset.settingKey;
        if (!key) return;
        const newValue = input.value.trim();
        const currentValue = nodeSettingsCache[key] !== undefined ? String(nodeSettingsCache[key]).trim() : '';
        if (newValue !== currentValue) {
          updates.push({ key, value: newValue });
        }
      });

      if (!updates.length) {
        setNodeSettingsStatus('No changes to apply.', 'info');
        return;
      }

      if (saveBtn) {
        saveBtn.disabled = true;
      }
      setNodeSettingsStatus('Applying settings...', 'info');

      try {
        for (const update of updates) {
          const response = await fetch('/api/settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(update)
          });
          const data = await response.json();
          if (!response.ok || data.status !== 'ok') {
            throw new Error(data.error || `Failed to update ${update.key}`);
          }
        }
        await refreshNodeSettings();
        setNodeSettingsStatus('Settings queued for the hat. Monitor pending file for application.', 'success');
      } catch (err) {
        console.error('Settings save error', err);
        setNodeSettingsStatus(`Apply failed: ${err.message || err}`, 'danger');
      } finally {
        if (saveBtn) {
          saveBtn.disabled = false;
        }
      }
    }

    const photoStatusBox = document.getElementById('photoUploadStatus');
    const photoForm = document.getElementById('photoUploadForm');

    function setPhotoStatus(message, level = 'secondary') {
      if (!photoStatusBox) return;
      photoStatusBox.className = `alert alert-${level} small mt-3`;
      if (!message) {
        photoStatusBox.classList.add('d-none');
      } else {
        photoStatusBox.textContent = message;
        photoStatusBox.classList.remove('d-none');
      }
    }

    if (photoForm) {
      photoForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const fileInput = document.getElementById('photoFile');
        if (!fileInput || fileInput.files.length === 0) {
          setPhotoStatus("Please choose an image to send.", "warning");
          return;
        }

        const submitBtn = photoForm.querySelector('button[type="submit"]');
        if (submitBtn) {
          submitBtn.disabled = true;
          submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Sending...';
        }
        setPhotoStatus("Sending photo over RF link...", "info");

        try {
          const formData = new FormData(photoForm);
          const response = await fetch('/api/photos/send', {
            method: 'POST',
            body: formData
          });

          const result = await response.json();
          if (!response.ok) {
            throw new Error(result.error || `Upload failed (${response.status})`);
          }

          setPhotoStatus(
            `Queued ${result.filename} (${(result.bytes / 1024).toFixed(1)} KB) in ${result.chunks} frames (file_id=0x${result.file_id.toString(16).padStart(4, '0')}).`,
            "success"
          );
          photoForm.reset();
          const fromField = document.getElementById('photoFromCall');
          if (fromField) fromField.value = result.from;
          const toCallField = document.getElementById('photoToCall');
          if (toCallField) toCallField.value = result.to;
          const connField = document.getElementById('photoConnectionless');
          if (connField) connField.checked = result.connectionless;
          const repeatField = document.getElementById('photoRepeatable');
          if (repeatField) repeatField.checked = result.repeatable;
          setTimeout(updateUI, 1500);
        } catch (err) {
          console.error('Photo upload error', err);
          setPhotoStatus(err.message || 'Photo send failed.', 'danger');
        } finally {
          if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="bi bi-upload"></i> Send Photo';
          }
        }
      });
    }

    function escapeHtml(unsafe) {
      return unsafe
           .replace(/&/g, "&amp;")
           .replace(/</g, "&lt;")
           .replace(/>/g, "&gt;")
           .replace(/"/g, "&quot;")
           .replace(/'/g, "&#039;");
    }

    document.getElementById('chatNodeSelect').onchange = (e) => {
      selectedNode = e.target.value;
      const input = document.getElementById('chatInput');
      const sendBtn = document.getElementById('chatSend');
      
      if (selectedNode) {
        input.disabled = false;
        sendBtn.disabled = false;
        input.placeholder = `Message ${selectedNode}...`;
        input.focus();
        refreshChat();
      } else {
        input.disabled = true;
        sendBtn.disabled = true;
        input.placeholder = 'Type message...';
        document.getElementById('chatMessages').innerHTML = `
          <div class="text-center text-muted py-4">
            <i class="bi bi-chat-dots" style="font-size: 2rem;"></i>
            <p class="mt-2">Select a node to start chatting</p>
          </div>
        `;
      }
    };

    document.getElementById('chatSend').onclick = () => {
      if (!selectedNode) return;
      
      const input = document.getElementById('chatInput');
      const text = input.value.trim();
      if (!text) return;
      
      fetch('/api/chat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message: text, node: selectedNode})
      }).then(() => { input.value = ''; refreshChat(); })
        .catch(err => console.error('Chat send error', err));
    };

    document.getElementById('chatInput').addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        document.getElementById('chatSend').click();
      }
    });

    // Console functions
    let consoleAutoScroll = true;
    
    async function postConsoleCommand(cmd) {
      const response = await fetch('/api/console/write', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({cmd})
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(`Console write failed (${response.status}): ${text}`);
      }
      return response.json().catch(() => ({}));
    }
    
    function sendConsoleCommand(cmd) {
      if (!cmd) return;
      
      lastCommandTime = Date.now();
      isTyping = false; // User has finished typing
      
      // Add command echo to console immediately
      const output = document.getElementById('consoleOutput');
      output.textContent += `\n> ${cmd}\n`;
      output.scrollTop = output.scrollHeight;
      
      // Disable input and show loading
      const input = document.getElementById('consoleInput');
      input.disabled = true;
      
      postConsoleCommand(cmd)
        .then(data => {
          console.log('Console command sent:', data);
          // Small delay before re-enabling input and refreshing
          setTimeout(() => {
            input.disabled = false;
            input.focus();
            // Wait a bit longer before refreshing to allow command to process
            setTimeout(refreshConsole, 300);
          }, 200);
        })
        .catch(err => {
          console.error('Console command error:', err);
          input.disabled = false;
          input.focus();
        });
    }
    
    function sendConsoleInput() {
      const input = document.getElementById('consoleInput');
      const cmd = input.value.trim();
      if (!cmd) return;
      
      // Clear input immediately for better UX
      input.value = '';
      
      sendConsoleCommand(cmd);
    }
    
    // Handle typing state
    document.getElementById('consoleInput').addEventListener('focus', () => {
      isTyping = true;
    });
    
    document.getElementById('consoleInput').addEventListener('blur', () => {
      isTyping = false;
      // Refresh when input loses focus
      refreshConsole();
    });
    
    // Handle Enter key in console input
    document.getElementById('consoleInput').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        sendConsoleInput();
      }
    });
    
    function clearConsole() {
      document.getElementById('consoleOutput').textContent = '';
    }
    
    function refreshConsole() {
      if (isTyping) return; // Don't refresh if user is typing
      
      fetch('/api/console/read')
        .then(r => r.json())
        .then(data => {
          if (data.output) {
            const output = document.getElementById('consoleOutput');
            const currentPosition = output.scrollTop;
            const isAtBottom = (output.scrollHeight - output.clientHeight - currentPosition) < 10;
            
            output.textContent += data.output;
            
            // Only auto-scroll if we were already at the bottom
            if (consoleAutoScroll && isAtBottom) {
              output.scrollTop = output.scrollHeight;
            }
          }
        })
        .catch(err => console.error('Console read error:', err));
    }
    
    // Detect if user scrolls up (disable auto-scroll)
    document.getElementById('consoleOutput').addEventListener('scroll', function() {
      const elem = this;
      consoleAutoScroll = (elem.scrollHeight - elem.scrollTop - elem.clientHeight) < 50;
    });
    
    function restartServer() {
      if (!confirm('Are you sure you want to restart the IP400 server? This will disconnect all active sessions briefly.')) {
        return;
      }
      
      fetch('/api/server/restart', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'}
      }).then(r => r.json())
        .then(data => {
          alert('Server restart initiated. The page will reload in 5 seconds...');
          setTimeout(() => {
            window.location.reload();
          }, 5000);
        })
        .catch(err => {
          console.error('Restart error:', err);
          alert('Server restart initiated. The page will reload in 5 seconds...');
          setTimeout(() => {
            window.location.reload();
          }, 5000);
        });
    }

    // Mode toggle event handlers for settings modal
    let isConsoleActive = false;
    let consoleRefreshInterval;
    let isTyping = false;
    let lastCommandTime = 0;
    
    // Function to refresh console only if not currently typing
    function safeRefreshConsole() {
      if (!isTyping && (Date.now() - lastCommandTime > 1000)) { // 1s cooldown after commands
        refreshConsole();
      }
    }
    
    const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
    
    document.getElementById('settingsModal').addEventListener('show.bs.modal', async () => {
      console.log('[MODE] Switching to console mode...');
      isConsoleActive = true;
      
      // Clear any existing output
      document.getElementById('consoleOutput').textContent = '';
      
      try {
        await refreshNodeSettings();
        const response = await fetch('/api/mode', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({mode: 'console'})
        });
        if (!response.ok) {
          const text = await response.text();
          throw new Error(`Mode switch failed (${response.status}): ${text}`);
        }
        
        await delay(200);
        await postConsoleCommand('\x1A');
        await delay(500);
        await postConsoleCommand('');
        await delay(500);
        
        // Start console refresh only when modal is open and console is ready
        consoleRefreshInterval = setInterval(safeRefreshConsole, 1000); // Slower refresh rate
        refreshConsole();
      } catch (err) {
        console.error('Console mode activation error:', err);
        isConsoleActive = false;
        if (consoleRefreshInterval) {
          clearInterval(consoleRefreshInterval);
          consoleRefreshInterval = null;
        }
      }
    });

    document.getElementById('settingsModal').addEventListener('hidden.bs.modal', async () => {
      console.log('[MODE] Returning to chat mode...');
      isConsoleActive = false;
      
      // Stop console refresh when modal is closed
      if (consoleRefreshInterval) {
        clearInterval(consoleRefreshInterval);
        consoleRefreshInterval = null;
      }
      
      try {
        await postConsoleCommand('');
        await delay(200);
        await postConsoleCommand('C');
        await delay(300);
      } catch (err) {
        console.error('Chat mode preparation error:', err);
      }
      
      try {
        const response = await fetch('/api/mode', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({mode: 'chat'})
        });
        if (!response.ok) {
          const text = await response.text();
          throw new Error(`Mode switch failed (${response.status}): ${text}`);
        }
      } catch (err) {
        console.error('Chat mode switch error:', err);
      }
    });

    // Initial load and periodic refresh
    updateUI();
    setInterval(updateUI, 2000);
    refreshChat();
    setInterval(refreshChat, 1500);
    // Don't start console refresh by default, only when modal is open
  </script>
</body>
</html>
    """)

# API Endpoints

@app.route("/api/nodeinfo")
def api_nodeinfo():
    """Return this station's local node info."""
    global node_info
    
    # Always try to get fresh data first
    fresh_info = read_ip400_node_info()
    
    # If we got fresh data, update our node_info
    if fresh_info:
        node_info = fresh_info
    
    # If we still don't have info, try to get it from the node_info global
    if not node_info and node_info_cache:
        node_info = node_info_cache
    
    # If we still don't have info, try to read from the temp file directly
    if not node_info and os.path.exists("/tmp/ip400_node.json"):
        try:
            with open("/tmp/ip400_node.json", "r") as f:
                node_info = json.load(f)
        except Exception as e:
            print(f"[API] Error loading node info from temp file: {e}")
    
    # If we still don't have info, try the local cache
    if not node_info and os.path.exists("nodeinfo.json"):
        try:
            with open("nodeinfo.json", "r") as f:
                node_info = json.load(f)
        except Exception as e:
            print(f"[API] Error loading node info from cache: {e}")
    
    # Ensure required fields exist with defaults
    response = {
        'Station Callsign': node_info.get('Station Callsign', 'UNKNOWN') if node_info else 'UNKNOWN',
        'Description': node_info.get('Description', '') if node_info else '',
        'RF Frequency': node_info.get('RF Frequency', '0.0') if node_info else '0.0',
        'Latitude': node_info.get('Latitude', '0.0') if node_info else '0.0',
        'Longitude': node_info.get('Longitude', '0.0') if node_info else '0.0',
        'Grid Square': node_info.get('Grid Square', '') if node_info else '',
        'Firmware': node_info.get('Firmware', '0.0') if node_info else '0.0'
    }
    
    return jsonify(response)

@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    try:
        response = local_command_manager.send_command("get_settings")
    except LocalCommandTimeout:
        return jsonify({"error": "timeout waiting for settings"}), 504
    status = response.get("status", "error")
    if status != "ok":
        return jsonify({"error": response.get("message", "command failed"), "status": status}), 500
    data = response.get("data", "{}")
    try:
        settings = json.loads(data)
    except Exception:
        settings = {}
    return jsonify({"status": "ok", "settings": settings})

@app.route("/api/settings", methods=["POST"])
def api_settings_set():
    global node_info
    payload = request.get_json(force=True)
    key = (payload.get("key") or "").strip()
    value = payload.get("value", "")
    if not key:
        return jsonify({"error": "missing key"}), 400
    try:
        response = local_command_manager.send_command("set_param", {"key": key, "value": str(value)})
    except LocalCommandTimeout:
        return jsonify({"error": "timeout applying setting"}), 504
    status = response.get("status", "error")
    if status != "ok":
        return jsonify({"error": response.get("message", "command failed"), "status": status}), 500
    if isinstance(node_info, dict):
        node_info[key] = value
    node_info_cache[key] = value
    try:
        with open("nodeinfo.json", "w") as f:
            json.dump(node_info_cache, f, indent=2)
    except Exception as exc:
        print(f"[SETTINGS] Failed to update cache file: {exc}")
    return jsonify({"status": "ok", "key": key, "value": value})

@app.route("/api/frames")
def api_frames():
    limit = min(int(request.args.get('limit', 50)), 100)
    return jsonify([b.to_dict() for b in list(frame_history)[:limit]])

@app.route("/api/nodes")
def api_nodes():
    return jsonify(dict(node_history))

@app.route("/api/chat", methods=["GET", "POST"])
def api_chat():
    if request.method == "POST":
        data = request.get_json(force=True)
        msg = (data.get("message", "") or "").strip()
        node = (data.get("node", "") or "").strip()
        if not msg:
            return jsonify({"error": "empty message"}), 400
        if not node:
            return jsonify({"error": "no node specified"}), 400
        # queue the outgoing message with node info (non-blocking)
        chat_outgoing.put({"node": node, "message": msg})
        # Add to chat history immediately for display
        entry = {"timestamp": datetime.utcnow().isoformat() + 'Z', "text": f"> {msg}"}
        chat_history[node].appendleft(entry)
        return jsonify({"status": "queued", "message": msg, "node": node}), 200
    else:
        node = request.args.get('node', '').strip()
        if not node:
            return jsonify({"error": "no node specified"}), 400
        limit = min(int(request.args.get('limit', 100)), CHAT_MAX_HISTORY)
        # Return newest-first for convenience
        return jsonify(list(chat_history[node])[:limit])

@app.route("/api/photos")
def api_photos():
    return jsonify(photo_manager.list_photos())

@app.route("/api/photos/send", methods=["POST"])
def api_photo_send():
    if "photo" not in request.files:
        return jsonify({"error": "missing photo file"}), 400

    file_storage = request.files["photo"]
    image_bytes = file_storage.read()
    if not image_bytes:
        return jsonify({"error": "empty file"}), 400

    from_call = (request.form.get("fromCall") or get_local_callsign()).strip().upper() or get_local_callsign()
    to_call = (request.form.get("toCall") or "BROADCAST").strip().upper() or "BROADCAST"

    def parse_int(field: str, default: int) -> int:
        value = request.form.get(field, "")
        if not value:
            return default
        try:
            return int(value, 0)
        except ValueError:
            raise PhotoSendError(f"Invalid integer for {field}")

    try:
        from_port = parse_int("fromPort", PHOTO_DEFAULT_FROM_PORT)
        to_port = parse_int("toPort", PHOTO_DEFAULT_TO_PORT)
        max_payload = parse_int("maxPayload", PHOTO_MAX_PAYLOAD)
    except PhotoSendError as exc:
        return jsonify({"error": str(exc)}), 400

    delay_value = request.form.get("delay", "")
    try:
        delay = float(delay_value) if delay_value else PHOTO_DELAY
    except ValueError:
        return jsonify({"error": "Invalid delay value"}), 400

    resize_value = request.form.get("resize", "").strip()
    quality_value = request.form.get("quality", "")
    try:
        quality = int(quality_value) if quality_value else 75
    except ValueError:
        return jsonify({"error": "Invalid quality value"}), 400

    resize = None
    if resize_value:
        try:
            resize = parse_resize(resize_value)
        except PhotoSendError as exc:
            return jsonify({"error": str(exc)}), 400

    repeatable = request.form.get("repeatable") == "on"
    connectionless = request.form.get("connectionless", "on") == "on"

    try:
        result = send_photo_bytes(
            image_bytes=image_bytes,
            filename=file_storage.filename or "upload.bin",
            resize=resize,
            quality=quality,
            max_payload=max_payload,
            delay=delay,
            udp_host=PHOTO_SPI_HOST,
            udp_port=PHOTO_SPI_PORT,
            from_call=from_call,
            from_port=from_port,
            to_call=to_call,
            to_port=to_port,
            repeatable=repeatable,
            connectionless=connectionless,
            file_id=None,
        )
    except PhotoSendError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        app.logger.exception("[PHOTO] Unexpected send error during upload")
        return jsonify({"error": f"internal error: {exc}"}), 500

    response = {
        "status": "sent",
        "from": from_call,
        "to": to_call,
        "chunks": result["chunks"],
        "bytes": result["bytes"],
        "file_id": result["file_id"],
        "filename": result["filename"],
        "delay": delay,
        "max_payload": max_payload,
        "repeatable": repeatable,
        "connectionless": connectionless,
    }
    return jsonify(response), 200

@app.route("/api/photos/<photo_id>")
def api_photo_download(photo_id):
    info = photo_manager.get_photo(photo_id)
    if not info:
        return jsonify({"error": "not found"}), 404
    download_name = info.get("original_name") or info["stored_name"]
    return send_from_directory(
        photo_manager.storage_dir,
        info["stored_name"],
        as_attachment=True,
        download_name=download_name,
    )

@app.route("/api/console/read")
def api_console_read():
    out = ""
    while not console_output.empty():
        out += console_output.get()
    return jsonify({"output": out})

@app.route("/api/console/write", methods=["POST"])
def api_console_write():
    data = request.get_json(force=True)
    cmd = data.get("cmd", "").strip()
    if not console_active.is_set():
        return jsonify({"error": "console not active"}), 409
    console_commands.put(cmd)
    return jsonify({"status": "ok", "sent": cmd})

@app.route("/api/mode", methods=["POST"])
def api_mode_toggle():
    """Switch between chat and console modes."""
    data = request.get_json(force=True)
    mode = (data.get("mode", "") or "").lower()
    if mode not in ("chat", "console"):
        return jsonify({"error": "invalid mode"}), 400

    if serial is None:
        return jsonify({"error": "pyserial not installed"}), 500

    if mode == "console":
        if console_active.is_set():
            return jsonify({"status": "ok", "mode": mode, "note": "already in console"}), 200
        # Pause chat thread and wait for confirmation
        chat_should_run.clear()
        if not chat_paused.wait(timeout=3.0):
            chat_should_run.set()  # Resume to avoid leaving chat halted
            return jsonify({"error": "timeout pausing chat thread"}), 503
        console_active.set()
        print("[MODE] Console mode activated")
        return jsonify({"status": "ok", "mode": mode}), 200

    # mode == "chat"
    if not console_active.is_set():
        chat_should_run.set()
        return jsonify({"status": "ok", "mode": mode, "note": "already in chat"}), 200

    console_active.clear()
    chat_should_run.set()
    # Wait briefly for chat thread to resume
    for _ in range(30):
        if not chat_paused.is_set():
            break
        time.sleep(0.1)
    print("[MODE] Chat mode reactivated")
    return jsonify({"status": "ok", "mode": mode}), 200

@app.route("/api/server/restart", methods=["POST"])
def api_server_restart():
    """Restart the server by exiting the process (systemd will restart it)"""
    import os
    import signal
    import threading
    
    def restart_delayed():
        time.sleep(1)
        print("[SERVER] Restart requested via API, exiting...")
        os.kill(os.getpid(), signal.SIGTERM)
    
    # Start restart in background thread to allow response to be sent
    threading.Thread(target=restart_delayed, daemon=True).start()
    return jsonify({"status": "restarting", "message": "Server will restart in 1 second"})

# ---------------------------
# Main
# ---------------------------

def main():
    import os
    udp_ip = os.getenv('IP400_UDP_IP', '0.0.0.0')
    udp_port = int(os.getenv('IP400_UDP_PORT', '9000'))
    web_host = os.getenv('IP400_WEB_HOST', '0.0.0.0')
    web_port = int(os.getenv('IP400_WEB_PORT', '5000'))

    global UDP_IP, UDP_PORT
    UDP_IP = udp_ip
    UDP_PORT = udp_port

    print(f"Starting IP400 Server...")
    print(f"UDP Listener: {udp_ip}:{udp_port}")
    print(f"Web Interface: http://{web_host}:{web_port}")
    print(f"Chat serial: {CHAT_PORT} @ {CHAT_BAUD}")
    
    # Read our node parameters once on boot (this will also populate /tmp/ip400_node.json)
    print("[BOOT] Reading local node info from menu A...")
    try:
        info = ip400_read_parameters()
        if info:
            print(f"[BOOT] Node {info.get('Station Callsign','UNKNOWN')} @ "
                  f"{info.get('Latitude','?')},{info.get('Longitude','?')} "
                  f"{info.get('RF Frequency','')} MHz")
        else:
            print("[BOOT] No node info read.")
    except Exception as e:
        print(f"[BOOT] Node info read failed: {e}")

    # Start UDP listener
    listener_thread = threading.Thread(target=udp_listener, daemon=True)
    listener_thread.start()

    # Start chat thread
    chat_thread = threading.Thread(target=ip400_chat_thread, daemon=True)
    chat_thread.start()

    # Start console thread
    console_thread = threading.Thread(target=ip400_console_thread, daemon=True)
    console_thread.start()

    # Start the web interface
    app.run(host=web_host, port=web_port, debug=False)

if __name__ == '__main__':
    main()

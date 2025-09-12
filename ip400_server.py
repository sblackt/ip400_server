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
from flask import Flask, render_template_string, jsonify, request

# Flask setup
app = Flask(__name__)

# Configuration
UDP_IP = "0.0.0.0"
UDP_PORT = 9000
MAX_HISTORY = 1000  # Maximum number of frames to keep in history

# Data structures
frame_history = deque(maxlen=MAX_HISTORY)
node_history = defaultdict(dict)  # node_id -> {last_seen, rssi, location, etc.}

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
            'raw_data': self.raw_data.hex(),
            'payload_hex': self.payload.hex(),
            'payload_ascii': self.payload.decode('ascii', errors='replace'),
        }
        # Ensure all values are JSON serializable
        for k, v in list(result.items()):
            if v is not None and not isinstance(v, (str, int, float, bool, list, dict)):
                result[k] = str(v)
        return result

def decode_excess40_callsign(call_bytes: bytes) -> str:
    if len(call_bytes) != 4:
        return "INVALID"

    try:
        value = struct.unpack('>I', call_bytes)[0]
        
        # This is likely the problem: the mapping is not a simple string.
        char_map = "0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ_-@"

        if value == 0xFFFFFFFF: return "BROADCAST"
        if value == 0: return "EMPTY"

        # Correct decoding logic:
        # Instead of using a simple string, we need to handle the character mapping carefully.
        # The value is built as: val = c1 + c2*40 + c3*40^2 + ...
        # So we extract from least significant to most significant.
        
        decoded_chars = []
        for i in range(6):
            if value == 0:
                break
            char_index = value % 40
            decoded_chars.append(char_map[char_index])
            value //= 40
        
        # The characters are extracted from right-to-left, so we reverse them.
        callsign = "".join(reversed(decoded_chars)).strip()

       
        value = struct.unpack('<I', call_bytes)[0]
        # value is now 3307105272

        decoded_chars = []
        for _ in range(6):
            if value == 0:
                break
            char_index = value % 40
            decoded_chars.append(char_map[char_index])
            value //= 40
        
        # Reverse and strip
        return "".join(reversed(decoded_chars)).strip()

    except Exception as e:
        return f"0x{call_bytes.hex()}"

def parse_gps_coords(coord_str: str) -> Optional[float]:
    """Convert NMEA-style coordinate string to decimal degrees.
    
    For latitude:  '4530.54000N' -> 45 + (30.54000/60) = 45.50900
    For longitude: '07711.46001W' -> 77 + (11.46001/60) = 77.19100
    """
    if not coord_str:
        return None
        
    try:
        # Get direction (last character)
        direction = coord_str[-1].upper()
        if direction not in 'NSEW':
            return None
            
        # Get numeric part (everything except direction)
        coord = coord_str[:-1]
        if not coord.replace('.', '').replace('-', '').isdigit():
            return None
        
        coord_float = float(coord)
        
        # For latitude (N/S) - DDMM.MMMM format
        if direction in 'NS':
            deg = int(coord_float // 100)
            minutes = coord_float - (deg * 100)
            dec_deg = deg + (minutes / 60.0)
            if direction == 'S':
                dec_deg = -dec_deg
            return round(dec_deg, 6)
            
        # For longitude (E/W) - DDDMM.MMMM format  
        elif direction in 'EW':
            deg = int(coord_float // 100)
            minutes = coord_float - (deg * 100)
            dec_deg = deg + (minutes / 60.0)
            if direction == 'W':
                dec_deg = -dec_deg
            return round(dec_deg, 6)
            
    except (ValueError, IndexError) as e:
        print(f"Error parsing coordinate '{coord_str}': {e}")
    return None

def parse_beacon_payload(payload: bytes) -> dict:
    """Parse beacon payload according to specification.
    
    Format: 'SOURCE,LATITUDE,LONGITUDE,SPEED,FIXTIME,GRIDSQUARE,'
    Example: 'FXD,4530.54000N,07711.46001W,,010610,FN15,'
    """
    try:
        # Decode payload and split by commas
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
        
        # Convert coordinates to decimal degrees
        if result['latitude_raw'] and result['longitude_raw']:
            lat = parse_gps_coords(result['latitude_raw'])
            lon = parse_gps_coords(result['longitude_raw'])
            if lat is not None and lon is not None:
                result['latitude'] = lat
                result['longitude'] = lon
        
        return result
        
    except Exception as e:
        print(f"Error parsing beacon payload: {e}")
        return {'raw': payload.decode('ascii', errors='replace')}

def get_packet_type_name(coding: int) -> str:
    """Get packet type name from coding field."""
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
    """Parse an IP400 frame according to the specification."""
    if len(frame) < 24:  # Minimum header size
        return None
        
    try:
        beacon = Beacon(
            timestamp=datetime.utcnow().isoformat() + 'Z',
            raw_data=frame
        )
        
        print(f"\nRaw frame ({len(frame)} bytes): {frame.hex()}")
        
        # Check for IP4C eye catcher (first 4 bytes)
        if not frame.startswith(b'IP4C'):
            print(f"Invalid eye catcher: {frame[:4]}")
            return None
        
        beacon.frame_type = "IP4C"
        
        # Parse header according to Table 5
        if len(frame) < 24:
            print("Frame too short for complete header")
            return None
            
        # Header fields (24 bytes total)
        # Eye: bytes 0-3 (already checked)
        # Status: byte 4
        beacon.status = frame[4]
        
        # Offset: bytes 5-6 (Hi, Lo)
        beacon.offset = (frame[5] << 8) | frame[6]
        
        # Length: bytes 7-8 (Hi, Lo) 
        beacon.length = (frame[7] << 8) | frame[8]
        
        # From Call: bytes 9-12 (4 bytes compressed)
        from_call_bytes = frame[9:13]
        beacon.from_call = decode_excess40_callsign(from_call_bytes)
        
        # From Port: bytes 13-14 (2 bytes)
        beacon.from_port = struct.unpack('>H', frame[13:15])[0]
        
        # To Call: bytes 15-18 (4 bytes compressed)
        to_call_bytes = frame[15:19]
        beacon.to_call = decode_excess40_callsign(to_call_bytes)
        
        # To Port: bytes 19-20 (2 bytes)
        beacon.to_port = struct.unpack('>H', frame[19:21])[0]
        
        # Coding: byte 21
        beacon.coding = frame[21]
        
        # Hop Count: byte 22
        beacon.hop_count = frame[22]
        
        # Flags: byte 23
        beacon.flags = frame[23]
        
        print(f"Parsed header:")
        print(f"  Status: {beacon.status}")
        print(f"  Offset: {beacon.offset}")
        print(f"  Length: {beacon.length}")
        print(f"  From: {beacon.from_call}:{beacon.from_port}")
        print(f"  To: {beacon.to_call}:{beacon.to_port}")
        print(f"  Coding: {beacon.coding} ({get_packet_type_name(beacon.coding)})")
        print(f"  Hop Count: {beacon.hop_count}")
        print(f"  Flags: 0x{beacon.flags:02x}")
        
        # Calculate where payload starts (after header + hop table)
        payload_start = 24
        
        # Check if hop table is present (flags bit 5)
        if beacon.flags & 0x20:
            hop_table_size = beacon.hop_count * 4  # 4 bytes per hop
            payload_start += hop_table_size
            print(f"  Hop table present: {hop_table_size} bytes")
        
        # Extract payload
        if payload_start < len(frame):
            beacon.payload = frame[payload_start:]
            print(f"Payload ({len(beacon.payload)} bytes): {beacon.payload.hex()}")
            
            # If this is a beacon packet, parse the payload
            if (beacon.coding & 0x0F) == 0x04:  # Beacon packet
                beacon_info = parse_beacon_payload(beacon.payload)
                print(f"Beacon info: {beacon_info}")
                
                # Extract location if available
                if 'latitude' in beacon_info and 'longitude' in beacon_info:
                    beacon.location = (beacon_info['latitude'], beacon_info['longitude'])
        else:
            print("No payload data")
            
        return beacon
        
    except Exception as e:
        print(f"Error parsing IP400 frame: {e}")
        import traceback
        traceback.print_exc()
        return None

def udp_listener():
    """Listen for UDP packets and process them."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"Listening on UDP {UDP_IP}:{UDP_PORT}...")
    
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            print(f"\nReceived {len(data)} bytes from {addr}")
            
            beacon = parse_ip400_frame(data)
            if beacon:
                print(f"Successfully parsed beacon from {beacon.from_call}:{beacon.from_port}")
                frame_history.appendleft(beacon)
                
                # Update node information
                node_id = f"{beacon.from_call}:{beacon.from_port}"
                node_history[node_id] = {
                    'last_seen': beacon.timestamp,
                    'rssi': beacon.rssi,
                    'location': beacon.location,
                    'frame_count': node_history.get(node_id, {}).get('frame_count', 0) + 1,
                    'last_data': data.hex(),
                    'packet_type': get_packet_type_name(beacon.coding)
                }
            else:
                print("Failed to parse frame as IP400")
                
        except Exception as e:
            print(f"Error in UDP listener: {e}")
            import traceback
            traceback.print_exc()

# Flask routes
@app.route("/")
def index():
    return render_template_string("""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>IP400 Network Monitor</title>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    #map { height: 400px; width: 100%; margin-bottom: 20px; }
    .signal-strength { 
        display: inline-block; 
        width: 12px; 
        height: 12px; 
        border-radius: 50%; 
        margin-right: 5px;
    }
    .signal-strong { background-color: #28a745; }
    .signal-medium { background-color: #ffc107; }
    .signal-weak { background-color: #dc3545; }
    .frame-row { cursor: pointer; }
    .frame-row:hover { background-color: #f8f9fa; }
    #frameTable { font-size: 0.9rem; }
    .sidebar { overflow-y: auto; max-height: 80vh; }
    .badge-beacon { background-color: #17a2b8; }
    .badge-text { background-color: #28a745; }
    .badge-data { background-color: #6f42c1; }
    .badge-unknown { background-color: #6c757d; }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container-fluid">
      <a class="navbar-brand" href="#">IP400 Network Monitor</a>
      <span class="navbar-text" id="frameCount">0 frames</span>
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
      </div>
    </div>

    <div class="row">
      <div class="col-12">
        <div class="card">
          <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="mb-0">Recent Frames</h5>
            <div>
              <input type="text" id="searchInput" class="form-control form-control-sm" placeholder="Search...">
            </div>
          </div>
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
              <tbody id="frameTable"></tbody>
            </table>
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

  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
  <script>
    // Initialize map
    var map = L.map('map').setView([45.4, -75.6], 5);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      maxZoom: 13,
      attribution: '© OpenStreetMap contributors'
    }).addTo(map);

    var markers = {};
    var frameModal = new bootstrap.Modal(document.getElementById('frameModal'));

    function updateUI() {
      fetch('/api/frames')
        .then(response => response.json())
        .then(data => {
          document.getElementById('frameCount').textContent = data.length + ' frames';
          updateMap(data);
          updateFrameTable(data);
        });
      
      fetch('/api/nodes')
        .then(response => response.json())
        .then(updateNodeList);
    }

    function updateMap(frames) {
      // Clear old markers
      Object.values(markers).forEach(marker => map.removeLayer(marker));
      markers = {};

      // Add new markers
      frames.forEach(frame => {
        if (frame.location) {
          const nodeId = `${frame.from_call}:${frame.from_port}`;
          if (!markers[nodeId]) {
            const marker = L.marker([frame.location[0], frame.location[1]])
              .bindPopup(`
                <b>${frame.from_call}:${frame.from_port}</b><br>
                To: ${frame.to_call}:${frame.to_port}<br>
                Last seen: ${new Date(frame.timestamp).toLocaleString()}<br>
                Hops: ${frame.hop_count}<br>
                Flags: 0x${frame.flags.toString(16).padStart(2, '0')}
              `)
              .addTo(map);
            markers[nodeId] = marker;
          }
        }
      });

      // Fit map to bounds if we have markers
      if (Object.keys(markers).length > 0) {
        const group = new L.featureGroup(Object.values(markers));
        map.fitBounds(group.getBounds().pad(0.1));
      }
    }

    function updateFrameTable(frames) {
      const tbody = document.getElementById('frameTable');
      tbody.innerHTML = '';

      frames.slice(0, 50).forEach(frame => {
        const row = document.createElement('tr');
        row.className = 'frame-row';
        row.onclick = () => showFrameDetails(frame);
        
        const typeClass = getTypeClass(frame.coding);
        const typeBadge = `<span class="badge ${typeClass}">${getTypeName(frame.coding)}</span>`;

        row.innerHTML = `
          <td>${new Date(frame.timestamp).toLocaleTimeString()}</td>
          <td>${frame.from_call}:${frame.from_port}</td>
          <td>${frame.to_call}:${frame.to_port}</td>
          <td>${typeBadge}</td>
          <td>${frame.hop_count}</td>
          <td>0x${frame.flags.toString(16).padStart(2, '0')}</td>
          <td>${Math.floor(frame.raw_data.length/2)} B</td>
        `;
        tbody.appendChild(row);
      });
    }

    function updateNodeList(nodes) {
      const nodeList = document.getElementById('nodeList');
      nodeList.innerHTML = '';

      Object.entries(nodes).forEach(([id, node]) => {
        const lastSeen = new Date(node.last_seen).toLocaleTimeString();
        
        const item = document.createElement('div');
        item.className = 'list-group-item list-group-item-action';
        item.innerHTML = `
          <div class="d-flex justify-content-between align-items-center">
            <div>
              <strong>${id}</strong><br>
              <small class="text-muted">Last: ${lastSeen}</small><br>
              <small class="text-muted">Type: ${node.packet_type || 'Unknown'}</small>
            </div>
            <div>
              <span class="badge bg-primary">${node.frame_count}</span>
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

    // Initial load and periodic refresh
    updateUI();
    setInterval(updateUI, 2000);
  </script>
</body>
</html>
    """)

# API Endpoints
@app.route("/api/frames")
def api_frames():
    limit = min(int(request.args.get('limit', 50)), 100)
    return jsonify([b.to_dict() for b in list(frame_history)[:limit]])

@app.route("/api/nodes")
def api_nodes():
    return jsonify(dict(node_history))

def main():
    """Start the IP400 server.
    
    This function starts both the UDP listener and the web interface.
    Configuration can be provided through environment variables:
    - IP400_UDP_IP: IP address to bind the UDP listener (default: 0.0.0.0)
    - IP400_UDP_PORT: UDP port to listen on (default: 9000)
    - IP400_WEB_HOST: Web interface host (default: 0.0.0.0)
    - IP400_WEB_PORT: Web interface port (default: 5000)
    """
    import os
    
    # Get configuration from environment variables
    udp_ip = os.getenv('IP400_UDP_IP', '0.0.0.0')
    udp_port = int(os.getenv('IP400_UDP_PORT', '9000'))
    web_host = os.getenv('IP400_WEB_HOST', '0.0.0.0')
    web_port = int(os.getenv('IP400_WEB_PORT', '5000'))
    
    # Update global variables
    global UDP_IP, UDP_PORT
    UDP_IP = udp_ip
    UDP_PORT = udp_port
    
    print(f"Starting IP400 Server...")
    print(f"UDP Listener: {udp_ip}:{udp_port}")
    print(f"Web Interface: http://{web_host}:{web_port}")
    
    # Start UDP listener in a separate thread
    listener_thread = threading.Thread(target=udp_listener, daemon=True)
    listener_thread.start()
    
    # Start the web interface
    app.run(host=web_host, port=web_port, debug=False)

if __name__ == '__main__':
    main()
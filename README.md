
<img width="1277" height="687" alt="ip400_server" src="https://github.com/user-attachments/assets/594d18ea-86df-41b5-bb30-221d75214726" />
# IP400 Server

This project hosts the Pi Zero 2 W gateway for an IP400 RF mesh node.  
It listens to the UDP feed produced by the IP400 hat, manages the serial-based
chat/console interface, and exposes a responsive Flask UI for live monitoring.

## Highlights

- **UDP ingest** of native IP4C frames with beacon parsing, location extraction,
  and per-node history.
- **Dual serial workers**: dedicated chat loop and on-demand console loop that
  coordinate access to the single UART.
- **Interactive web dashboard** featuring a Leaflet map, active node list,
  chat panel, and a console modal that mirrors the device menu.
- **REST API** (`/api/frames`, `/api/nodes`, `/api/chat`, `/api/console/*`,
  `/api/nodeinfo`, `/api/mode`, `/api/server/restart`) backing the UI and
  available for integrations.
- **Node info caching** from Menu A (station parameters) with optional refresh
  on demand.

## Requirements

- Python 3.9+
- `pip install -r requirements.txt` (includes Flask and pyserial)
- IP400 Pi Zero hat attached to `/dev/serial0` (default; configurable via env)

## Configuration

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `IP400_CHAT_PORT` | `/dev/serial0` | Serial device used for chat/console |
| `IP400_CHAT_BAUD` | `115200` | Baud rate for serial communication |
| `IP400_UDP_IP` | `0.0.0.0` | Bind address for UDP listener |
| `IP400_UDP_PORT` | `9000` | UDP port for inbound IP4C frames |
| `IP400_WEB_HOST` | `0.0.0.0` | Flask web host |
| `IP400_WEB_PORT` | `5000` | Flask web port |

## Running

```bash
cd ip400_server
python3 ip400_server.py
```

On startup the server:

1. Reads node parameters via menu **A** and caches them to `/tmp/ip400_node.json`.
2. Launches three daemon threads: UDP listener, chat loop, console loop.
3. Serves the Flask UI/API at `http://<web-host>:<web-port>`.

### Autostarting the Ip400Spi bridge

The Flask server expects IP4C frames on UDP port `9000`. If you use the
`Ip400Spi` helper to forward frames from the HAT’s SPI interface, run it as a
systemd service so it starts at boot:

1. Copy `Ip400Spi` (and any helper scripts) into a permanent location, e.g.
   `/opt/ip400`.
2. Create `/etc/systemd/system/ip400spi.service` with:

   ```ini
   [Unit]
   Description=IP400 SPI to UDP bridge
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   WorkingDirectory=/opt/ip400
   ExecStart=/opt/ip400/Ip400Spi -s /dev/spidev0.0 -n 192.168.1.239 -p 9000 -m 9001 -d 1
   Restart=on-failure
   User=ip400
   Group=ip400

   [Install]
   WantedBy=multi-user.target
   ```

   Adjust `-n`/`-p`/`-m` flags or the `User`/`Group` to match your setup.
3. Reload systemd and enable the service:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now ip400spi.service
   ```

Check status with `sudo systemctl status ip400spi.service`. Logs appear under
`journalctl -u ip400spi.service`.

### Console & Chat Coordination

- Opening the **Settings** modal on the web UI calls `/api/mode` to pause the
  chat thread and give exclusive serial access to the console loop.
- Closing the modal sends the device back to chat mode and resumes the chat
  thread automatically.

### Web UI Tips

- **Map**: displays live nodes with custom markers; local node renders in red.
- **Active Nodes**: shows last seen, distance, RSSI, and packet counts.
- **Chat**: select a node (or broadcast) to send messages via the serial loop.
- **Console**: available in the Settings modal. Commands are serialized through
  the console worker and responses stream into the terminal view.

## Development Notes

- `pyproject.toml` and `setup.py` are present for legacy setuptools support.
- When editing the frontend, remember the HTML/JS is embedded directly within
  `ip400_server.py`.
- The server writes node info to `nodeinfo.json` (local cache) and optionally
  to `/tmp/ip400_node.json` for other services.

## License

MIT

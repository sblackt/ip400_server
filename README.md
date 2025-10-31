
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

- Raspberry Pi OS (Pi Zero 2 W or newer)
- Python 3.9+
- `python3-venv` and `python3-pip`
- `build-essential` (to rebuild the Ip400Spi bridge on the target device)
- IP400 Pi Zero hat attached to `/dev/serial0` (default; configurable via env)

## Quick Install (Pi Zero image)

If you have the original IP400 Pi Zero firmware image, you can install the
updated server and services with the bundled helper script:

```bash
sudo apt update
sudo apt install git python3-venv python3-pip build-essential
cd /home/ip400
git clone https://github.com/<your-user>/ip400_server.git
cd ip400_server
./scripts/install_ip400.sh
```

Replace `<your-user>` with the GitHub account or organisation that hosts your
fork.

The script will:

1. Create/refresh the virtual environment in `.venv`.
2. Install the Python dependencies from `requirements.txt`.
3. Drop a default configuration file in `/etc/ip400/ip400.env` (edit to adjust
   SPI host/ports, device path, or Flask bind address).
4. Copy the systemd units into `/etc/systemd/system/` and enable both
   `ip400_spi.service` and `ip400_server.service`.

Check their status afterwards with:

```bash
sudo systemctl status ip400_spi.service ip400_server.service
```

> **Note:** If you are running a 64-bit OS, rebuild the SPI bridge in
> `/home/ip400/ip400spi` (`make clean && make`) so the binary matches the
> architecture, otherwise the service will exit with `Exec format error`.

## Manual Setup

Prefer to do things step by step? The manual process is:

```bash
sudo apt install python3-venv python3-pip build-essential
cd /home/ip400/ip400_server
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
sudo cp systemd/ip400_spi.service systemd/ip400_server.service /etc/systemd/system/
sudo install -d /etc/ip400
sudo cp config/ip400.env.example /etc/ip400/ip400.env
sudo systemctl daemon-reload
sudo systemctl enable --now ip400_spi.service ip400_server.service
```

Adjust `/etc/ip400/ip400.env` if your host IP, ports, or SPI device differ from
the defaults.

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

The systemd units source `/etc/ip400/ip400.env`. Any values defined there will
override the defaults shown above when the services start.

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

The Flask server expects IP4C frames on UDP port `9000`. The supplied
`systemd/ip400_spi.service` unit (installed by `scripts/install_ip400.sh`)
automates the SPI bridge startup. If you prefer to deploy it manually:

```bash
sudo install -m 644 systemd/ip400_spi.service /etc/systemd/system/ip400_spi.service
sudo systemctl daemon-reload
sudo systemctl enable --now ip400_spi.service
```

The unit reads `/etc/ip400/ip400.env`. Adjust the host, ports, or SPI device in
that file to match your mesh. Logs are written to `/var/log/ip400_spi.log` and
also available via `journalctl -u ip400_spi.service`.

### Console & Chat Coordination

- Opening the **Settings** modal on the web UI calls `/api/mode` to pause the
  chat thread and give exclusive serial access to the console loop.
- Closing the modal sends the device back to chat mode and resumes the chat
  thread automatically.

### Web UI Tips

- **Map**: displays live nodes with custom markers; local node renders in red.
- **Active Nodes**: shows last seen, distance, RSSI, and packet counts.
- **Chat**: sends broadcast messages to all reachable nodes (individual
  targeting is disabled in v1).
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

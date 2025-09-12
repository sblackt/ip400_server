# IP400 Server

A server for processing and displaying APRS and other radio packet data from IP400 devices.

## Features

- UDP packet listener for IP400 protocol
- Web-based interface for real-time monitoring
- JSON API for integration with other applications
- Support for GPS coordinates and APRS data

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/ip400-server.git
   cd ip400-server
   ```

2. Install the package:
   ```bash
   pip install -e .
   ```
   
   Or for system-wide installation:
   ```bash
   pip install .
   ```

## Usage

### Starting the Server

```bash
ip400-server
```

By default, the server will:
- Listen on UDP port 9000 for incoming packets
- Start a web interface on http://localhost:5000

### Configuration

You can configure the server using environment variables:

- `IP400_UDP_IP`: IP address to bind the UDP listener (default: 0.0.0.0)
- `IP400_UDP_PORT`: UDP port to listen on (default: 9000)
- `IP400_WEB_HOST`: Web interface host (default: 0.0.0.0)
- `IP400_WEB_PORT`: Web interface port (default: 5000)

## API Endpoints

- `GET /api/frames` - Get recent frames
- `GET /api/nodes` - Get node information

## Development

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

2. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

## License

MIT

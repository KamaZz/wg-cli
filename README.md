# WireGuard CLI Manager

A command-line tool for managing WireGuard VPN server and clients.

## Features

- Create new WireGuard clients
- List existing clients
- Delete clients
- Generate QR codes for client configurations
- Enable client-to-client network access
- View client status
- Automatic configuration detection from existing WireGuard setup

## Prerequisites

- Python 3.8 or higher
- WireGuard installed on the server
- Root/sudo privileges

## Installation

1. Clone this repository:
```bash
git clone https://github.com/KamaZz/wg-cli.git
cd wg-cli
```

2. Run the setup script (requires root privileges):
```bash
chmod +x setup.sh
sudo ./setup.sh
```

This will:
- Install required system packages (python3-venv)
- Create a Python virtual environment
- Install all dependencies in the virtual environment
- Make the main script executable

## Usage

1. Activate the virtual environment:
```bash
source venv/bin/activate
```

2. Run the commands (with sudo):
```bash
# Create a new client
sudo ./wg-cli.py add-client client_name

# List all clients
sudo ./wg-cli.py list-all

# Delete a client
sudo ./wg-cli.py delete client_name

# Show client QR code
sudo ./wg-cli.py show-qr client_name

# View client status
sudo ./wg-cli.py status
```

## Configuration

The tool will automatically detect existing WireGuard configurations. You only need to create a `.env` file if you want to override the defaults:

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Edit the `.env` file with your settings:
```bash
# Required only if not using default paths
WIREGUARD_CONFIG_DIR=/etc/wireguard
SERVER_INTERFACE=wg0

# Required only if not detected from system
SERVER_PUBLIC_IP=your_server_public_ip

# Optional settings (will be loaded from existing config if available)
# SERVER_PORT=51820
# CLIENT_SUBNET=10.0.0.0/24
# SERVER_ADDRESS=10.0.0.1/24
# DNS_SERVERS=1.1.1.1,8.8.8.8
```

## Security Notes

- Keep your private keys secure
- Regularly update client configurations
- Monitor server logs for suspicious activity
- The tool requires root privileges to manage WireGuard configurations

## License

MIT License 
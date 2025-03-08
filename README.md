# WireGuard CLI Manager

A command-line tool for managing WireGuard VPN server and clients.

## Features

- Create new WireGuard clients
- List existing clients
- Delete clients
- Generate QR codes for client configurations
- Enable client-to-client network access
- View client status

## Prerequisites

- Python 3.8 or higher
- WireGuard installed on the server
- Root/sudo privileges

## Installation

1. Clone this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file with your configuration:
```bash
WIREGUARD_CONFIG_DIR=/etc/wireguard
SERVER_PUBLIC_IP=your_server_public_ip
SERVER_PORT=51820
```

## Usage

```bash
# Create a new client
python wg-cli.py add-client client_name

# List all clients
python wg-cli.py list-clients

# Delete a client
python wg-cli.py delete-client client_name

# Show client QR code
python wg-cli.py show-qr client_name

# View client status
python wg-cli.py status
```

## Security Notes

- Keep your private keys secure
- Regularly update client configurations
- Monitor server logs for suspicious activity

## License

MIT License 
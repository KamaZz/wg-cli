import subprocess
import re
from pathlib import Path
from typing import List, Tuple, Dict
import qrcode
from config import settings, get_client_config_path

def generate_keypair() -> Tuple[str, str]:
    """Generate a WireGuard private-public key pair."""
    private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
    public_key = subprocess.check_output(["wg", "pubkey"], input=private_key.encode()).decode().strip()
    return private_key, public_key

def create_client_config(client_name: str, client_ip: str) -> Dict[str, str]:
    """Create a new client configuration."""
    client_private_key, client_public_key = generate_keypair()
    
    # Ensure server keys exist
    if not settings.SERVER_PUBLIC_KEY:
        server_private_key, server_public_key = generate_keypair()
        settings.SERVER_PRIVATE_KEY = server_private_key
        settings.SERVER_PUBLIC_KEY = server_public_key
    
    client_config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_ip}/24
DNS = {settings.DNS_SERVERS}

[Peer]
PublicKey = {settings.SERVER_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = {settings.SERVER_PUBLIC_IP}:{settings.SERVER_PORT}
PersistentKeepalive = 25"""

    config_path = get_client_config_path(client_name)
    config_path.write_text(client_config)
    
    return {
        "private_key": client_private_key,
        "public_key": client_public_key,
        "config_path": str(config_path),
        "ip_address": client_ip
    }

def get_available_ip() -> str:
    """Get the next available IP address in the subnet."""
    used_ips = get_used_ips()
    network_prefix = settings.CLIENT_SUBNET.split('/')[0].rsplit('.', 1)[0]
    
    for i in range(2, 255):  # Start from 2 as .1 is server
        ip = f"{network_prefix}.{i}"
        if ip not in used_ips:
            return ip
    raise Exception("No available IP addresses")

def get_used_ips() -> List[str]:
    """Get list of IP addresses currently in use."""
    used_ips = []
    config_dir = Path(settings.WIREGUARD_CONFIG_DIR)
    
    for config_file in config_dir.glob("*.conf"):
        content = config_file.read_text()
        ip_match = re.search(r"Address = ([\d\.]+)/", content)
        if ip_match:
            used_ips.append(ip_match.group(1))
    
    return used_ips

def generate_qr_code(client_name: str) -> None:
    """Generate QR code for client configuration."""
    config_path = get_client_config_path(client_name)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration for {client_name} not found")
    
    config_data = config_path.read_text()
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(config_data)
    qr.make(fit=True)
    
    qr_path = config_path.with_suffix('.png')
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(qr_path)
    return qr_path

def delete_client(client_name: str) -> None:
    """Delete a client configuration."""
    config_path = get_client_config_path(client_name)
    if config_path.exists():
        config_path.unlink()
        # Also delete QR code if it exists
        qr_path = config_path.with_suffix('.png')
        if qr_path.exists():
            qr_path.unlink()

def list_clients() -> List[Dict[str, str]]:
    """List all configured clients."""
    clients = []
    config_dir = Path(settings.WIREGUARD_CONFIG_DIR)
    
    for config_file in config_dir.glob("*.conf"):
        if config_file.stem == settings.SERVER_INTERFACE:
            continue
            
        content = config_file.read_text()
        ip_match = re.search(r"Address = ([\d\.]+)/", content)
        pubkey_match = re.search(r"PublicKey = (.+)", content)
        
        clients.append({
            "name": config_file.stem,
            "ip": ip_match.group(1) if ip_match else "Unknown",
            "public_key": pubkey_match.group(1) if pubkey_match else "Unknown"
        })
    
    return clients

def get_client_status() -> List[Dict[str, str]]:
    """Get the status of all connected clients."""
    try:
        output = subprocess.check_output(["wg", "show", settings.SERVER_INTERFACE]).decode()
        status = []
        current_peer = None
        
        for line in output.split('\n'):
            if line.startswith('peer:'):
                if current_peer:
                    status.append(current_peer)
                current_peer = {'public_key': line.split(':')[1].strip()}
            elif current_peer and line.strip():
                key, value = line.strip().split(':', 1)
                current_peer[key.strip()] = value.strip()
        
        if current_peer:
            status.append(current_peer)
            
        return status
    except subprocess.CalledProcessError:
        return [] 
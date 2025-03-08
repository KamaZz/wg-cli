import subprocess
import re
from pathlib import Path
from typing import List, Tuple, Dict, Optional
import qrcode
from config import settings, get_client_config_path
from datetime import datetime, timedelta

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
        ip_match = re.search(r"Address = ([\d\.]+/\d+)", content)
        pubkey_match = re.search(r"PublicKey = (.+)", content)
        allowed_ips_match = re.search(r"AllowedIPs = (.+)", content)
        
        # Parse allowed IPs to separate VPN IP and local networks
        allowed_ips = []
        local_networks = []
        if allowed_ips_match:
            for ip in allowed_ips_match.group(1).split(','):
                ip = ip.strip()
                # If it's not the default route and not the VPN IP
                if ip != "0.0.0.0/0" and (not ip_match or not ip.startswith(ip_match.group(1).split('/')[0])):
                    local_networks.append(ip)
                else:
                    allowed_ips.append(ip)
        
        clients.append({
            "name": config_file.stem,
            "ip": ip_match.group(1) if ip_match else "Unknown",
            "public_key": pubkey_match.group(1) if pubkey_match else "Unknown",
            "allowed_ips": ", ".join(allowed_ips) if allowed_ips else "0.0.0.0/0",
            "local_networks": ", ".join(local_networks) if local_networks else "None"
        })
    
    return clients

def parse_allowed_ips(allowed_ips_str: str) -> Tuple[str, str]:
    """Parse allowed IPs string into VPN IP and local networks."""
    if not allowed_ips_str:
        return "Unknown", "None"
        
    ips = [ip.strip() for ip in allowed_ips_str.split(',')]
    vpn_ips = []
    local_networks = []
    
    for ip in ips:
        # Assuming VPN IPs are in 10.x.x.x range (adjust if your VPN subnet is different)
        if ip.startswith('10.'):
            vpn_ips.append(ip)
        else:
            local_networks.append(ip)
    
    return (
        vpn_ips[0] if vpn_ips else "Unknown",
        ", ".join(local_networks) if local_networks else "None"
    )

def get_client_status() -> List[Dict[str, str]]:
    """Get the status of all connected clients."""
    try:
        # First, get all configured clients and their information
        all_clients = list_clients()
        clients_by_pubkey = {}
        
        # Get current status from wireguard
        output = subprocess.check_output(["wg", "show", settings.SERVER_INTERFACE]).decode()
        status = []
        current_peer = None
        
        # Process the wireguard output
        for line in output.split('\n'):
            if line.startswith('peer:'):
                if current_peer and 'public_key' in current_peer:
                    # Find matching client by public key
                    matching_client = next(
                        (client for client in all_clients if client['public_key'] == current_peer['public_key']),
                        None
                    )
                    
                    # Get client name from matching client or use first part of public key
                    current_peer['name'] = matching_client['name'] if matching_client else current_peer['public_key'][:8]
                    
                    # Parse allowed IPs
                    if 'allowed ips' in current_peer:
                        current_peer['ip'], current_peer['local_networks'] = parse_allowed_ips(current_peer['allowed ips'])
                    
                    # Check handshake status
                    handshake_str = current_peer.get('latest handshake', 'Never')
                    handshake_time = parse_handshake_time(handshake_str)
                    current_peer['alert'] = check_handshake_alert(handshake_time)
                    status.append(current_peer)
                
                # Start new peer
                pubkey = line.split(':')[1].strip()
                current_peer = {'public_key': pubkey}
                clients_by_pubkey[pubkey] = current_peer
            elif current_peer and line.strip():
                key, value = line.strip().split(':', 1)
                current_peer[key.strip()] = value.strip()
        
        # Handle the last peer
        if current_peer and 'public_key' in current_peer:
            matching_client = next(
                (client for client in all_clients if client['public_key'] == current_peer['public_key']),
                None
            )
            
            # Get client name from matching client or use first part of public key
            current_peer['name'] = matching_client['name'] if matching_client else current_peer['public_key'][:8]
            
            # Parse allowed IPs
            if 'allowed ips' in current_peer:
                current_peer['ip'], current_peer['local_networks'] = parse_allowed_ips(current_peer['allowed ips'])
            
            handshake_str = current_peer.get('latest handshake', 'Never')
            handshake_time = parse_handshake_time(handshake_str)
            current_peer['alert'] = check_handshake_alert(handshake_time)
            status.append(current_peer)
        
        # Add offline clients (those with no current connection)
        connected_pubkeys = set(clients_by_pubkey.keys())
        for client in all_clients:
            if client['public_key'] not in connected_pubkeys:
                status.append({
                    'name': client['name'],
                    'ip': client['ip'],
                    'local_networks': client['local_networks'],
                    'public_key': client['public_key'],
                    'latest handshake': 'Never',
                    'transfer': '0/0',
                    'endpoint': 'Unknown',
                    'alert': True
                })
        
        return status
    except subprocess.CalledProcessError:
        # If wireguard interface is not available, just show configured clients
        return [{
            'name': client['name'],
            'ip': client['ip'],
            'local_networks': client['local_networks'],
            'public_key': client['public_key'],
            'latest handshake': 'Never',
            'transfer': '0/0',
            'endpoint': 'Unknown',
            'alert': True
        } for client in list_clients()]

def parse_handshake_time(handshake_str: str) -> Optional[datetime]:
    """Parse handshake time string into datetime object."""
    if not handshake_str or handshake_str == "Never":
        return None
        
    try:
        # Handle different time formats
        parts = handshake_str.lower().split()
        if len(parts) >= 2:
            try:
                value = int(parts[0])
                unit = parts[1]
                
                if "minute" in unit:
                    return datetime.now() - timedelta(minutes=value)
                elif "hour" in unit:
                    return datetime.now() - timedelta(hours=value)
                elif "day" in unit:
                    return datetime.now() - timedelta(days=value)
                elif "second" in unit:
                    return datetime.now() - timedelta(seconds=value)
            except (ValueError, IndexError):
                pass
                
        # Try to parse as absolute time
        return datetime.strptime(handshake_str, "%Y-%m-%d %H:%M:%S")
    except (ValueError, IndexError):
        return None

def check_handshake_alert(handshake_time: Optional[datetime]) -> bool:
    """Check if handshake time should trigger an alert."""
    if handshake_time is None:
        return True
        
    alert_threshold = datetime.now() - timedelta(days=settings.HANDSHAKE_ALERT_DAYS)
    return handshake_time < alert_threshold 
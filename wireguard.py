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

def add_client_to_wg(client_name: str, public_key: str, allowed_ips: List[str]) -> None:
    """Add a new client to WireGuard interface using wg command."""
    try:
        # Check for subnet conflicts
        for ip in allowed_ips:
            if not ip.startswith('10.') and check_subnet_conflict(ip):
                raise Exception(f"Subnet conflict: {ip} is already in use by another client")
        
        # Add peer to WireGuard interface
        cmd = [
            "wg", "set", settings.SERVER_INTERFACE,
            "peer", public_key,
            "allowed-ips", ",".join(allowed_ips),
            "endpoint", "0.0.0.0:0"  # Initial endpoint, will be updated when client connects
        ]
        subprocess.check_call(cmd)
        
        # Save the configuration
        subprocess.check_call(["wg-quick", "save", settings.SERVER_INTERFACE])
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to add client to WireGuard: {str(e)}")

def remove_client_from_wg(public_key: str) -> None:
    """Remove a client from WireGuard interface using wg command."""
    try:
        # Remove peer from WireGuard interface
        cmd = [
            "wg", "set", settings.SERVER_INTERFACE,
            "peer", public_key,
            "remove"
        ]
        subprocess.check_call(cmd)
        
        # Save the configuration
        subprocess.check_call(["wg-quick", "save", settings.SERVER_INTERFACE])
    except subprocess.CalledProcessError as e:
        raise Exception(f"Failed to remove client from WireGuard: {str(e)}")

def create_client_config(client_name: str, client_ip: str, local_networks: Optional[List[str]] = None) -> Dict[str, str]:
    """Create a new client configuration.
    
    Args:
        client_name: Name of the client
        client_ip: VPN IP address for the client
        local_networks: Optional list of local network subnets (e.g., ["192.168.1.0/24"])
    """
    client_private_key, client_public_key = generate_keypair()
    
    # Ensure server keys exist
    if not settings.SERVER_PUBLIC_KEY:
        server_private_key, server_public_key = generate_keypair()
        settings.SERVER_PRIVATE_KEY = server_private_key
        settings.SERVER_PUBLIC_KEY = server_public_key
    
    # Prepare allowed IPs
    allowed_ips = [f"{client_ip}/32"]
    if local_networks:
        allowed_ips.extend(local_networks)
    
    # Add client to WireGuard interface
    add_client_to_wg(client_name, client_public_key, allowed_ips)
    
    # For client config, we use /24 for the interface address and 0.0.0.0/0 for allowed IPs
    # This ensures the client routes all traffic through VPN but can still access allowed local networks
    client_config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_ip}/24
DNS = {settings.DNS_SERVERS}

[Peer]
PublicKey = {settings.SERVER_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = {settings.SERVER_PUBLIC_IP}:{settings.SERVER_PORT}
PersistentKeepalive = 25"""

    # Get config path and ensure parent directory exists
    config_path = get_client_config_path(client_name)
    
    try:
        # Write configuration with secure permissions
        config_path.write_text(client_config)
        config_path.chmod(0o600)  # Set secure permissions (only owner can read/write)
        
        # Generate QR code
        try:
            qr_path = generate_qr_code(client_name)
        except Exception as qr_error:
            print(f"Warning: Failed to generate QR code: {str(qr_error)}")
            qr_path = None
            
        return {
            "private_key": client_private_key,
            "public_key": client_public_key,
            "config_path": str(config_path),
            "qr_path": str(qr_path) if qr_path else None,
            "ip_address": client_ip,
            "local_networks": local_networks or []
        }
    except Exception as e:
        # If writing fails, try to clean up
        try:
            if config_path.exists():
                config_path.unlink()
            remove_client_from_wg(client_public_key)
        except:
            pass
        raise Exception(f"Failed to write client configuration: {str(e)}")

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
    clients_dir = Path(settings.WIREGUARD_CLIENTS_DIR)
    
    for config_file in clients_dir.glob("*.conf"):
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
    """Delete a client configuration and remove from WireGuard."""
    config_path = get_client_config_path(client_name)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration for {client_name} not found")
    
    # Get client's public key before deleting the config
    content = config_path.read_text()
    pubkey_match = re.search(r"PublicKey = (.+)", content)
    if pubkey_match:
        public_key = pubkey_match.group(1).strip()
        # Remove from WireGuard interface
        remove_client_from_wg(public_key)
    
    # Delete configuration file
    config_path.unlink()
    
    # Delete QR code if it exists
    qr_path = config_path.with_suffix('.png')
    if qr_path.exists():
        qr_path.unlink()

def list_clients() -> List[Dict[str, str]]:
    """List all configured clients."""
    clients = []
    clients_dir = Path(settings.WIREGUARD_CLIENTS_DIR)
    
    for config_file in clients_dir.glob("*.conf"):
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

def get_used_subnets() -> List[str]:
    """Get list of local network subnets currently in use by clients."""
    used_subnets = []
    try:
        output = subprocess.check_output(["wg", "show", settings.SERVER_INTERFACE]).decode()
        for line in output.split('\n'):
            if line.strip().startswith('allowed ips:'):
                ips = line.split(':', 1)[1].strip().split(',')
                for ip in ips:
                    ip = ip.strip()
                    # Only collect non-VPN subnets (assuming VPN is in 10.x.x.x range)
                    if not ip.startswith('10.') and '/' in ip:
                        used_subnets.append(ip)
    except subprocess.CalledProcessError:
        pass
    return used_subnets

def check_subnet_conflict(subnet: str) -> bool:
    """Check if a subnet conflicts with existing client subnets."""
    used_subnets = get_used_subnets()
    for used_subnet in used_subnets:
        if used_subnet == subnet:
            return True
    return False 

def delete_inactive_clients(force: bool = False) -> List[str]:
    """Delete clients that haven't connected within the handshake threshold.
    
    Args:
        force: If True, skip confirmation and delete all inactive clients
        
    Returns:
        List of deleted client names
    """
    # Get current client status
    clients = get_client_status()
    
    # Filter inactive clients
    inactive_clients = [
        client for client in clients 
        if client.get('alert', True) and  # Clients with alert flag
        client.get('latest handshake', 'Never') != 'Never'  # Exclude never connected clients
    ]
    
    if not inactive_clients:
        print("No inactive clients found.")
        return []
    
    # Print inactive clients
    print("\nInactive clients (no handshake for more than {} days):".format(settings.HANDSHAKE_ALERT_DAYS))
    for client in inactive_clients:
        print(f"- {client['name']}: Last handshake {client.get('latest handshake', 'Never')}")
    
    # Ask for confirmation unless force is True
    if not force:
        confirmation = input(f"\nDo you want to delete these {len(inactive_clients)} inactive clients? [y/N]: ")
        if confirmation.lower() != 'y':
            print("Operation cancelled.")
            return []
    
    # Delete confirmed inactive clients
    deleted_clients = []
    for client in inactive_clients:
        try:
            delete_client(client['name'])
            deleted_clients.append(client['name'])
            print(f"Deleted client: {client['name']}")
        except Exception as e:
            print(f"Failed to delete client {client['name']}: {str(e)}")
    
    return deleted_clients 
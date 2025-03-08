import re
from pathlib import Path
from typing import Dict, Optional, List
import subprocess
import ipaddress

def parse_wg_config(config_file: Path) -> Dict[str, any]:
    """Parse a WireGuard configuration file and return its settings."""
    if not config_file.exists():
        return {}
    
    config = {
        'interface': {},
        'peers': []
    }
    
    current_section = None
    content = config_file.read_text().splitlines()
    
    for line in content:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        if line == '[Interface]':
            current_section = 'interface'
            continue
        elif line == '[Peer]':
            current_section = 'peer'
            config['peers'].append({})
            continue
            
        if current_section:
            key, value = [x.strip() for x in line.split('=', 1)]
            if current_section == 'interface':
                config['interface'][key] = value
            elif current_section == 'peer':
                config['peers'][-1][key] = value
    
    return config

def get_server_config(interface: str = "wg0") -> Dict[str, any]:
    """Get server configuration from WireGuard interface."""
    try:
        # Try to get configuration from running interface
        output = subprocess.check_output(["wg", "show", interface, "dump"]).decode().strip()
        if output:
            fields = output.split('\t')
            config = {
                'private_key': fields[0] if len(fields) > 0 else None,
                'public_key': fields[1] if len(fields) > 1 else None,
                'listen_port': fields[2] if len(fields) > 2 else None,
            }
            return config
    except subprocess.CalledProcessError:
        pass
    
    # If running interface not found, try to read from config file
    config_file = Path('/etc/wireguard') / f"{interface}.conf"
    if config_file.exists():
        return parse_wg_config(config_file)
    
    return {}

def get_network_config() -> Dict[str, str]:
    """Get network configuration from existing interfaces."""
    try:
        # Try to get IP address from running interface
        output = subprocess.check_output(["ip", "addr", "show", "wg0"]).decode()
        ip_match = re.search(r"inet ([\d\.]+/\d+)", output)
        if ip_match:
            network = ipaddress.ip_interface(ip_match.group(1))
            return {
                'server_address': str(network),
                'client_subnet': str(network.network)
            }
    except subprocess.CalledProcessError:
        pass
    
    return {}

def detect_dns_servers() -> List[str]:
    """Detect system DNS servers."""
    dns_servers = []
    
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns_servers.append(line.split()[1])
    except FileNotFoundError:
        pass
    
    return dns_servers if dns_servers else ['1.1.1.1', '8.8.8.8']

def get_existing_config(interface: str = "wg0") -> Dict[str, any]:
    """Get all existing WireGuard configuration."""
    config = {}
    
    # Get server configuration
    server_config = get_server_config(interface)
    if server_config:
        config.update({
            'server_private_key': server_config.get('interface', {}).get('PrivateKey'),
            'server_public_key': server_config.get('interface', {}).get('PublicKey'),
            'server_port': server_config.get('interface', {}).get('ListenPort', 51820),
        })
    
    # Get network configuration
    network_config = get_network_config()
    if network_config:
        config.update(network_config)
    
    # Get DNS servers
    dns_servers = detect_dns_servers()
    if dns_servers:
        config['dns_servers'] = ','.join(dns_servers)
    
    return config 
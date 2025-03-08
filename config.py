from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
import os
from dotenv import load_dotenv
from wg_parser import get_existing_config

load_dotenv()

class Settings(BaseSettings):
    WIREGUARD_CONFIG_DIR: str = "/etc/wireguard"
    WIREGUARD_CLIENTS_DIR: str = "/etc/wireguard/clients"
    SERVER_INTERFACE: str = "wg0"
    
    # These will be loaded from existing config if available
    SERVER_PUBLIC_IP: Optional[str] = None
    SERVER_PORT: int = 51820
    SERVER_PRIVATE_KEY: Optional[str] = None
    SERVER_PUBLIC_KEY: Optional[str] = None
    SERVER_CONFIG_FILE: str = "wg0.conf"
    CLIENT_SUBNET: str = "10.0.0.0/24"
    SERVER_ADDRESS: str = "10.0.0.1/24"
    DNS_SERVERS: str = "1.1.1.1,8.8.8.8"
    
    # Monitoring settings
    HANDSHAKE_ALERT_DAYS: int = 14  # Alert if handshake is older than this many days
    
    class Config:
        env_file = ".env"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._load_existing_config()
    
    def _load_existing_config(self):
        """Load configuration from existing WireGuard setup."""
        existing_config = get_existing_config(self.SERVER_INTERFACE)
        
        if existing_config.get('server_private_key'):
            self.SERVER_PRIVATE_KEY = existing_config['server_private_key']
        if existing_config.get('server_public_key'):
            self.SERVER_PUBLIC_KEY = existing_config['server_public_key']
        if existing_config.get('server_port'):
            self.SERVER_PORT = int(existing_config['server_port'])
        if existing_config.get('client_subnet'):
            self.CLIENT_SUBNET = existing_config['client_subnet']
        if existing_config.get('server_address'):
            self.SERVER_ADDRESS = existing_config['server_address']
        if existing_config.get('dns_servers'):
            self.DNS_SERVERS = existing_config['dns_servers']

settings = Settings()

def ensure_config_dir():
    """Ensure the WireGuard configuration directories exist."""
    # Create main config dir
    config_dir = Path(settings.WIREGUARD_CONFIG_DIR)
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Create clients dir
    clients_dir = Path(settings.WIREGUARD_CLIENTS_DIR)
    clients_dir.mkdir(parents=True, exist_ok=True)
    
    return clients_dir

def get_client_config_path(client_name: str) -> Path:
    """Get the path for a client's configuration file."""
    clients_dir = ensure_config_dir()
    config_path = clients_dir / f"{client_name}.conf"
    # Touch the file to ensure it exists and is writable
    config_path.touch(mode=0o600, exist_ok=True)
    return config_path 
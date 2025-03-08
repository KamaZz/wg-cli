#!/usr/bin/env python3

import os
import sys

# Get the absolute path of the script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Check if running in virtual environment, if not, switch to it
if not hasattr(sys, 'real_prefix') and not sys.prefix == os.path.join(SCRIPT_DIR, 'venv'):
    venv_python = os.path.join(SCRIPT_DIR, 'venv', 'bin', 'python3')
    if os.path.exists(venv_python):
        os.execv(venv_python, [venv_python] + sys.argv)
    else:
        print("Virtual environment not found. Please run setup.sh first.")
        sys.exit(1)

import click
from rich.console import Console
from rich.table import Table
from pathlib import Path
import os

from config import settings, ensure_config_dir
from wireguard import (
    create_client_config,
    get_available_ip,
    generate_qr_code,
    delete_client,
    list_clients,
    get_client_status
)

console = Console()

def check_root():
    """Check if the script is running with root privileges."""
    if os.geteuid() != 0:
        console.print("[red]This script must be run as root![/red]")
        sys.exit(1)

@click.group()
def cli():
    """WireGuard VPN Server Management CLI"""
    ensure_config_dir()

@cli.command()
@click.argument('client_name')
def add_client(client_name):
    """Create a new WireGuard client configuration."""
    check_root()
    try:
        # Get next available IP
        client_ip = get_available_ip()
        
        # Create client configuration
        result = create_client_config(client_name, client_ip)
        
        # Generate QR code
        qr_path = generate_qr_code(client_name)
        
        console.print(f"[green]Successfully created client '{client_name}'[/green]")
        console.print(f"IP Address: {result['ip_address']}")
        console.print(f"Config file: {result['config_path']}")
        console.print(f"QR Code: {qr_path}")
        
    except Exception as e:
        console.print(f"[red]Error creating client: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
def list_all():
    """List all configured WireGuard clients."""
    check_root()
    try:
        clients = list_clients()
        
        if not clients:
            console.print("[yellow]No clients configured.[/yellow]")
            return
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Client Name")
        table.add_column("WireGuard IP")
        table.add_column("Local Networks")
        table.add_column("Public Key")
        
        for client in clients:
            table.add_row(
                client['name'],
                client['ip'],
                client['local_networks'],
                client['public_key']
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error listing clients: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
@click.argument('client_name')
def delete(client_name):
    """Delete a WireGuard client configuration."""
    check_root()
    try:
        delete_client(client_name)
        console.print(f"[green]Successfully deleted client '{client_name}'[/green]")
    except Exception as e:
        console.print(f"[red]Error deleting client: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
@click.argument('client_name')
def show_qr(client_name):
    """Generate and show QR code for a client configuration."""
    check_root()
    try:
        qr_path = generate_qr_code(client_name)
        console.print(f"[green]QR code generated: {qr_path}[/green]")
    except Exception as e:
        console.print(f"[red]Error generating QR code: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
def status():
    """Show the status of all WireGuard connections."""
    check_root()
    try:
        status_list = get_client_status()
        
        if not status_list:
            console.print("[yellow]No active connections.[/yellow]")
            return
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Client Name")
        table.add_column("WireGuard IP")
        table.add_column("Local Networks")
        table.add_column("Latest Handshake")
        table.add_column("Transfer (↓/↑)")
        table.add_column("Endpoint")
        
        for peer in status_list:
            # Format row based on alert status
            style = "red" if peer.get('alert', True) else None
            name = f"[{style}]{peer.get('name', 'Unknown')}[/{style}]" if style else peer.get('name', 'Unknown')
            ip = f"[{style}]{peer.get('ip', 'Unknown')}[/{style}]" if style else peer.get('ip', 'Unknown')
            networks = f"[{style}]{peer.get('local_networks', 'None')}[/{style}]" if style else peer.get('local_networks', 'None')
            handshake = f"[{style}]{peer.get('latest handshake', 'Never')}[/{style}]" if style else peer.get('latest handshake', 'Never')
            transfer = f"[{style}]{peer.get('transfer', '0/0')}[/{style}]" if style else peer.get('transfer', '0/0')
            endpoint = f"[{style}]{peer.get('endpoint', 'Unknown')}[/{style}]" if style else peer.get('endpoint', 'Unknown')
            
            table.add_row(
                name,
                ip,
                networks,
                handshake,
                transfer,
                endpoint
            )
        
        # Show alert threshold information
        console.print(f"\nAlert threshold: [yellow]{settings.HANDSHAKE_ALERT_DAYS} days[/yellow] (configure with HANDSHAKE_ALERT_DAYS in .env)")
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error getting status: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    cli() 
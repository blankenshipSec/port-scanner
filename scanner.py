#!/usr/bin/env python3
"""
Port Scanner - A CLI-based TCP port scanner for security reconnaissance.
Author: Joshua Blankenship (blankenshipSec)
GitHub: https://github.com/blankenshipSec/port-scanner
License: MIT
"""
import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich import print as rprint

# -------- Constants --------
console = Console()

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

# -------- Port Parser --------
def parse_ports(ports_arg: str) -> list[int]:
    """Parse port argument and return a list of ports to scan."""
    if ports_arg == "common":
        return list(COMMON_PORTS.keys())
    
    try:
        if "-" in ports_arg:
            start, end = ports_arg.split("-")
            return list(range(int(start), int(end) + 1))
        else:
            return [int(ports_arg)]
    except ValueError:
        console.print("[red]Error: Invalid port range. Use format 1-1000 or a single port number.[/red]")
        sys.exit(1)

# -------- Argument Parser --------
def parse_arguments():
    """Parse and return CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="A CLI-based TCP port scanner for security reconnaissance.",
        epilog="Example: python scanner.py --target 192.168.1.1 --ports 1-1000",
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP address or hostname to scan.",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="common",
        help="Port range to scan (e.g., 1-1000) or 'common' for commonly used ports (default: common)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads (default: 100)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Save results to a file (e.g., results.txt)",
    )
    return parser.parse_args()

# -------- Port Scanner --------
def scan_port(target: str, port: int, timeout: float) -> dict:
    """Scan a single port and return the result."""
    result = {
        "port": port,
        "state": "closed",
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner": None,
        }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        connection = sock.connect_ex((target, port))
        
        if connection == 0:
            result["state"] = "open"
            result["banner"] = grab_banner(sock)
            
        sock.close()
        
    except socket.error:
        pass
    
    return result

# ------- Banner Grabber --------
def grab_banner(sock: socket.socket) -> str | None:
    """Attempt to grab a service banner from an open port."""
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        if banner:
            return banner[:200]
        return None
    except socket.error:
        return None
    
# -------- Run Scan --------
def run_scan(target: str, ports: list[int], threads: int, timeout: float) -> list[dict]:
    """Run the port scan using multiple threads and return results."""
    results = []
    
    with Progress() as progress:
        task = progress.add_task(
            f"[cyan]Scanning {target}...", total=len(ports)
        )
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(scan_port, target, port, timeout): port
                for port in ports
            }
            
            for future in futures:
                result = future.result()
                results.append(result)
                progress.advance(task)
                
    return sorted(results, key=lambda x: x["port"])

# -------- Display Results --------
def display_results(target: str, results: list[dict], start_time: datetime) -> None:
    """Display scan results in a formatted table."""
    open_ports = [r for r in results if r["state"] == "open"]
    elapsed = datetime.now() - start_time
    
    console.print(f"\n[bold cyan]Scan Complete[/bold cyan]")
    console.print(f"[white]Target:[/white] [yellow]{target}[/yellow]")
    console.print(f"[white]Open Ports:[/white] [yellow]{len(open_ports)}[/yellow]")
    console.print(f"[white]Scanned:[/white] [yellow]{len(results)} ports[/yellow]")
    console.print(f"[white]Duration:[/white] [yellow]{elapsed.seconds}s[/yellow]\n")
    
    if not open_ports:
        console.print("[red]No open ports found.[/red]")
        return
    
    table = Table(
        title="Open Ports",
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
    )
    
    table.add_column("Port", style="cyan", width=10)
    table.add_column("State", style="green", width=10)
    table.add_column("Service", style="yellow", width=15)
    table.add_column("Banner", style="white")
    
    for result in open_ports:
        table.add_row(
            str(result["port"]),
            result["state"],
            result["service"],
            result["banner"] or "N/A",
        )
        
    console.print(table)
    
# -------- Export Results --------
def export_results(target: str, results: list[dict], filename: str) -> None:
    """Export scan results to a text file."""
    open_ports = [r for r in results if r["state"] == "open"]
    
    try:
        with open(filename, "w") as f:
            f.write(f"Port Scan Results\n")
            f.write(f"{'=' * 40}\n\n")
            f.write(f"Target:     {target}\n")
            f.write(f"Date:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Open Ports: {len(open_ports)}\n")
            f.write(f"{'=' * 40}\n\n")
            
            if not open_ports:
                f.write("No open ports found.\n")
            else:
                for result in open_ports:
                    f.write(f"Port {result['port']:5} | "
                            f"{result['service']:10} | "
                            f"{result['banner'] or 'N/A'}\n")
        
        console.print(f"\n[green]Results saved to [bold]{filename}[/bold][/green]")
        
    except IOError as e:
        console.print(f"[red]Error saving results: {e}[/red]")
        
# -------- Main Function --------
def main() -> None:
    """Main entry point for the port scanner."""
    console.print("[bold cyan]blankenshipSec Port Scanner[/bold cyan]")
    console.print("[dim]For authorized use only.[/dim]\n")
    
    args = parse_arguments()
    ports = parse_ports(args.ports)
    start_time = datetime.now()
    
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        console.print(f"[red]Error: Could not resolve hostname '{args.target}'[/red]")
        sys.exit(1)
        
    console.print(f"[white]Target:[/white] [yellow]{args.target}[/yellow] ([yellow]{target_ip}[/yellow])")
    console.print(f"[white]Ports:[/white] [yellow]{len(ports)} ports queued[/yellow]")
    console.print(f"[white]Threads:[/white] [yellow]{args.threads}[/yellow]")
    console.print(f"[white]Timeout:[/white] [yellow]{args.timeout}s[/yellow]\n")
    
    results = run_scan(target_ip, ports, args.threads, args.timeout)
    display_results(args.target, results, start_time)
    
    if args.output:
        export_results(args.target, results, args.output)
        
if __name__ == "__main__":
    main()
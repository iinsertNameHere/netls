import nmap
from rich.console import Console
from rich.table import Table
from rich.text import Text
from argparse import ArgumentParser
import socket
import ipaddress
import re

# Create a console object
console = Console()

def is_iprange(s):
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|[1-2]?[0-9])$'
    return re.match(pattern, s)

def is_ports(s):
    pattern = r'^([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])(,([0-9]|[1-9][0-9]{1,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))*$'
    return re.match(pattern, s)

def get_iprange():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    ip = ipaddress.ip_address(local_ip)
    network = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(network)

def run_device_scan(ip_range: str = '192.168.178.0/24', ports: str = None):
    # Create a PortScanner object
    nm = nmap.PortScanner()
    
    try:
        # Run the nmap ping scan
        with console.status(Text("Running network scan..."), spinner="line", spinner_style="yellow"):
            r = None
            if ports:
                r = nm.scan(hosts=ip_range, ports=ports)
            else:
                r = nm.scan(hosts=ip_range)      
    except KeyboardInterrupt:
        console.print(Text("[~] Network scan canceled by User!\n", style="yellow"))
        exit(0)
    except Exception as e:
        console.print(Text(f"[!] Network scan failed: {str(e)}\n", style="red"))
        exit(1)

    # Construct result table
    table = Table(title="NetLS Results")
    table.add_column("Host", justify="right", style="cyan", no_wrap=True)
    table.add_column("Name", justify="right", style="magenta")
    table.add_column("State")
    if ports: table.add_column("Open Ports")

    for host in nm.all_hosts():
        state = Text("Down", style="red")

        open_ports_str = 'None'
        if nm[host].state() == "up":
            state = Text("Up", style="green")

            # List open ports
            if ports:
                open_ports = [str(port) for port in nm[host]['tcp'] if nm[host]['tcp'][port]['state'] == 'open']
                open_ports_str = ', '.join(open_ports) if open_ports else 'None'

        
        if ports:
            table.add_row(host, nm[host].hostname(), state, open_ports_str)
        else:
            table.add_row(host, nm[host].hostname(), state)

    return table

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-r", "--ip-range", default="NONE", help="Define ip range to scan")
    parser.add_argument("-p", "--ports", default="NONE", help="Define ports to scan (comma-separated, e.g. '22,80,443')")
    args = parser.parse_args()

    ip_range = ""
    if args.ip_range == "NONE":
        ip_range = get_iprange()
        console.print(Text(f"[+] Using '{ip_range}' as ip range.", style="green"))
    else:
        if is_iprange(args.ip_range):
            ip_range = args.ip_range
            console.print(Text(f"[+] Using '{ip_range}' as ip range.", style="green"))
        else:
            ip_range = get_iprange()
            console.print(Text(f"[!] '{args.ip_range}', is not a valid ip range!", style="red"))
            console.print(Text(f"[~] Using '{ip_range}' as ip range.", style="yellow"))
    
    ports = None
    if args.ports != "NONE":
        if is_ports(args.ports):
            ports = args.ports
            console.print(Text(f"[+] Scanning for ports: {ports}", style="green"))
        else:
            console.print(Text(f"[!] '{args.ports}' is not a valid ports definition!", style="red"))
            console.print(Text(f"[~] Running without port scann."), style="yellow")
    else:
        console.print(Text(f"[+] Running without port scann."), style="green")


    print("\n")
    console.print(run_device_scan(ip_range, ports))

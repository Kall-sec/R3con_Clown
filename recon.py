#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          ADVANCED RECONNAISSANCE TOOL v2.0                  ║
║          Educational / Authorized Use Only                   ║
╚══════════════════════════════════════════════════════════════╝
"""

import socket
import subprocess
import sys
import os
import json
import datetime
import time
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Auto-install missing dependencies ──────────────────────────
REQUIRED = {
    "whois":     "python-whois",
    "dns":       "dnspython",
    "requests":  "requests",
    "rich":      "rich",
}

def install_if_missing():
    import importlib
    for mod, pkg in REQUIRED.items():
        try:
            importlib.import_module(mod)
        except ImportError:
            print(f"[*] Installing {pkg}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

install_if_missing()

# ── Imports after install ──────────────────────────────────────
import whois
import dns.resolver
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.rule import Rule
from rich.layout import Layout
from rich.live import Live
from rich.tree import Tree

console = Console()

# ══════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════
def print_banner():
    banner = """
[bold cyan]
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
[/bold cyan]"""
    console.print(banner)
    console.print(Panel(
	"[bold italic white]✵Author✵>>> Kall-sec [/bold italic white]\n"
        "[bold yellow]Advanced Reconnaissance Tool v2.0[/bold yellow]\n"
        "[dim]For educational and authorized penetration testing only[/dim]\n"
	"[dim] ( う-´)づ︻╦̵̵̿╤── '(˚☐˚”)' [/dim]\n"
        f"[dim]Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
        border_style="cyan",
        expand=False
    ))
    console.print()

# ══════════════════════════════════════════════════════════════
#  1. DNS ENUMERATION
# ══════════════════════════════════════════════════════════════
class DNSEnumerator:
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV"]

    def __init__(self, target):
        self.target = target
        self.results = {}

    def query(self, rtype):
        try:
            answers = dns.resolver.resolve(self.target, rtype, lifetime=5)
            return [str(r) for r in answers]
        except Exception:
            return []

    def run(self):
        console.print(Rule("[bold cyan]DNS Enumeration[/bold cyan]", style="cyan"))
        table = Table(title=f"DNS Records — {self.target}", box=box.ROUNDED,
                      border_style="cyan", header_style="bold cyan")
        table.add_column("Record Type", style="bold yellow", width=14)
        table.add_column("Values", style="white")
        table.add_column("Count", justify="right", style="green")

        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      transient=True, console=console) as prog:
            task = prog.add_task("Querying DNS records...", total=len(self.RECORD_TYPES))
            for rtype in self.RECORD_TYPES:
                records = self.query(rtype)
                self.results[rtype] = records
                if records:
                    table.add_row(rtype, "\n".join(records), str(len(records)))
                prog.advance(task)

        console.print(table)
        return self.results

# ══════════════════════════════════════════════════════════════
#  2. WHOIS LOOKUP
# ══════════════════════════════════════════════════════════════
class WhoisLookup:
    def __init__(self, target):
        self.target = target

    def run(self):
        console.print(Rule("[bold magenta]WHOIS Information[/bold magenta]", style="magenta"))
        try:
            w = whois.whois(self.target)
            fields = {
                "Domain Name":      w.domain_name,
                "Registrar":        w.registrar,
                "Created":          w.creation_date,
                "Expires":          w.expiration_date,
                "Updated":          w.updated_date,
                "Status":           w.status,
                "Name Servers":     w.name_servers,
                "Registrant Org":   w.org,
                "Country":          w.country,
                "Emails":           w.emails,
                "DNSSEC":           w.dnssec,
            }
            table = Table(title=f"WHOIS — {self.target}", box=box.ROUNDED,
                          border_style="magenta", header_style="bold magenta")
            table.add_column("Field", style="bold yellow", width=20)
            table.add_column("Value", style="white")

            for key, val in fields.items():
                if val is None:
                    continue
                if isinstance(val, list):
                    val = "\n".join([str(v) for v in val if v])
                else:
                    val = str(val)
                if val.strip():
                    table.add_row(key, val)

            console.print(table)
            return fields
        except Exception as e:
            console.print(f"[red]WHOIS failed: {e}[/red]")
            return {}

# ══════════════════════════════════════════════════════════════
#  3. PORT SCANNER (Multi-threaded)
# ══════════════════════════════════════════════════════════════
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    1433: "MSSQL", 5900: "VNC", 11211: "Memcached",
}

class PortScanner:
    COMMON_PORTS = list(SERVICE_MAP.keys()) + list(range(1, 1025))
    COMMON_PORTS = sorted(set(COMMON_PORTS))

    def __init__(self, target, timeout=1, max_workers=100):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.open_ports = []

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            if result == 0:
                return port
        except Exception:
            pass
        return None

    def grab_banner(self, port):
        try:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((self.target, port))
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode(errors="ignore").strip()
            sock.close()
            return banner[:80] if banner else ""
        except Exception:
            return ""

    def run(self):
        console.print(Rule("[bold green]Port Scanner[/bold green]", style="green"))
        console.print(f"[dim]Scanning {len(self.COMMON_PORTS)} ports on {self.target}...[/dim]\n")

        open_ports = []
        with Progress(SpinnerColumn(), TextColumn("[green]{task.description}"),
                      BarColumn(), TextColumn("{task.completed}/{task.total}"),
                      transient=True, console=console) as prog:
            task = prog.add_task("Scanning ports...", total=len(self.COMMON_PORTS))
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(self.scan_port, p): p for p in self.COMMON_PORTS}
                for fut in as_completed(futures):
                    result = fut.result()
                    if result:
                        open_ports.append(result)
                    prog.advance(task)

        self.open_ports = sorted(open_ports)

        table = Table(title=f"Open Ports — {self.target}", box=box.ROUNDED,
                      border_style="green", header_style="bold green")
        table.add_column("Port", style="bold yellow", justify="right", width=8)
        table.add_column("Service", style="cyan", width=15)
        table.add_column("State", style="bold green", width=10)
        table.add_column("Banner / Info", style="dim white")

        for port in self.open_ports:
            service = SERVICE_MAP.get(port, "Unknown")
            banner = self.grab_banner(port) if port in [80, 443, 8080, 8443, 21, 22] else ""
            table.add_row(str(port), service, "● OPEN", banner)

        if self.open_ports:
            console.print(table)
        else:
            console.print("[yellow]No open ports found in common range.[/yellow]")

        return self.open_ports

# ══════════════════════════════════════════════════════════════
#  4. SUBDOMAIN ENUMERATION
# ══════════════════════════════════════════════════════════════
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "imap",
    "vpn", "api", "dev", "staging", "test", "blog", "shop", "portal",
    "remote", "secure", "cdn", "app", "ns1", "ns2", "mx", "cloud",
    "m", "mobile", "beta", "old", "new", "static", "assets", "img",
    "login", "cpanel", "whm", "autodiscover", "autoconfig",
]

class SubdomainEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.found = []

    def check(self, sub):
        full = f"{sub}.{self.domain}"
        try:
            ip = socket.gethostbyname(full)
            return (full, ip)
        except Exception:
            return None

    def run(self):
        console.print(Rule("[bold blue]Subdomain Enumeration[/bold blue]", style="blue"))
        console.print(f"[dim]Checking {len(COMMON_SUBDOMAINS)} subdomains...[/dim]\n")

        found = []
        with Progress(SpinnerColumn(), TextColumn("[blue]{task.description}"),
                      BarColumn(), transient=True, console=console) as prog:
            task = prog.add_task("Enumerating subdomains...", total=len(COMMON_SUBDOMAINS))
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(self.check, s): s for s in COMMON_SUBDOMAINS}
                for fut in as_completed(futures):
                    result = fut.result()
                    if result:
                        found.append(result)
                    prog.advance(task)

        self.found = sorted(found, key=lambda x: x[0])

        table = Table(title=f"Subdomains — {self.domain}", box=box.ROUNDED,
                      border_style="blue", header_style="bold blue")
        table.add_column("Subdomain", style="cyan")
        table.add_column("IP Address", style="bold yellow")

        for sub, ip in self.found:
            table.add_row(sub, ip)

        if self.found:
            console.print(table)
            console.print(f"[green]✓ Found {len(self.found)} subdomains[/green]\n")
        else:
            console.print("[yellow]No subdomains resolved.[/yellow]\n")

        return self.found

# ══════════════════════════════════════════════════════════════
#  5. HTTP HEADERS ANALYSIS
# ══════════════════════════════════════════════════════════════
class HTTPHeaderAnalyzer:
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing Protection",
        "Referrer-Policy": "Referrer Policy",
        "Permissions-Policy": "Permissions Policy",
        "X-XSS-Protection": "XSS Protection",
    }

    def __init__(self, target):
        self.target = target

    def run(self):
        console.print(Rule("[bold red]HTTP Headers & Security Analysis[/bold red]", style="red"))
        for scheme in ["https", "http"]:
            url = f"{scheme}://{self.target}"
            try:
                resp = requests.get(url, timeout=8, verify=False,
                                    headers={"User-Agent": "ReconTool/2.0"})

                # All headers
                htable = Table(title=f"HTTP Headers — {url}", box=box.ROUNDED,
                               border_style="red", header_style="bold red")
                htable.add_column("Header", style="bold yellow", width=35)
                htable.add_column("Value", style="white")

                for h, v in resp.headers.items():
                    htable.add_row(h, v[:120])
                console.print(htable)

                # Security headers check
                stable = Table(title="Security Headers Audit", box=box.SIMPLE_HEAVY,
                               border_style="yellow", header_style="bold yellow")
                stable.add_column("Security Header", style="cyan", width=35)
                stable.add_column("Status", width=12)
                stable.add_column("Value", style="dim")

                for header, desc in self.SECURITY_HEADERS.items():
                    if header in resp.headers:
                        stable.add_row(
                            f"{desc}\n[dim]{header}[/dim]",
                            "[bold green]✓ Present[/bold green]",
                            resp.headers[header][:60]
                        )
                    else:
                        stable.add_row(
                            f"{desc}\n[dim]{header}[/dim]",
                            "[bold red]✗ Missing[/bold red]",
                            ""
                        )
                console.print(stable)

                # Technology detection
                server = resp.headers.get("Server", "Unknown")
                powered = resp.headers.get("X-Powered-By", "Unknown")
                console.print(Panel(
                    f"[bold]Status Code:[/bold] [cyan]{resp.status_code}[/cyan]\n"
                    f"[bold]Server:[/bold] [yellow]{server}[/yellow]\n"
                    f"[bold]X-Powered-By:[/bold] [yellow]{powered}[/yellow]\n"
                    f"[bold]Content-Type:[/bold] {resp.headers.get('Content-Type', 'N/A')}",
                    title="[bold]Server Fingerprint[/bold]",
                    border_style="red"
                ))
                return resp.headers
            except requests.exceptions.SSLError:
                continue
            except Exception as e:
                console.print(f"[red]HTTP error ({scheme}): {e}[/red]")
        return {}

# ══════════════════════════════════════════════════════════════
#  6. GEO-IP LOOKUP
# ══════════════════════════════════════════════════════════════
class GeoIPLookup:
    def __init__(self, target):
        self.target = target

    def run(self):
        console.print(Rule("[bold yellow]GeoIP & ASN Information[/bold yellow]", style="yellow"))
        try:
            ip = socket.gethostbyname(self.target)
            resp = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
            data = resp.json()

            table = Table(title=f"GeoIP — {ip}", box=box.ROUNDED,
                          border_style="yellow", header_style="bold yellow")
            table.add_column("Field", style="bold cyan", width=20)
            table.add_column("Value", style="white")

            fields = [
                ("IP Address", "ip"), ("City", "city"), ("Region", "region"),
                ("Country", "country_name"), ("Postal Code", "postal"),
                ("Latitude", "latitude"), ("Longitude", "longitude"),
                ("ISP / Org", "org"), ("ASN", "asn"), ("Timezone", "timezone"),
                ("Currency", "currency_name"), ("Languages", "languages"),
            ]
            for label, key in fields:
                val = data.get(key)
                if val:
                    table.add_row(label, str(val))

            console.print(table)
            return data
        except Exception as e:
            console.print(f"[red]GeoIP lookup failed: {e}[/red]")
            return {}

# ══════════════════════════════════════════════════════════════
#  7. SUMMARY REPORT
# ══════════════════════════════════════════════════════════════
def print_summary(target, dns_res, whois_res, ports, subdomains, geo):
    console.print()
    console.print(Rule("[bold white]RECONNAISSANCE SUMMARY[/bold white]", style="white"))

    tree = Tree(f"[bold cyan]🎯 {target}[/bold cyan]")

    # DNS
    dns_node = tree.add("[bold magenta]📡 DNS Records[/bold magenta]")
    for rtype, vals in dns_res.items():
        if vals:
            dns_node.add(f"[yellow]{rtype}[/yellow]: {', '.join(vals[:2])}")

    # Ports
    port_node = tree.add(f"[bold green]🔓 Open Ports ({len(ports)} found)[/bold green]")
    for p in ports[:10]:
        port_node.add(f"[green]{p}[/green] — {SERVICE_MAP.get(p, 'Unknown')}")
    if len(ports) > 10:
        port_node.add(f"[dim]...and {len(ports)-10} more[/dim]")

    # Subdomains
    sub_node = tree.add(f"[bold blue]🌐 Subdomains ({len(subdomains)} found)[/bold blue]")
    for sub, ip in subdomains[:8]:
        sub_node.add(f"[blue]{sub}[/blue] → {ip}")

    # Geo
    if geo:
        geo_node = tree.add("[bold yellow]📍 Location[/bold yellow]")
        geo_node.add(f"{geo.get('city','?')}, {geo.get('region','?')}, {geo.get('country_name','?')}")
        geo_node.add(f"ISP: {geo.get('org','N/A')}")

    console.print(tree)

    # Save report
    report = {
        "target": target,
        "timestamp": datetime.datetime.now().isoformat(),
        "dns": dns_res,
        "open_ports": ports,
        "subdomains": [{"host": s, "ip": i} for s, i in subdomains],
        "geo": geo,
    }
    filename = f"recon_{target.replace('.','_')}_{int(time.time())}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)

    console.print(Panel(
        f"[bold green]✓ Report saved:[/bold green] [cyan]{filename}[/cyan]",
        border_style="green"
    ))

# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════
def main():
    print_banner()

    console.print("[bold]Target domain/IP:[/bold] ", end="")
    target = input().strip()
    if not target:
        console.print("[red]No target provided. Exiting.[/red]")
        sys.exit(1)

    # Resolve if domain
    try:
        ip = socket.gethostbyname(target)
        console.print(f"\n[green]✓ Resolved:[/green] {target} → [bold cyan]{ip}[/bold cyan]\n")
    except Exception:
        console.print(f"[red]Could not resolve {target}[/red]")
        sys.exit(1)

    console.print("\n[bold]Select modules to run:[/bold]")
    console.print("[1] DNS Enumeration")
    console.print("[2] WHOIS Lookup")
    console.print("[3] Port Scan")
    console.print("[4] Subdomain Enumeration")
    console.print("[5] HTTP Headers Analysis")
    console.print("[6] GeoIP Lookup")
    console.print("[A] All modules (recommended)\n")

    choice = input("Choice [A/1-6, comma separated]: ").strip().upper()
    modules = set()
    if not choice or choice == "A":
        modules = {"1","2","3","4","5","6"}
    else:
        modules = set(choice.replace(" ","").split(","))

    console.print()
    dns_res = whois_res = ports = subdomains = geo = {}
    ports = subdomains = []

    if "1" in modules:
        dns_res = DNSEnumerator(target).run()
        console.print()

    if "2" in modules:
        whois_res = WhoisLookup(target).run()
        console.print()

    if "3" in modules:
        ports = PortScanner(ip).run()
        console.print()

    if "4" in modules:
        subdomains = SubdomainEnumerator(target).run()

    if "5" in modules:
        HTTPHeaderAnalyzer(target).run()
        console.print()

    if "6" in modules:
        geo = GeoIPLookup(target).run()
        console.print()

    print_summary(target, dns_res, whois_res, ports, subdomains, geo)

if __name__ == "__main__":
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass
    main()

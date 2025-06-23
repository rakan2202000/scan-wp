import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from packaging import version
from rich.console import Console
from rich.table import Table
import re

console = Console()

console.print(r'''
[bold bright_cyan]
███████╗ ██████╗ █████╗ ███╗   ██╗      ██╗    ██╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║      ██║    ██║██╔══██╗
███████╗██║     ███████║██╔██╗ ██║█████╗██║ █╗ ██║██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║╚════╝██║███╗██║██╔═══╝ 
███████║╚██████╗██║  ██║██║ ╚████║      ╚███╔███╔╝██║     
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝       ╚══╝╚══╝ ╚═╝     
                                                            [bold yellow]By Rakan[/bold yellow]

[bold green] Fast WordPress Plugin & Version Scanner with CVE Match[/bold green]
[/bold bright_cyan]
''')

CVE_DB = [
    {
        "cve": "CVE-2025-3102",
        "plugin": "suretriggers",
        "max_version": "1.0.78",
        "type": "Bypass Authentication",
        "poc_url": "https://github.com/Nxploited/CVE-2025-3102"
    },
    {
        "cve": "CVE-2025-47577",
        "plugin": "ti-woocommerce-wishlist",
        "max_version": "2.9.2",
        "type": "file_upload",
        "poc_url": "https://github.com/Yucaerin/CVE-2025-47577"
    },
    {
        "cve": "CVE-2022-1329",
        "plugin": "elementor",
        "max_version": "3.6.2",
        "type": "rce",
        "poc_url": "https://www.exploit-db.com/exploits/50882"
    },
    {
        "cve": "CVE-2025-2563",
        "plugin": "membership",
        "max_version": "4.1.1",
        "type": "privilege_escalation",
        "poc_url": "https://www.exploit-db.com/exploits/52137"
    },
    {
        "cve": "CVE-2023-6114",
        "plugin": "duplicator",
        "max_version": "1.5.7.1",
        "type": "data_exposure",
        "poc_url": "https://www.exploit-db.com/exploits/51874"
    },
    {
        "cve": "CVE-2022-21661",
        "plugin": "site-editor",
        "max_version": "1.1.1",
        "type": "lfi",
        "poc_url": "https://www.exploit-db.com/exploits/44340"
    },
    {
        "cve": "CVE-2022-21661",
        "plugin": "wordpress-core",
        "max_version": "5.8.3",
        "type": "sqli",
        "poc_url": "https://www.exploit-db.com/exploits/50663"
    },
    {
        "cve": "CVE-2023-2636",
        "plugin": "an-gradebook",
        "max_version": "5.0.1",
        "type": "sqli",
        "poc_url": "https://www.exploit-db.com/exploits/51632"
    },
    {
        "cve": "CVE-2021-42362",
        "plugin": "popular-posts",
        "max_version": "5.3.2",
        "type": "rce",
        "poc_url": "https://www.exploit-db.com/exploits/50129"
    }
]

def get_plugins(url):
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(resp.text, 'html.parser')
        plugins = set()
        for link in soup.find_all("link", href=True):
            href = link['href']
            match = re.search(r'/wp-content/plugins/([^/]+)/.*?ver=([\d.]+)', href)
            if match:
                plugins.add((match.group(1).lower(), match.group(2)))
        return plugins
    except:
        return set()

def get_wp_version(url):
    try:
        r = requests.get(url + "/readme.html", timeout=10)
        match = re.search(r"Version (\d+\.\d+(?:\.\d+)?)", r.text)
        if match:
            return match.group(1)
    except:
        return "Unknown"

def check_vulnerabilities(plugins, wp_version):
    vulns = []
    for cve in CVE_DB:
        if cve["plugin"] == "wordpress-core":
            if wp_version and wp_version != "Unknown":
                try:
                    if version.parse(wp_version) <= version.parse(cve["max_version"]):
                        vulns.append(("wordpress-core", wp_version, cve))
                except:
                    continue
        else:
            for plugin, ver in plugins:
                try:
                    if plugin == cve["plugin"] and version.parse(ver) <= version.parse(cve["max_version"]):
                        vulns.append((plugin, ver, cve))
                except:
                    continue
    return vulns

def scan(url):
    if not url.startswith("http"):
        url = "http://" + url
    url = url.strip("/")
    plugins = get_plugins(url)
    wp_ver = get_wp_version(url)
    vulns = check_vulnerabilities(plugins, wp_ver)
    return url, wp_ver, vulns

def main():
    with open("list.txt") as f:
        urls = [u.strip() for u in f if u.strip()]
    
    table = Table(title="Vulnerable Sites")
    table.add_column("URL", style="cyan")
    table.add_column("WordPress Ver", style="blue")
    table.add_column("Plugin", style="yellow")
    table.add_column("CVE", style="red")

    results = []

    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = {executor.submit(scan, url): url for url in urls}
        for future in as_completed(futures):
            url, wp_ver, vulns = future.result()
            if vulns:
                for plugin, version_, cve in vulns:
                    console.print(
                        f"[green][+][/green] [bold cyan]{url}[/bold cyan] | [yellow]{plugin}[/yellow] | [magenta]{version_}[/magenta] | [red]{cve['cve']}[/red] ({cve['type']}) → {cve['poc_url']}"
                    )
                    table.add_row(url, wp_ver, plugin, cve["cve"])
                    results.append(f"{url} | {plugin} | {version_} | {cve['cve']}")
            else:
                console.print(f"[grey][-] {url} -> No vulnerable plugins found[/grey]")

    if results:
        with open("vuln.txt", "w") as f:
            for r in results:
                f.write(r + "\n")
        console.print(f"\n[yellow]Saved to vuln.txt[/yellow]")
        console.print(table)
    else:
        console.print("[bold red]No vulnerable sites found.[/bold red]")

if __name__ == "__main__":
    main()

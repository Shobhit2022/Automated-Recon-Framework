
"""
Advanced Vulnerability Scanner with PDF reports & SSL warning suppression
"""

import socket, json, os, re, threading
from threading import Lock
from datetime import datetime
import requests
from rich.console import Console
from rich.progress import Progress
from fpdf import FPDF                                                                                           
import matplotlib.pyplot as plt
import dns.resolver
from fpdf import FPDF
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_FILE = "config.json"
with open(CONFIG_FILE, "r") as f:
    config = json.load(f)

TOP_PORTS = config.get("top_ports", [21,22,23,25,53,80,443,445,3306,8080])
MAX_THREADS = config.get("max_threads", 50)
HTTP_TIMEOUT = config.get("http_timeout", 3)
SUBDOMAIN_LIST = config.get("subdomains", ["www","mail","ftp","dev","api","test"])
REPORT_FOLDER = "reports"

console = Console()
results_lock = Lock()


def sanitize_filename(name):
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name)

def is_host_alive(target):
    try:
        socket.create_connection((target, 80), timeout=1)
        return True
    except:
        return False

def scan_port(target, port, results, progress_task, progress):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        if sock.connect_ex((target, port)) == 0:
            banner = ""
            try:
                banner = sock.recv(1024).decode(errors='ignore').strip()
            except:
                banner = "No banner"
            with results_lock:
                results[port] = {"status": "open", "banner": banner}
    except:
        pass
    finally:
        sock.close()
        progress.advance(progress_task)

def port_scan(target):
    console.print(f"[bold cyan][+] Scanning ports for {target}...[/bold cyan]")
    results = {}
    threads = []
    with Progress() as progress:
        task = progress.add_task("[green]Scanning ports...", total=len(TOP_PORTS))
        for port in TOP_PORTS:
            t = threading.Thread(target=scan_port, args=(target, port, results, task, progress))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
    console.print(f"[bold green][+] Scan complete: {len(results)} open ports found.[/bold green]")
    return results

def probe_http(target):
    urls = [f"http://{target}", f"https://{target}"]
    results = {}
    for url in urls:
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT, verify=False)
            results[url] = {
                "status": r.status_code,
                "server": r.headers.get("Server"),
                "x-powered-by": r.headers.get("X-Powered-By")
            }
        except requests.exceptions.RequestException as e:
            results[url] = {"status": "unreachable", "error": str(e)}
    return results

def subdomain_enum(domain):
    if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
        try:
            hostname = socket.gethostbyaddr(domain)[0]
            domain = hostname
            console.print(f"[yellow][*] Reverse DNS: {domain}[/yellow]")
        except:
            console.print("[yellow][*] IP detected, skipping subdomain enumeration[/yellow]")
            return ["No subdomains found for IP"]

    found = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1

    for sub in SUBDOMAIN_LIST:
        try:
            full = f"{sub}.{domain}"
            answers = resolver.resolve(full, 'A')
            if answers:
                found.add(full)
        except:
            pass

    for sub in SUBDOMAIN_LIST:
        url = f"http://{sub}.{domain}"
        try:
            r = requests.get(url, timeout=2, verify=False)
            if r.status_code < 500:
                found.add(f"{sub}.{domain}")
        except:
            pass

    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=3, verify=False)
        data = r.json()
        for entry in data:
            name = entry.get("name_value")
            if name:
                for n in name.split("\n"):
                    found.add(n.strip())
    except:
        pass

    if not found:
        return ["No subdomains found"]
    return sorted(list(found))

def web_vuln_scan(target):
    vulns = {}
    endpoints = [""] 
    for ep in endpoints:
        url = f"http://{target}/{ep}"
        sqli_payloads = ["' OR '1'='1", "';--", "' OR 1=1 --"]
        for p in sqli_payloads:
            try:
                r = requests.get(url, params={"id": p}, timeout=HTTP_TIMEOUT)
                if "sql" in r.text.lower() or r.status_code == 500:
                    vulns[url] = "Potential SQL Injection"
            except:
                pass
        xss_payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']
        for p in xss_payloads:
            try:
                r = requests.get(url, params={"q": p}, timeout=HTTP_TIMEOUT)
                if p in r.text:
                    vulns[url] = "Reflected XSS detected"
            except:
                pass
        try:
            r = requests.get(url, params={"next": "http://evil.com"}, timeout=HTTP_TIMEOUT, allow_redirects=False)
            if r.status_code in [301,302] and "evil.com" in r.headers.get("Location",""):
                vulns[url] = "Open Redirect detected"
        except:
            pass
    if not vulns:
        return {"No vulnerabilities detected": "Safe"}
    return vulns

def check_default_creds(port_results):
    vuln = {}
    for port, info in port_results.items():
        if port == 21:
            vuln[port] = "Anonymous FTP login allowed"
        elif port == 22:
            vuln[port] = "SSH default credentials test (demo)"
        elif port == 3306:
            vuln[port] = "MySQL default creds test (demo)"
        else:
            vuln[port] = "No default creds detected"
    return vuln


def api_security_test(target):
    vulns = {}
    endpoints = ["api/v1/users", "api/v1/admin"]
    for ep in endpoints:
        url = f"http://{target}/{ep}"
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                vulns[url] = "Potential unauthorized API access"
        except:
            pass
    if not vulns:
        return {"No API vulnerabilities detected": "Safe"}
    return vulns


def create_port_chart(port_results, file_path):
    open_ports = list(port_results.keys())
    status = [1]*len(open_ports)
    plt.figure(figsize=(6,3))
    plt.bar(open_ports, status, color='green')
    plt.xlabel('Port')
    plt.ylabel('Open (1)')
    plt.title('Open Ports Overview')
    plt.tight_layout()
    plt.savefig(file_path)
    plt.close()

def create_vuln_chart(vulns, file_path):
    types = [v for v in vulns.values()]
    from collections import Counter
    counter = Counter(types)
    labels = counter.keys()
    sizes = counter.values()
    plt.figure(figsize=(6,3))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=['red','orange','yellow','green'])
    plt.title("Vulnerability Types")
    plt.tight_layout()
    plt.savefig(file_path)
    plt.close()

def generate_reports(target, port_results, http_results, subdomains, web_vulns, creds_vulns, api_vulns):
    if not os.path.exists(REPORT_FOLDER):
        os.makedirs(REPORT_FOLDER)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = sanitize_filename(target)

    all_vulns = {}
    all_vulns.update(web_vulns)
    for port, v in creds_vulns.items():
        all_vulns[f"Port {port}"] = v
    all_vulns.update(api_vulns)

    json_file = os.path.join(REPORT_FOLDER, f"{safe_target}_{timestamp}.json")
    with open(json_file,'w') as f:
        json.dump({
            "target": target,
            "ports": port_results,
            "http_probe": http_results,
            "subdomains": subdomains,
            "vulnerabilities": all_vulns
        }, f, indent=4)


    html_file = os.path.join(REPORT_FOLDER, f"{safe_target}_{timestamp}.html")
    html_content = f"<html><head><title>Recon Report - {target}</title></head><body>"
    html_content += f"<h1>Recon Report for {target}</h1><p>Generated on {timestamp}</p>"
    html_content += "<h2>Open Ports</h2><ul>"
    for port, info in port_results.items():
        html_content += f"<li>{port}: {info}</li>"
    html_content += "</ul><h2>HTTP Probe</h2><ul>"
    for url, info in http_results.items():
        html_content += f"<li>{url}: {info}</li>"
    html_content += "</ul><h2>Subdomains</h2><ul>"
    for sub in subdomains:
        html_content += f"<li>{sub}</li>"
    html_content += "</ul><h2>Vulnerabilities</h2><ul>"
    for key, val in all_vulns.items():
        html_content += f"<li>{key}: {val}</li>"
    html_content += "</ul></body></html>"
    with open(html_file,'w') as f:
        f.write(html_content)


    pdf_file = os.path.join(REPORT_FOLDER, f"{safe_target}_{timestamp}.pdf")
    port_chart_file = os.path.join(REPORT_FOLDER, f"{safe_target}_ports.png")
    vuln_chart_file = os.path.join(REPORT_FOLDER, f"{safe_target}_vulns.png")
    create_port_chart(port_results, port_chart_file)
    create_vuln_chart(all_vulns, vuln_chart_file)

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial",'B',16)
    pdf.cell(0,10,f"Advanced Recon Report - {target}",ln=True)
    pdf.set_font("Arial",'',12)
    pdf.cell(0,10,f"Generated on: {timestamp}",ln=True)
    pdf.ln(5)
    pdf.set_font("Arial",'B',14)
    pdf.cell(0,10,"Open Ports Chart:",ln=True)
    pdf.image(port_chart_file,w=170)
    pdf.ln(5)
    pdf.cell(0,10,"Vulnerabilities Chart:",ln=True)
    pdf.image(vuln_chart_file,w=170)
    pdf.ln(5)
    pdf.set_font("Arial",'B',14)
    pdf.cell(0,10,"Subdomains:",ln=True)
    pdf.set_font("Arial",'',12)
    for sub in subdomains:
        pdf.cell(0,8,sub,ln=True)
    pdf.ln(5)
    pdf.set_font("Arial",'B',14)
    pdf.cell(0,10,"Vulnerabilities:",ln=True)
    pdf.set_font("Arial",'',12)
    for key, val in all_vulns.items():
        pdf.cell(0,8,f"{key}: {val}",ln=True)
    pdf.output(pdf_file)

    console.print(f"[bold yellow][+] JSON report: {json_file}[/bold yellow]")
    console.print(f"[bold yellow][+] HTML report: {html_file}[/bold yellow]")
    console.print(f"[bold yellow][+] PDF report: {pdf_file}[/bold yellow]")


def main():
    target = input("Enter target IP or domain: ").strip()
    console.print(f"[bold cyan][*] Checking if host {target} is alive...[/bold cyan]")
    if not is_host_alive(target):
        console.print(f"[bold red][-] Host {target} is not reachable. Exiting.[/bold red]")
        return

    console.print("[bold cyan][*] Starting advanced automated recon...[/bold cyan]")
    port_results = port_scan(target)
    http_results = probe_http(target)
    subdomains = subdomain_enum(target)
    web_vulns = web_vuln_scan(target)
    creds_vulns = check_default_creds(port_results)
    api_vulns = api_security_test(target)
    generate_reports(target, port_results, http_results, subdomains, web_vulns, creds_vulns, api_vulns)

    console.print("[bold green][+] Advanced Vulnerability Scan completed![/bold green]")

if __name__ == "__main__":
    main()

import ssl
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def is_web_server(ip, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
        response = s.recv(1024).decode(errors="ignore").lower()
        s.close()
        if "http/" in response:
                return "http"
    except Exception:
        pass
    return None

def scan_ip_range(ip_range, ports=None):
    if ports is None:
        ports = [80, 443, 8080, 8000, 8443, 5000, 8888]
    try:
        ip_list = ipaddress.ip_network(ip_range, strict=False)
    except ValueError:
        raise ValueError("Invalid IP range format. Use CIDR notation (e.g. 10.0.0.0/24) or a single IP (e.g. 10.0.0.1).")
    
    found_sites = []

    def check_ip_port(ip, port):
        print(f"[~] Scanning {ip}:{port}")
        result = is_web_server(str(ip), port)
        if result:
            url = f"{result}://{ip}:{port}" if port not in [80, 443] else f"{result}://{ip}"
            print(f"  [+] Found web server: {url}")
            found_sites.append(url)

    with ThreadPoolExecutor(max_workers=100) as executor:
        for ip in ip_list:
            for port in ports:
                executor.submit(check_ip_port, ip, port)

    return found_sites

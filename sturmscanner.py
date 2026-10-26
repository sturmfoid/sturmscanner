#!/usr/bin/env python3
"""
sturmscanner - a simple CCTV camera finder & traffic sniffer for Linux.

For YOUR OWN network / lab only. Scanning or sniffing networks you do not
own or have written permission to test is illegal in most places.

Features:
  1. Host discovery   - fast ARP scan (scapy) or ping fallback
  2. Port scan        - common CCTV / NVR ports + banner grab
  3. Fingerprinting   - guess brand from banner AND from MAC (OUI) vendor
  4. ONVIF discovery  - WS-Discovery multicast probe (most IP cams answer)
  5. RTSP check       - try common stream paths on port 554
  6. Sniffer          - live-capture one camera's traffic (scapy)
  7. Save report      - write everything found to a text file

Best run as root for ARP scan + sniffing:   sudo python3 sturmscanner.py
Optional dependency:                          pip install scapy
"""

import socket
import threading
import ipaddress
import subprocess
import os
from queue import Queue
from datetime import datetime

# scapy is optional: ARP scan + sniffing use it, everything else works without.
try:
    from scapy.all import ARP, Ether, srp, sniff
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


# Ports IP cameras / NVRs commonly listen on, with a short label.
CCTV_PORTS = {
    80:    "HTTP (web UI)",
    443:   "HTTPS (web UI)",
    554:   "RTSP (video stream)",
    8000:  "Hikvision SDK",
    8080:  "HTTP alt",
    8554:  "RTSP alt",
    34567: "Dahua / XMeye (media)",
    37777: "Dahua (service)",
    37778: "Dahua (UDP)",
    9000:  "ONVIF / media alt",
    2020:  "ONVIF alt",
    8899:  "ONVIF / XMeye alt",
}

# Words in a text banner that hint at a vendor.
VENDOR_HINTS = {
    "hikvision": "Hikvision",
    "dvrdvs":    "Hikvision (DVR)",
    "dahua":     "Dahua",
    "dahuartsp": "Dahua",
    "axis":      "Axis",
    "reolink":   "Reolink",
    "dlink":     "D-Link",
    "d-link":    "D-Link",
    "foscam":    "Foscam",
    "ubnt":      "Ubiquiti",
    "uniview":   "Uniview",
    "tp-link":   "TP-Link",
    "tapo":      "TP-Link Tapo",
    "amcrest":   "Amcrest",
    "vivotek":   "Vivotek",
}

# First 3 bytes of a MAC (the OUI) map to the maker. A few common camera ones.
MAC_VENDORS = {
    "00:40:48": "Hikvision",
    "4c:bd:8f": "Hikvision",
    "c0:56:e3": "Hikvision",
    "bc:ad:28": "Hikvision",
    "90:02:a9": "Dahua",
    "3c:ef:8c": "Dahua",
    "08:ed:ed": "Dahua",
    "00:40:8c": "Axis",
    "ac:cc:8e": "Axis",
    "ec:71:db": "Reolink",
    "00:62:6e": "Amcrest",
}

# Common RTSP stream paths to try (vendor defaults).
RTSP_PATHS = [
    "/",
    "/live",
    "/live.sdp",
    "/h264",
    "/Streaming/Channels/101",        # Hikvision
    "/cam/realmonitor?channel=1&subtype=0",  # Dahua
    "/live/ch00_0",
    "/11",
    "/video1",
]


# ---------------------------------------------------------------------------
# Network info: find our IP and the /24 we live on
# ---------------------------------------------------------------------------
def get_my_network():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))     # no real packet sent; just picks the route
        my_ip = s.getsockname()[0]
    finally:
        s.close()
    net = ipaddress.ip_network(my_ip + "/24", strict=False)
    return my_ip, net


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


# ---------------------------------------------------------------------------
# Step 1: host discovery (ARP if we can, else ping sweep)
# ---------------------------------------------------------------------------
def arp_scan(net):
    """Layer-2 ARP sweep via scapy. Fast and reliable, but needs root."""
    print("  using ARP scan (scapy)...")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
    answered, _ = srp(pkt, timeout=3, verbose=0)
    hosts = {}
    for _, reply in answered:
        hosts[reply.psrc] = reply.hwsrc
        print(f"  [+] {reply.psrc}   ({reply.hwsrc})")
    return hosts   # {ip: mac}


def ping(host):
    cmd = ["ping", "-c", "1", "-W", "1", str(host)]
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def ping_sweep(net):
    """Threaded ping sweep. No root needed, but no MACs."""
    print("  using ping sweep...")
    live = {}
    lock = threading.Lock()
    q = Queue()
    for host in net.hosts():
        q.put(host)

    def worker():
        while not q.empty():
            host = q.get()
            if ping(host):
                with lock:
                    live[str(host)] = None
                    print(f"  [+] {host}")
            q.task_done()

    threads = [threading.Thread(target=worker) for _ in range(60)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return live


def discover_hosts(net):
    """Pick the best discovery method available."""
    if HAVE_SCAPY and is_root():
        return arp_scan(net)
    return ping_sweep(net)


def mac_vendor(mac):
    if not mac:
        return None
    return MAC_VENDORS.get(mac.lower()[:8])


# ---------------------------------------------------------------------------
# Step 2 & 3: port scan + banner grab + fingerprint
# ---------------------------------------------------------------------------
def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((ip, port))
        if port in (554, 8554):                     # RTSP OPTIONS
            s.sendall(f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
                      .encode())
        elif port in (80, 8080, 443):               # HTTP GET
            s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
        data = s.recv(1024)
        s.close()
        return data.decode(errors="ignore")
    except Exception:
        return ""


def guess_vendor_from_banner(banner):
    low = banner.lower()
    for word, name in VENDOR_HINTS.items():
        if word in low:
            return name
    return None


def scan_host(ip, mac=None):
    open_ports = {}
    vendor = mac_vendor(mac)            # start with the MAC-based guess
    for port, label in CCTV_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            if s.connect_ex((ip, port)) == 0:       # 0 == open
                banner = grab_banner(ip, port)
                open_ports[port] = (label, banner.strip()[:120])
                vendor = vendor or guess_vendor_from_banner(banner)
            s.close()
        except Exception:
            pass
    return {"ip": ip, "mac": mac, "ports": open_ports, "vendor": vendor}


def looks_like_camera(result):
    camera_ports = {554, 8554, 8000, 34567, 37777, 2020, 9000, 8899}
    return bool(set(result["ports"]) & camera_ports) or result["vendor"]


# ---------------------------------------------------------------------------
# Step 4: ONVIF WS-Discovery
# ---------------------------------------------------------------------------
def onvif_discover(timeout=3):
    probe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        '<e:Header><w:MessageID>uuid:sturmscanner-probe</w:MessageID>'
        '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
        '</e:Header><e:Body><d:Probe/></e:Body></e:Envelope>'
    )
    group = ("239.255.255.250", 3702)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout)
    s.sendto(probe.encode(), group)
    found = []
    try:
        while True:
            _, addr = s.recvfrom(65535)
            found.append(addr[0])
            print(f"  [+] ONVIF reply from {addr[0]}")
    except socket.timeout:
        pass
    finally:
        s.close()
    return sorted(set(found))


# ---------------------------------------------------------------------------
# Step 5: RTSP common-path check
# ---------------------------------------------------------------------------
def rtsp_check(ip, port=554):
    """Send DESCRIBE for common paths; a 200/401 means the path exists."""
    print(f"\nChecking RTSP paths on {ip}:{port} ...")
    hits = []
    for path in RTSP_PATHS:
        url = f"rtsp://{ip}:{port}{path}"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((ip, port))
            s.sendall(f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
            resp = s.recv(512).decode(errors="ignore")
            s.close()
            line = resp.splitlines()[0] if resp else ""
            if "200" in line:
                print(f"  [+] OPEN stream: {url}")
                hits.append(url)
            elif "401" in line:
                print(f"  [auth] needs login: {url}")
                hits.append(url + "  (login required)")
        except Exception:
            pass
    if not hits:
        print("  no common paths responded")
    return hits


# ---------------------------------------------------------------------------
# Step 6: sniff one camera's traffic
# ---------------------------------------------------------------------------
def sniff_camera(ip, count=50):
    if not HAVE_SCAPY:
        print("\n  Sniffing needs scapy:  pip install scapy")
        return
    if not is_root():
        print("\n  Sniffing needs root:  sudo python3 sturmscanner.py")
        return
    print(f"\nSniffing up to {count} packets for {ip} (Ctrl+C to stop)...")
    sniff(filter=f"host {ip}", prn=lambda p: print("  " + p.summary()),
          count=count)


# ---------------------------------------------------------------------------
# Step 7: save a report
# ---------------------------------------------------------------------------
def save_report(results):
    fname = "sturmscan_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt"
    with open(fname, "w") as f:
        f.write("sturmscanner report  " + datetime.now().isoformat() + "\n")
        f.write("=" * 50 + "\n")
        for r in results:
            if not r["ports"]:
                continue
            brand = f" [{r['vendor']}]" if r["vendor"] else ""
            cam = "  <-- CAMERA" if looks_like_camera(r) else ""
            f.write(f"\n{r['ip']}{brand}{cam}\n")
            if r["mac"]:
                f.write(f"    mac: {r['mac']}\n")
            for port, (label, banner) in r["ports"].items():
                f.write(f"    {port:<6} {label}\n")
                if banner:
                    f.write(f"           {banner}\n")
    print(f"\n  saved -> {os.path.abspath(fname)}")


# ---------------------------------------------------------------------------
# Full scan helper (discover -> scan each host)
# ---------------------------------------------------------------------------
def full_scan(net):
    hosts = discover_hosts(net)
    if not hosts:
        print("  no hosts found")
        return []
    print(f"\nScanning {len(hosts)} host(s) for CCTV ports...\n")
    results = []
    order = sorted(hosts, key=lambda ip: tuple(int(p) for p in ip.split(".")))
    for ip in order:
        r = scan_host(ip, hosts[ip])
        results.append(r)
        if not r["ports"]:
            continue
        brand = f" [{r['vendor']}]" if r["vendor"] else ""
        cam = "  <-- probably a CAMERA" if looks_like_camera(r) else ""
        mac = f"  {r['mac']}" if r["mac"] else ""
        print(f"{ip}{mac}{brand}{cam}")
        for port, (label, banner) in r["ports"].items():
            print(f"    {port:<6} {label}")
            if banner:
                print(f"           banner: {banner}")
    return results


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------
def main():
    print("=" * 62)
    print(" sturmscanner - CCTV finder & sniffer (Linux)")
    print(" Use ONLY on networks you own or are allowed to test.")
    print("=" * 62)

    my_ip, net = get_my_network()
    print(f"\n Your IP : {my_ip}")
    print(f" Range   : {net}")
    print(f" scapy   : {'yes' if HAVE_SCAPY else 'no (pip install scapy)'}")
    print(f" root    : {'yes' if is_root() else 'no (sudo for ARP + sniff)'}")

    last_results = []

    while True:
        print("\n--- menu ---")
        print(" 1) discover hosts")
        print(" 2) full scan (hosts + CCTV ports + fingerprint)")
        print(" 3) ONVIF discovery")
        print(" 4) RTSP path check on one IP")
        print(" 5) sniff one camera's traffic")
        print(" 6) save last scan to file")
        print(" 7) quit")
        choice = input("choose: ").strip()

        if choice == "1":
            print()
            discover_hosts(net)

        elif choice == "2":
            last_results = full_scan(net)

        elif choice == "3":
            print("\nSending ONVIF probe...")
            if not onvif_discover():
                print("  no ONVIF replies (try option 2)")

        elif choice == "4":
            ip = input("camera IP: ").strip()
            if ip:
                rtsp_check(ip)

        elif choice == "5":
            ip = input("camera IP to sniff: ").strip()
            if ip:
                try:
                    sniff_camera(ip)
                except KeyboardInterrupt:
                    print("\n  stopped.")

        elif choice == "6":
            if last_results:
                save_report(last_results)
            else:
                print("  run a full scan (option 2) first")

        elif choice == "7":
            print("bye!")
            break

        else:
            print("pick 1-7")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nbye!")

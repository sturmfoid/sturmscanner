# sturmscanner

A small network scanner I wrote to find CCTV cameras on a network and poke at them a bit. It's a learning project, so don't expect anything fancy. I was mostly curious how tools like nmap find devices, and cameras seemed like a fun thing to hunt for since they're everywhere and most of them answer back if you ask the right way.

It's written in plain Python 3 and made for Linux. The core stuff (port scanning, ONVIF, RTSP) runs with nothing extra installed. The faster bits (ARP scanning and packet sniffing) use scapy and need root.

## What it does

- Finds live hosts on your network. Uses an ARP scan if it can (fast, also grabs MAC addresses), otherwise just pings everything.
- Scans each host for the ports cameras and NVRs usually sit on (RTSP 554, the web UI, the Hikvision/Dahua service ports, and so on).
- Tries to guess the brand two ways: from whatever the device says in its banner, and from the MAC address (the first few bytes tell you the manufacturer).
- Sends an ONVIF discovery probe. Most IP cameras reply to this, so it's the quickest way to spot them.
- Checks a bunch of common RTSP stream paths so you can actually find the video URL instead of just knowing the port is open.
- Sniffs the traffic going to and from one camera.
- Saves whatever it found to a text file.

## Heads up

Only run this on your own network, or one you have permission to test. Scanning and sniffing other people's networks is illegal pretty much everywhere and will get you in real trouble. I built it to learn on my own gear. Please do the same.

## Requirements

- Python 3
- Linux
- scapy, but only if you want the ARP scan and the sniffer:

```bash
pip install -r requirements.txt
```

If you skip scapy it still works, it just falls back to ping and turns off the sniffer.

## How to use it

Run it with sudo so the ARP scan and sniffer have what they need:

```bash
sudo python3 sturmscanner.py
```

It figures out your IP and the network range on its own, then drops you into a menu:

```
 1) discover hosts
 2) full scan (hosts + CCTV ports + fingerprint)
 3) ONVIF discovery
 4) RTSP path check on one IP
 5) sniff one camera's traffic
 6) save last scan to file
 7) quit
```

Normal flow is option 2 to see what's out there, then 4 to dig into anything that looks like a camera, then 6 if you want to keep the results. Option 3 is a nice shortcut if you just want cameras and nothing else.

The startup screen tells you whether scapy and root are available, so if something's off you'll know why.

## Adding more cameras

All the lists live at the top of the file: the ports, the banner keywords, the MAC prefixes, and the RTSP paths. If you run into a camera it doesn't recognize, add a line and it'll know next time.

## Still want to add

- MAC lookup from a proper OUI file instead of my short hardcoded list
- Export to JSON, not just a text dump
- Maybe a real nmap-style output someday

It's a work in progress. If you have ideas or it breaks on your setup, open an issue.

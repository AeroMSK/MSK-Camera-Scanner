#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSK Camera Scanner
Author: MSK
Description: Scan custom IP ranges for cameras
License: MIT
Termux Compatible: Yes
"""

import socket
import threading
from queue import Queue
import ipaddress
from datetime import datetime
import time
import sys
import signal
import os
import re
import multiprocessing
import subprocess
import platform
import random
import base64

# Try to import colorama, but work without it (Termux compatibility)
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        GREEN = '\033[92m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
    class Style:
        RESET_ALL = '\033[0m'

# Add requests and auth for login testing
try:
    import requests
    from requests.auth import HTTPDigestAuth
    import urllib3
    # Disable SSL warnings for testing
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

def typing_print(text, speed=0.005):
    """Prints text character by character for a cinematic effect"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()


def glitch_intro():
    """Short glitch-like effect before clearing the screen"""
    chars = "!@#$%^&*()_+{}[]|;:,.<>?"
    for _ in range(5):
        glitch = "".join(random.choice(chars) for _ in range(60))
        sys.stdout.write(f"\r{Fore.GREEN}{glitch}{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(0.04)
    sys.stdout.write("\r" + " " * 60 + "\r")


def loading_spinner(duration=0.8, task="Initializing"):
    """Animated loading spinner for transitions"""
    spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end_time = time.time() + duration
    while time.time() < end_time:
        for char in spinner:
            sys.stdout.write(f"\r{Fore.GREEN}[*] {task}... {char}{Style.RESET_ALL}")
            sys.stdout.flush()
            time.sleep(0.08)
    sys.stdout.write("\r" + " " * 60 + "\r")

# Default credentials to try
DEFAULT_CREDENTIALS = [
    ("admin", "admin123"),
    ("admin", "admin1234"),
    ("admin", "admin12345"),
    ("admin", "admin1122"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
]


class CameraValidator:
    """
    Camera credential validator.
    Each check uses a specific API endpoint with a known response signature
    so we NEVER report a false positive from a publicly-accessible page.
    """
    RTSP_PORT = 554
    TIMEOUT   = 3.5

    # Endpoints with deterministic success markers ─────────────────────
    # (url_suffix, success_strings_in_body, auth_types_to_try)
    HIK_ENDPOINTS = [
        ("/ISAPI/System/deviceInfo",   ["<DeviceInfo", "<serialNumber", "deviceName"]),
        ("/ISAPI/Security/userCheck",  ["statusValue", "<statusValue"]),
    ]
    DAHUA_ENDPOINTS = [
        ("/cgi-bin/magicBox.cgi?action=getDeviceType",           ["DeviceType="]),
        ("/cgi-bin/configManager.cgi?action=getConfig&name=General", ["table.General"]),
        ("/RPC2",                                                 []),  # body-independent: 200 = auth ok
    ]
    # Snapshot endpoints: success = 200 + image/jpeg content-type
    SNAPSHOT_PATHS = [
        "/cgi-bin/snapshot.cgi",
        "/snapshot.cgi",
        "/snap.jpg",
        "/image/jpeg.cgi",
        "/cgi-bin/hi3510/snap.cgi",
    ]

    def __init__(self, ip, username, password, port=80):
        self.ip       = ip
        self.username = username
        self.password = password
        self.port     = port

    def validate(self, hint=None):
        if not HAS_REQUESTS:
            return False, "requests library not installed"

        base_http  = f"http://{self.ip}:{self.port}"
        base_https = f"https://{self.ip}:{self.port}"

        # 1. Hikvision ISAPI
        for suffix, markers in self.HIK_ENDPOINTS:
            for base in (base_http, base_https):
                ok, msg = self._check_endpoint(base + suffix, markers, "Hikvision")
                if ok: return True, msg

        # 2. Dahua / Anjhua CGI + RPC2
        for suffix, markers in self.DAHUA_ENDPOINTS:
            for base in (base_http, base_https):
                ok, msg = self._check_endpoint(base + suffix, markers, "Dahua")
                if ok: return True, msg

        # 3. Image snapshot — content-type: image/jpeg proves auth
        for path in self.SNAPSHOT_PATHS:
            ok, msg = self._check_snapshot(base_http + path)
            if ok: return True, msg

        # 4. RTSP
        ok, msg = self._try_rtsp()
        if ok: return True, msg

        return False, "No match"

    # ── helpers ──────────────────────────────────────────────────────────

    def _get(self, url, auth):
        """GET with no redirect following — redirects are auth failures."""
        try:
            return requests.get(
                url, auth=auth,
                timeout=self.TIMEOUT, verify=False,
                allow_redirects=False          # ← KEY: no redirect chasing
            )
        except Exception:
            return None

    def _check_endpoint(self, url, success_markers, brand):
        """
        Try Digest then Basic auth.
        Success = status 200 AND (no markers required OR at least one marker in body).
        A redirect (3xx) or 401 is always a failure.
        """
        for auth in (
            HTTPDigestAuth(self.username, self.password),
            (self.username, self.password),
        ):
            r = self._get(url, auth)
            if r is None:
                continue
            if r.status_code == 200:
                # If we require specific body markers, check them
                if success_markers:
                    if any(m in r.text for m in success_markers):
                        label = "Digest" if isinstance(auth, HTTPDigestAuth) else "Basic"
                        return True, f"{brand} ({label} Auth)"
                else:
                    # No markers required (e.g. RPC2 — 200 = authenticated)
                    # But reject if body suggests it's a login page
                    body_low = r.text.lower()
                    if not any(w in body_low for w in ['<form', 'type="password"', "type='password'", 'login']):
                        label = "Digest" if isinstance(auth, HTTPDigestAuth) else "Basic"
                        return True, f"{brand} ({label} Auth)"
        return False, "Failed"

    def _check_snapshot(self, url):
        """
        Snapshot check: a real JPEG response (Content-Type contains image/)
        proves the camera accepted credentials.  An HTML login page never
        returns Content-Type: image/jpeg.
        """
        for auth in (
            HTTPDigestAuth(self.username, self.password),
            (self.username, self.password),
        ):
            r = self._get(url, auth)
            if r is None:
                continue
            if r.status_code == 200:
                ct = r.headers.get("Content-Type", "").lower()
                if "image/" in ct:
                    label = "Digest" if isinstance(auth, HTTPDigestAuth) else "Basic"
                    return True, f"Snapshot ({label} Auth)"
        return False, "Failed"

    def _try_rtsp(self):
        """RTSP DESCRIBE with Basic auth — checks for RTSP/1.0 200 OK exactly."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.TIMEOUT)
            sock.connect((self.ip, self.RTSP_PORT))

            rtsp_url = f"rtsp://{self.ip}:{self.RTSP_PORT}/cam/realmonitor?channel=1&subtype=0"
            auth_str = base64.b64encode(
                f"{self.username}:{self.password}".encode()
            ).decode()

            request = (
                f"DESCRIBE {rtsp_url} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"Authorization: Basic {auth_str}\r\n"
                "\r\n"
            )
            sock.send(request.encode())
            response = sock.recv(4096).decode(errors="ignore")

            if "RTSP/1.0 200 OK" in response:
                return True, "RTSP (Basic Auth)"
        except Exception:
            pass
        finally:
            if sock:
                try: sock.close()
                except: pass
        return False, "Failed"



# Keep old names for compatibility if needed, but point to new logic
class HikvisionValidator(CameraValidator):
    def validate(self):
        return super().validate(hint="Hikvision")

class DahuaValidator(CameraValidator):
    def validate(self):
        return super().validate(hint="Dahua")

# Configuration
CCTV_OUTPUT = "CCTV_Found.txt"

# Set a default timeout for socket connections
socket.setdefaulttimeout(0.25)

# Set to store detected IPs
detected_ips = set()

# Global control flags
stop_scan = False
pause_scan = False

# Thread-safety for printing
print_lock = threading.Lock()

def safe_print(msg, color=Fore.GREEN, end='\n'):
    """Thread-safe printer"""
    with print_lock:
        print(f"{color}{msg}{Style.RESET_ALL}", end=end)




def print_banner():
    """Display main banner with hacking green colors and box border (optimized for Termux)"""
    # Enable ANSI (important for Windows)
    os.system("")
    
    # Width optimized for mobile terminals (Termux)
    width = 60
    internal_width = width - 2 # 58
    
    glitch_intro()
    
    banner = [
        "███╗   ███╗██╗   ██╗███████╗██╗ ██████╗ ███╗   ██╗",
        "████╗ ████║██║   ██║██╔════╝██║██╔═══██╗████╗  ██║",
        "██╔████╔██║██║   ██║███████╗██║██║   ██║██╔██╗ ██║",
        "██║╚██╔╝██║██║   ██║╚════██║██║██║   ██║██║╚██╗██║",
        "██║ ╚═╝ ██║╚██████╔╝███████║██║╚██████╔╝██║ ╚████║",
        "╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝"
    ]

    # Hacking Green colors
    green = "\033[38;5;46m" # Intense Neon Green
    red_warning = "\033[91m"
    reset = "\033[0m"

    print(f"{green}╔" + "═" * internal_width + "╗")
    
    for line in banner:
        # Center the logo line
        left_pad = (internal_width - len(line)) // 2
        right_pad = internal_width - len(line) - left_pad
        print(f"║{' ' * left_pad}{green}{line}{' ' * right_pad}║")
        time.sleep(0.01) # Wipe effect

    print(f"║{' ' * internal_width}║")
    
    warning_text = "⚠ WARNING: USE FOR EDUCATIONAL PERMISSION ONLY"
    w_left_pad = (internal_width - len(warning_text)) // 2
    w_right_pad = internal_width - len(warning_text) - w_left_pad
    print(f"║{' ' * w_left_pad}{red_warning}{warning_text}{green}{' ' * w_right_pad}║")
    
    print(f"╚" + "═" * internal_width + f"╝{reset}")

    loading_spinner(0.6, "Infiltrating")
    typing_print(f"{green}[*] Developed by: {Fore.YELLOW}MSK{reset}", 0.01)
    typing_print(f"{green}[*] Termux Status: {Fore.CYAN}ONLINE ✓{reset}", 0.01)
    print()
def validate_ip(ip_str):
    """Validate IP address format"""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except:
        return False


def get_default_gateway():
    """Get the default gateway (router) IP address"""
    try:
        system = platform.system()
        
        if system == "Windows":
            # Windows command
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            output = result.stdout
            
            # Look for Default Gateway
            for line in output.split('\n'):
                if 'Default Gateway' in line or 'Default Gateway' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        gateway = parts[1].strip()
                        if gateway and gateway != '' and validate_ip(gateway):
                            return gateway
        
        elif system == "Linux" or system == "Darwin":  # Linux or macOS
            # Unix/Linux/Mac command
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            output = result.stdout
            
            # Look for default route
            for line in output.split('\n'):
                if 'default' in line:
                    parts = line.split()
                    if len(parts) > 2:
                        gateway = parts[2]
                        if validate_ip(gateway):
                            return gateway
            
            # Fallback for macOS
            result = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True)
            output = result.stdout
            for line in output.split('\n'):
                if 'gateway:' in line:
                    gateway = line.split(':')[1].strip()
                    if validate_ip(gateway):
                        return gateway
        
        return "Not Found"
    except:
        return "Not Found"


def get_local_ip():
    """Get local IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "Not Found"


def extract_title(html_content):
    """Extract title from HTML content"""
    try:
        match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        return "No Title Found"
    except:
        return "Error Extracting Title"




def get_camera_type(response_str, title, filter_mode=1):
    """
    Fingerprint camera and filter based on user choice.
    filter_mode: 1 = Show All, 2 = Only Cameras
    """
    t_low = title.lower().strip()
    r_low = response_str.lower()
    
    # 1. Check for Specific Camera Manufacturers/Categories
    camera_found = False
    cam_type = None
    
    # Priority Categories (Exact or near-exact match)
    if t_low == 'web' or t_low == 'web service' or '<title>web service</title>' in r_low:
        cam_type = "WEB" if t_low == 'web' else "WEB SERVICE"
        camera_found = True
    elif t_low == 'cplus' or 'cplus' in r_low or t_low == 'c+':
        cam_type = "CPlus"
        camera_found = True
    elif '301 moved' in r_low or '302 found' in r_low or 'object moved' in r_low:
        # If it's a redirect, check if the redirect page itself has hints
        if 'dahua' in r_low or 'dh-' in r_low:
             cam_type = "DAHUA (Redirect)"
             camera_found = True
        elif 'hikvision' in r_low or 'isapi' in r_low:
             cam_type = "HIKVISION (Redirect)"
             camera_found = True
    
    # Major Brands
    if not camera_found:
        if 'hikvision' in r_low or 'hikvision' in t_low or '/isapi/' in r_low:
            cam_type = "HIKVISION"
            camera_found = True
        elif 'dahua' in r_low or 'dahua' in t_low or 'dh-' in t_low or 'dh-' in r_low:
            cam_type = "DAHUA"
            camera_found = True
        elif 'axis' in t_low or 'axis network' in t_low or 'axis.com' in r_low:
            cam_type = "AXIS"
            camera_found = True
        elif ('sony' in t_low or 'sony' in r_low) and 'camera' in t_low:
            cam_type = "SONY"
            camera_found = True
        elif ('bosch' in t_low or 'bosch' in r_low) and 'camera' in t_low:
            cam_type = "BOSCH"
            camera_found = True
            
    # Generic IP Camera Fingerprints
    if not camera_found:
        if any(x in t_low for x in ['ip camera', 'ip cam', 'network camera', 'ipcam', 'dvr', 'nvr']):
            cam_type = "IP CAMERA"
            camera_found = True
        elif 'h.264' in t_low or 'monitoring system' in t_low or 'view.html' in r_low or 'net.html' in r_low:
            cam_type = "GENERIC CAMERA"
            camera_found = True
            
    # Handle Filtering
    if camera_found:
        return cam_type
        
    # If mode is 2 (Strict), stop here if no camera match found
    if filter_mode == 2:
        return None
        
    # Regular detection for "Show All" (Mode 1) - Login pages etc.
    if 'login' in t_low or 'index.html' in r_low:
        return "Camera - Login"
        
    return None


def trace_route():
    """Trace route to a domain/IP"""
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[🔍] TRACE ROUTE MODE [🔍]{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
    
    # Automatically use google.com as target
    target = "google.com"
    
    print(f"{Fore.GREEN}[i] Target: {Fore.CYAN}{target}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Tracing route to {Fore.CYAN}{target}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Please wait...{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}{'─'*50}{Style.RESET_ALL}\n")
    
    try:
        system = platform.system()
        
        if system == "Windows":
            # Windows tracert command (fast mode with max 30 hops)
            cmd = ['tracert', '-d', '-h', '30', '-w', '1000', target]
        else:
            # Linux/macOS/Termux traceroute command
            # Try multiple commands in order of preference
            cmd = None
            
            # Try traceroute first
            try:
                result = subprocess.run(['traceroute', '--version'], capture_output=True, timeout=2)
                cmd = ['traceroute', '-n', '-m', '30', '-w', '1', target]
            except:
                pass
            
            # Try tracepath as fallback
            if cmd is None:
                try:
                    result = subprocess.run(['tracepath', '-V'], capture_output=True, timeout=2)
                    cmd = ['tracepath', '-n', target]
                except:
                    pass
            
            # If nothing works, default to traceroute (will show error if not found)
            if cmd is None:
                cmd = ['traceroute', '-n', '-m', '30', '-w', '1', target]
        
        # Run the command and display output in real-time
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        hop_count = 0
        for line in iter(process.stdout.readline, ''):
            if line:
                line = line.strip()
                
                # Color code the output
                if '*' in line or 'timeout' in line.lower():
                    print(f"{Fore.RED}{line}{Style.RESET_ALL}")
                elif 'ms' in line.lower() or 'Tracing' in line or 'traceroute' in line:
                    # Highlight successful hops
                    if any(char.isdigit() for char in line) and ('ms' in line.lower() or '<' in line):
                        hop_count += 1
                        print(f"{Fore.GREEN}[Hop {hop_count:2d}] {line}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.CYAN}{line}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.WHITE}{line}{Style.RESET_ALL}")
        
        process.wait()
        
        print(f"\n{Fore.CYAN}{'─'*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Trace complete!{Style.RESET_ALL}")
        
        if hop_count > 0:
            print(f"{Fore.CYAN}[i] Total hops: {hop_count}{Style.RESET_ALL}")
        
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Traceroute command not found on this system{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[i] For Termux, install: pkg install inetutils{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[i] Or install: pkg install traceroute{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")


def super_fast_scan(gui_start_ip=None, gui_end_ip=None, gui_filter_mode=None):
    """Super fast scan with full threading power"""
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.RED}[⚡] SUPER FAST SCAN MODE [⚡]{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}[i] Maximum performance mode enabled{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[i] Uses multi-threading for ultra-fast scanning{Style.RESET_ALL}\n")
    
    print(f"{Fore.CYAN}Examples:{Style.RESET_ALL}")
    print(f"  Single IP: 192.168.1.1")
    print(f"  IP Range: 192.168.1.1 to 192.168.1.255\n")
    
    # Get start IP or CIDR
    if gui_start_ip is not None:
        start_ip = gui_start_ip
        end_ip = gui_end_ip if gui_end_ip is not None else ""
        filter_mode = gui_filter_mode if gui_filter_mode is not None else 1
    else:
        print(f"{Fore.CYAN}Options for Scan Output:{Style.RESET_ALL}")
        print(f"  1. Show all (Diagnostic Mode)")
        print(f"  2. Show only cameras (Stricter Filter)")
        
        while True:
            f_choice = input(f"{Fore.GREEN}Select option (1/2): {Style.RESET_ALL}").strip()
            if f_choice in ['1', '2']:
                filter_mode = int(f_choice)
                break
            print(f"{Fore.RED}[!] Invalid choice!{Style.RESET_ALL}")

        while True:
            start_ip = input(f"{Fore.GREEN}Enter Start IP or CIDR (e.g. 192.168.1.0/24): {Style.RESET_ALL}").strip()
            if '/' in start_ip:
                try:
                    ipaddress.IPv4Network(start_ip, strict=False)
                    break
                except:
                    print(f"{Fore.RED}[!] Invalid CIDR format!{Style.RESET_ALL}")
                    continue
            if not validate_ip(start_ip):
                print(f"{Fore.RED}[!] Invalid IP address format!{Style.RESET_ALL}")
                continue
            break
        
        # Get end IP (only if no CIDR)
        if '/' not in start_ip:
            end_ip = input(f"{Fore.GREEN}Enter End IP (press Enter for single IP): {Style.RESET_ALL}").strip()
        else:
            end_ip = ""
    
    # Generate IP generator (memory efficient)
    def ip_generator():
        if '/' in start_ip:
            try:
                network = ipaddress.IPv4Network(start_ip, strict=False)
                for ip in network:
                    yield str(ip)
            except:
                yield start_ip.split('/')[0]
        elif not end_ip:
            yield start_ip
        else:
            if not validate_ip(end_ip):
                yield start_ip
            else:
                start_int = int(ipaddress.IPv4Address(start_ip))
                end_int = int(ipaddress.IPv4Address(end_ip))
                
                if start_int > end_int:
                    yield start_ip
                else:
                    for ip_int in range(start_int, end_int + 1):
                        yield str(ipaddress.IPv4Address(ip_int))

    # Calculate count for display (still useful, but avoid list materialization if possible)
    # If network is too large, we just say "Large Subnet"
    try:
        if '/' in start_ip:
            total_count = ipaddress.IPv4Network(start_ip, strict=False).num_addresses
        elif not end_ip:
            total_count = 1
        else:
            total_count = int(ipaddress.IPv4Address(end_ip)) - int(ipaddress.IPv4Address(start_ip)) + 1
    except:
        total_count = "Unknown"
    
    print(f"\n{Fore.GREEN}[✓] Total IPs to scan: {total_count}{Style.RESET_ALL}")
    
    # Auto-detect optimal thread count — cap lower for Termux/mobile compatibility
    cpu_count = multiprocessing.cpu_count()
    max_threads = min(300, cpu_count * 30)  # Balanced for desktop and mobile
    
    loading_spinner(0.8, "Deploying Threads")
    
    print(f"{Fore.CYAN}[i] CPU Cores: {cpu_count}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[i] Threads: {max_threads}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Starting super fast scan...{Style.RESET_ALL}\n")
    
    ports = [80, 8080]
    results = []
    results_lock = threading.Lock()
    scan_queue = Queue()
    
    # Worker function for threading
    def worker():
        # Session for connection pooling (only if requests is installed)
        session = None
        if HAS_REQUESTS:
            session = requests.Session()
            session.verify = False
            adapter = requests.adapters.HTTPAdapter(pool_connections=max_threads, pool_maxsize=max_threads)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

        while True:
            try:
                ip, port = scan_queue.get(timeout=0.5)
                
                try:
                    # 1. Quick port check first to avoid overhead on closed ports
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.4)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    
                    if result == 0:
                        url = f"http://{ip}:{port}"
                        response_full = ""
                        title = "No Title Found"
                        server = "Unknown"
                        final_url = url

                        if HAS_REQUESTS and session:
                            # 2a. Use requests for robust HTTP/HTTPS/Redirect handling
                            try:
                                resp = session.get(url, timeout=2.5, allow_redirects=True, stream=True)
                                content_chunks = []
                                content_len = 0
                                for chunk in resp.iter_content(chunk_size=4096):
                                    content_chunks.append(chunk)
                                    content_len += len(chunk)
                                    if content_len > 32768: break
                                response_body = b"".join(content_chunks).decode('utf-8', errors='ignore')
                                response_full = f"HTTP/1.1 {resp.status_code}\n"
                                for k, v in resp.headers.items():
                                    response_full += f"{k}: {v}\n"
                                response_full += "\n" + response_body
                                title = extract_title(response_body)
                                server = resp.headers.get('Server', 'Unknown')
                                final_url = resp.url
                            except Exception:
                                pass
                        else:
                            # 2b. Fallback: raw socket HTTP (no redirect following)
                            try:
                                http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                http_sock.settimeout(2.0)
                                http_sock.connect((ip, port))
                                request = f'GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n'
                                http_sock.send(request.encode())
                                raw = b''
                                while True:
                                    data = http_sock.recv(4096)
                                    if not data: break
                                    raw += data
                                    if len(raw) > 32768: break
                                http_sock.close()
                                response_full = raw.decode('utf-8', errors='ignore')
                                title = extract_title(response_full)
                                server_match = re.search(r'Server: ([^\r\n]+)', response_full, re.IGNORECASE)
                                server = server_match.group(1) if server_match else "Unknown"
                            except Exception:
                                try:
                                    http_sock.close()
                                except Exception:
                                    pass

                        if response_full:
                            camera_type = get_camera_type(response_full, title, filter_mode)
                            if camera_type:
                                with results_lock:
                                    results.append({
                                        'ip': ip, 'port': port, 'title': title,
                                        'server': server, 'url': final_url, 'type': camera_type
                                    })
                                    safe_print(f"[✓] Camera Found: {ip}:{port} - {camera_type} ({title[:30]})", Fore.GREEN)
                except Exception:
                    pass
                
                scan_queue.task_done()
            except:
                break

    
    # Start threads
    threads = []
    for _ in range(max_threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    
    # Queue all IP:port combinations using the generator
    start_time = time.time()
    for ip in ip_generator():
        for port in ports:
            scan_queue.put((ip, port))
    
    # Wait for completion
    scan_queue.join()
    elapsed = time.time() - start_time
    
    # Display completion summary
    print(f"\n{Fore.CYAN}{'═'*50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] SUPER FAST SCAN COMPLETE!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*50}{Style.RESET_ALL}\n")
    
    if results:
        if gui_start_ip is None:
            # Post-scan: offer credential testing on found cameras
            brute_forcible = [r for r in results if r['type'] not in ["Camera - Login"]]
            if brute_forcible:
                print(f"{Fore.YELLOW}[!] Found {len(brute_forcible)} cameras compatible with default credential testing.{Style.RESET_ALL}")
                choice = input(f"{Fore.GREEN}Would you like to try default credentials on them? (y/n): {Style.RESET_ALL}").lower().strip()
                if choice == 'y':
                    brute_force_cameras(brute_forcible)
        
        # Save to file
        try:
            with open("SuperFastScan_Results.txt", 'w', encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write("SUPER FAST SCAN - CAMERAS FOUND\n")
                f.write("="*60 + "\n\n")
                for r in results:
                    f.write(f"IP: {r['ip']}:{r['port']}\n")
                    f.write(f"Title: {r['title']}\n")
                    f.write(f"Server: {r['server']}\n")
                    f.write(f"Type: {r['type']}\n")
                    f.write(f"URL: {r['url']}\n")
                    f.write("-"*60 + "\n\n")
            print(f"{Fore.GREEN}[✓] Results saved to: SuperFastScan_Results.txt{Style.RESET_ALL}")
        except:
            pass
    else:
        print(f"{Fore.YELLOW}[!] No cameras found{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}[i] Total IPs scanned: {total_count}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[i] Time taken: {elapsed:.2f} seconds{Style.RESET_ALL}")
    
    if gui_start_ip is None:
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
    return results


def brute_force_cameras(camera_list, output_widget=None):
    """Try default credentials on a list of cameras in parallel"""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def log(msg, color=Fore.GREEN):
        if output_widget:
            output_widget.insert('end', msg + "\n")
            output_widget.see('end')
        else:
            safe_print(msg, color)

    if not camera_list:
        log("[-] No cameras to test.", Fore.YELLOW)
        return

    log(f"\n[*] Starting multi-threaded default credential test on {len(camera_list)} cameras...", Fore.YELLOW)
    
    success_count = 0
    results_lock = threading.Lock()

    def test_single_camera(cam):
        nonlocal success_count
        ip = cam['ip']
        port = cam['port']
        cam_type = cam['type']
        
        log(f"[*] Testing {ip}:{port} ({cam_type})...", Fore.CYAN)
        
        found_login = False
        for user, pwd in DEFAULT_CREDENTIALS:
            try:
                validator = CameraValidator(ip, user, pwd, port)
                success, msg = validator.validate(hint=cam_type)
                
                if success:
                    log(f"    [+] SUCCESS: {ip}:{port} | {user}:{pwd} ({msg})", Fore.GREEN)
                    with results_lock:
                        success_count += 1
                    found_login = True
                    break
            except Exception as e:
                pass
        
        if not found_login:
            log(f"    [-] No match for {ip}:{port}", Fore.RED)

    # Use ThreadPoolExecutor for parallel testing
    max_workers = min(10, len(camera_list)) # Don't overwhelm with too many threads
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(test_single_camera, cam) for cam in camera_list]
        for future in as_completed(futures):
            pass # Wait for all to finish
            
    log(f"\n[✓] Credential test complete. Found {success_count} matches.", Fore.GREEN)
    if not output_widget:
        input(f"\n{Fore.CYAN}[!] Press Enter to continue...{Style.RESET_ALL}")


def scan(ip, port):
    """Scan a specific IP and port for cameras"""
    global stop_scan, pause_scan
    
    # Check if scan should stop
    if stop_scan:
        return
    
    # Wait while paused
    while pause_scan and not stop_scan:
        time.sleep(0.1)
    
    if stop_scan:
        return
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((ip, port))
            sock.send(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
            response = sock.recv(4096).decode()
            
            camera_found = False
            camera_type = ""
            url = f"http://{ip}:{port}" if port == 8080 else f"http://{ip}"
            
            if 'HTTP' in response and '<title>WEB SERVICE</title>' in response:
                if ip not in detected_ips:
                    detected_ips.add(ip)
                    camera_type = "Anjhua-Dahua Technology Camera"
                    camera_found = True
                    safe_print(f"[✓] {camera_type} Found! at {url}", Fore.GREEN)
                    
            elif 'HTTP' in response and 'login.asp' in response:
                if ip not in detected_ips:
                    detected_ips.add(ip)
                    camera_type = "HIK Vision Camera"
                    camera_found = True
                    safe_print(f"[✓] {camera_type} Found! at {url}", Fore.RED)
            
            # Live save to file
            if camera_found:
                try:
                    with open(CCTV_OUTPUT, 'a', encoding='utf-8') as file:
                        file.write(f"{'='*60}\n")
                        file.write(f"Camera Type: {camera_type}\n")
                        file.write(f"IP Address: {ip}\n")
                        file.write(f"Port: {port}\n")
                        file.write(f"URL: {url}\n")
                        file.write(f"Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        file.write(f"{'='*60}\n\n")
                        file.flush()  # Force write to disk immediately (live save)
                except Exception as e:
                    pass
                    
    except Exception as e:
        pass


def execute(queue):
    """Execute the scan from the queue"""
    global stop_scan
    try:
        while not stop_scan:
            try:
                ip, port = queue.get(timeout=0.5)
                scan(ip, port)
                queue.task_done()
            except:
                if stop_scan:
                    break
                continue
    except KeyboardInterrupt:
        stop_scan = True
        return


def signal_handler_stop(signum, frame):
    """Handle Ctrl+C - Immediate stop"""
    global stop_scan
    stop_scan = True
    print(f"\n\n{Fore.RED}[!] Ctrl+C detected - STOPPING IMMEDIATELY...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Cleaning up threads...{Style.RESET_ALL}")
    sys.exit(0)


def signal_handler_pause(signum, frame):
    """Handle Ctrl+Z - Pause/Resume"""
    global pause_scan
    pause_scan = not pause_scan
    if pause_scan:
        print(f"\n\n{Fore.YELLOW}[⏸] SCAN PAUSED - Press Ctrl+Z again to resume...{Style.RESET_ALL}\n")
    else:
        print(f"\n\n{Fore.GREEN}[▶] SCAN RESUMED - Continuing...{Style.RESET_ALL}\n")


def run_scanner(ip_list):
    """Run the IP scanner"""
    global stop_scan, pause_scan
    
    # Reset flags
    stop_scan = False
    pause_scan = False
    
    # Register signal handlers
    try:
        signal.signal(signal.SIGINT, signal_handler_stop)  # Ctrl+C
        if hasattr(signal, 'SIGTSTP'):  # Unix/Linux/Mac
            signal.signal(signal.SIGTSTP, signal_handler_pause)  # Ctrl+Z
    except:
        pass  # Windows might not support SIGTSTP
    
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Starting Camera Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}[*] Controls:{Style.RESET_ALL}")
    print(f"  {Fore.RED}Ctrl+C{Style.RESET_ALL} - Stop scan immediately")
    if hasattr(signal, 'SIGTSTP'):
        print(f"  {Fore.YELLOW}Ctrl+Z{Style.RESET_ALL} - Pause/Resume scan")
    print()
    
    print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Starting scan on ports 80 and 8080...")
    print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Results will be saved to {Fore.GREEN}{CCTV_OUTPUT}{Style.RESET_ALL} (Live Save)\n")
    
    queue = Queue()
    start_time = time.time()
    
    # Create worker threads
    threads = []
    for _ in range(100):
        thread = threading.Thread(target=execute, args=(queue,), daemon=True)
        thread.start()
        threads.append(thread)
    
    # Enqueue IPs and ports for scanning
    try:
        total_ips = 0
        for ip in ip_list:
                if stop_scan:
                    break
                queue.put((ip, 80))
                queue.put((ip, 8080))
                total_ips += 1
        
        if not stop_scan:
            print(f"\n{Fore.GREEN}[✓]{Style.RESET_ALL} Queued {total_ips} IPs for scanning")
            print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Scanning in progress...\n")
            
            # Wait for all tasks to complete or stop signal
            while not stop_scan and not queue.empty():
                time.sleep(0.5)
        
    except KeyboardInterrupt:
        stop_scan = True
        print(f"\n\n{Fore.YELLOW}[!]{Style.RESET_ALL} Ctrl+C detected. Stopping...")
    except Exception as e:
        print(f"\n{Fore.RED}[!]{Style.RESET_ALL} Error: {e}")
    
    # Mark as stopped
    stop_scan = True
    time.sleep(1)  # Give threads time to finish
    
    elapsed_time = time.time() - start_time
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] Scan Complete!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Time taken: {elapsed_time:.2f} seconds")
    print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Cameras found: {len(detected_ips)}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")


def get_subnet():
    """Get local subnet"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ".".join(ip.split(".")[:3])
    except:
        return None


def is_rtsp(ip):
    """Check if RTSP port 554 is open"""
    try:
        s = socket.socket()
        s.settimeout(0.3)
        ok = s.connect_ex((ip, 554)) == 0
        s.close()
        return ok
    except:
        return False


def dahua_name(ip):
    """Get Dahua camera name"""
    sock = None
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((ip, 37777))
        data = sock.recv(512).decode(errors="ignore")
        m = re.search(r"DH-[A-Z0-9\-]+", data)
        if m: return m.group(0)
    except:
        pass
    finally:
        if sock: sock.close()
    return None


def hikvision_name(ip):
    """Get Hikvision camera name"""
    sock = None
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((ip, 8000))
        data = sock.recv(512).decode(errors="ignore")
        if "Hikvision" in data: return "HIKVISION CAMERA"
    except:
        pass
    finally:
        if sock: sock.close()
    return None


def scan_rtsp_ip(ip, results, results_lock):
    """Scan single IP for RTSP camera"""
    if not is_rtsp(ip):
        return
    
    name = (
        dahua_name(ip)
        or hikvision_name(ip)
        or "RTSP CAMERA"
    )
    
    with results_lock:
        results.append({
            'ip': ip,
            'name': name,
            'rtsp_url': f"rtsp://{ip}:554"
        })
        safe_print(f"[✓] Camera Found: {ip} - {name}", Fore.GREEN)


def neighbours_camera_scanner():
    """Scan local network for RTSP cameras"""
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[📷] NEIGHBOURS CAMERA SCANNER [📷]{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
    
    subnet = get_subnet()
    if not subnet:
        print(f"{Fore.RED}[!] Could not detect local subnet!{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[i] Detected Subnet: {Fore.CYAN}{subnet}.x{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Scanning for RTSP cameras (port 554)...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] This may take a few minutes...{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}{'─'*50}{Style.RESET_ALL}\n")
    
    ips = [f"{subnet}.{i}" for i in range(1, 255)]
    results = []
    results_lock = threading.Lock()
    
    # Worker function
    def worker(ip_list):
        for ip in ip_list:
            scan_rtsp_ip(ip, results, results_lock)
    
    # Create threads
    THREADS = 80
    chunks = [ips[i::THREADS] for i in range(THREADS)]
    threads = []
    
    start_time = time.time()
    
    for chunk in chunks:
        t = threading.Thread(target=worker, args=(chunk,), daemon=True)
        t.start()
        threads.append(t)
    
    # Wait for all threads
    for t in threads:
        t.join()
    
    elapsed = time.time() - start_time
    
    # Display results
    print(f"\n{Fore.CYAN}{'═'*50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] SCAN COMPLETE!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═'*50}{Style.RESET_ALL}\n")
    
    if results:
        # Save to file
        try:
            with open("NeighboursCameras_Results.txt", 'w', encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write("NEIGHBOURS CAMERA SCAN - RTSP CAMERAS FOUND\n")
                f.write("="*60 + "\n\n")
                for r in results:
                    f.write(f"IP: {r['ip']}\n")
                    f.write(f"Name: {r['name']}\n")
                    f.write(f"RTSP URL: {r['rtsp_url']}\n")
                    f.write("-"*60 + "\n\n")
            print(f"{Fore.GREEN}[✓] Results saved to: NeighboursCameras_Results.txt{Style.RESET_ALL}")
        except:
            pass
    else:
        print(f"{Fore.YELLOW}[!] No RTSP cameras found on local network{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}[i] Total IPs scanned: 254{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[i] Cameras found: {len(results)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[i] Time taken: {elapsed:.2f} seconds{Style.RESET_ALL}")
    input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")


def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_menu():
    """Print main menu with cinematic wipe"""
    print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    typing_print(f"{Fore.GREEN}Select Mode:{Style.RESET_ALL}", 0.01)
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
    
    menu_ops = [
        f"{Fore.YELLOW}1.{Style.RESET_ALL} 🔍 Trace Route",
        f"{Fore.RED}2.{Style.RESET_ALL} ⚡ SUPER FAST SCAN (Camera Scanner)",
        f"{Fore.GREEN}3.{Style.RESET_ALL} 📷 Neighbours Camera Scanner",
        f"{Fore.YELLOW}4.{Style.RESET_ALL} Exit"
    ]
    
    for op in menu_ops:
        print(op)
        
    print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")



def run_gui():
    import tkinter as tk
    from tkinter import scrolledtext, simpledialog, messagebox
    import threading
    import sys
    import re
    import time

    root = tk.Tk()
    root.title("MSK Camera Scanner")
    root.geometry("850x650")
    root.configure(bg="black")

    # Hacker style styling
    bg_color = "black"
    fg_color = "#00FF00"  # Authentic CRT Green
    font_main = ("Consolas", 10)
    font_btn = ("Consolas", 12, "bold")

    # Warning Label
    warning_lbl = tk.Label(root, text="⚠️ WARNING: Do not use this tool without MSK's permission.", 
                           fg="yellow", bg="black", font=("Consolas", 12, "bold"))
    warning_lbl.pack(pady=10)

    # MUSION Logo for GUI (using Text for gradient)
    logo_frame = tk.Frame(root, bg="black")
    logo_frame.pack(pady=5)
    
    txt_logo = tk.Text(logo_frame, bg="black", fg="white", font=("Consolas", 6),
                       height=10, width=70, relief=tk.FLAT, highlightthickness=0)
    txt_logo.pack()

    musion_text = """╔═════════════════════════════════════════════════════════════════╗
║                                                                 ║
║   ███╗   ███╗██╗   ██╗███████╗██╗ ██████╗ ███╗   ██╗            ║
║   ████╗ ████║██║   ██║██╔════╝██║██╔═══██╗████╗  ██║            ║
║   ██╔████╔██║██║   ██║███████╗██║██║   ██║██╔██╗ ██║            ║
║   ██║╚██╔╝██║██║   ██║╚════██║██║██║   ██║██║╚██╗██║            ║
║   ██║ ╚═╝ ██║╚██████╔╝███████║██║╚██████╔╝██║ ╚████║            ║
║   ╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝            ║
║                                                                 ║
╚═════════════════════════════════════════════════════════════════╝"""
    txt_logo.insert(tk.END, musion_text)
    
    # Hacking Green logo tags
    txt_logo.tag_config("green", foreground="#00FF00")
    txt_logo.tag_add("green", "1.0", tk.END)

    txt_logo.config(state=tk.DISABLED)

    # Title Label
    title_lbl = tk.Label(root, text="MSK CAMERA SCANNER - Developed by MSK",
                         fg=fg_color, bg="black", font=("Consolas", 12, "bold"))
    title_lbl.pack(pady=5)

    # Output text area
    txt_out = scrolledtext.ScrolledText(root, bg=bg_color, fg=fg_color, font=font_main, height=20)
    txt_out.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    class StdoutRedirector:
        def __init__(self, text_widget):
            self.text_space = text_widget
            self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        def write(self, string):
            clean = self.ansi_escape.sub('', string)
            self.text_space.insert(tk.END, clean)
            self.text_space.see(tk.END)
            self.text_space.update_idletasks()
        def flush(self):
            pass

    sys.stdout = StdoutRedirector(txt_out)
    sys.stderr = sys.stdout

    found_cameras_store = []

    def run_in_thread(target, *args):
        # Disable buttons while running
        for btn in buttons:
            btn.config(state=tk.DISABLED)
        txt_out.delete(1.0, tk.END)
        
        def thread_task():
            nonlocal found_cameras_store
            try:
                res = target(*args)
                if isinstance(res, list):
                    found_cameras_store = res
            except Exception as e:
                print(f"\nError: {e}")
            finally:
                for btn in buttons:
                    btn.config(state=tk.NORMAL)
        
        t = threading.Thread(target=thread_task)
        t.daemon = True
        t.start()

    def do_trace_route():
        run_in_thread(trace_route)

    def do_super_fast_scan():
        filter_mode = simpledialog.askinteger("Option", "Select Mode:\n1. Show All (Diagnostic)\n2. Show Only Cameras (Brands & Generic)", parent=root, minvalue=1, maxvalue=2)
        if filter_mode is None: return
        
        start_ip = simpledialog.askstring("Input", "Enter Start IP or CIDR:\n(e.g., 192.168.1.1 or 192.168.1.0/24)", parent=root)
        if not start_ip: return
        
        end_ip = ""
        if '/' not in start_ip:
            if not validate_ip(start_ip.strip()):
                messagebox.showerror("Error", "Invalid IP address format!")
                return
            end_ip = simpledialog.askstring("Input", "Enter End IP (Optional):\nLeave blank for single IP:", parent=root)
            if end_ip and not validate_ip(end_ip.strip()):
                messagebox.showerror("Error", "Invalid IP address format!")
                return
            
        run_in_thread(super_fast_scan, start_ip.strip(), end_ip.strip() if end_ip else "", filter_mode)

    def do_neighbours_camera_scanner():
        run_in_thread(neighbours_camera_scanner)

    def do_brute_force():
        brute_forcible = [r for r in found_cameras_store if r.get('type') not in ["Camera - Login"]]
        if not brute_forcible:
            messagebox.showinfo("Wait", "No compatible cameras found in last scan.", parent=root)
            return
        
        if not messagebox.askyesno("Confirm", f"Try default credentials on {len(brute_forcible)} found cameras?", parent=root):
            return
            
        run_in_thread(brute_force_cameras, brute_forcible, txt_out)

    btn_frame = tk.Frame(root, bg="black")
    btn_frame.pack(fill=tk.X, pady=10)

    buttons = []
    
    btn1 = tk.Button(btn_frame, text="🔍 Trace Route", command=do_trace_route, 
                     bg="#111111", fg=fg_color, font=font_btn, relief=tk.FLAT, activebackground="#222222", activeforeground=fg_color)
    btn1.pack(side=tk.LEFT, expand=True, padx=5)
    buttons.append(btn1)
    
    btn2 = tk.Button(btn_frame, text="⚡ SUPER FAST SCAN", command=do_super_fast_scan, 
                     bg="#111111", fg=fg_color, font=font_btn, relief=tk.FLAT, activebackground="#222222", activeforeground=fg_color)
    btn2.pack(side=tk.LEFT, expand=True, padx=5)
    buttons.append(btn2)
    
    btn3 = tk.Button(btn_frame, text="📷 Neighbours Scanner", command=do_neighbours_camera_scanner, 
                     bg="#111111", fg=fg_color, font=font_btn, relief=tk.FLAT, activebackground="#222222", activeforeground=fg_color)
    btn3.pack(side=tk.LEFT, expand=True, padx=5)
    buttons.append(btn3)

    btn4 = tk.Button(btn_frame, text="🔑 Try Credentials", command=do_brute_force, 
                     bg="#111111", fg="#FFFF00", font=font_btn, relief=tk.FLAT, activebackground="#222222", activeforeground="#FFFF00")
    btn4.pack(side=tk.LEFT, expand=True, padx=5)
    buttons.append(btn4)

    print("[*] GUI Loaded successfully. Welcome to MSK Camera Scanner.")
    root.mainloop()

def environment_has_gui():
    import os
    import platform
    
    # Check Termux
    if "PREFIX" in os.environ and "com.termux" in os.environ["PREFIX"]:
        return False
        
    system = platform.system()
    if system == "Windows" or system == "Darwin":
        return True
    elif system == "Linux":
        if "DISPLAY" in os.environ or "WAYLAND_DISPLAY" in os.environ:
            return True
    return False

def main():
    """Main function"""
    if environment_has_gui():
        try:
            import tkinter
            run_gui()
            return
        except ImportError:
            pass

    while True:
        try:
            # Clear screen at start
            clear_screen()
            
            print_banner()
            
            # Display system info
            try:
                timestamp = datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')
                print(f"{Fore.GREEN}[i]{Style.RESET_ALL} Time: {Fore.YELLOW}{timestamp}{Style.RESET_ALL}")
            except:
                pass
            
            # Display network info
            try:
                gateway = get_default_gateway()
                local_ip = get_local_ip()
                print(f"{Fore.GREEN}[i]{Style.RESET_ALL} Your Local IP: {Fore.CYAN}{local_ip}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[i]{Style.RESET_ALL} Router Gateway: {Fore.CYAN}{gateway}{Style.RESET_ALL}")
            except:
                pass
            
            # Show menu
            print_menu()
            choice = input(f"{Fore.GREEN}Enter your choice (1-4): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                # Trace Route
                trace_route()
                
            elif choice == '2':
                # Super Fast Scan
                super_fast_scan()
                
            elif choice == '3':
                # Neighbours Camera Scanner
                neighbours_camera_scanner()
                
            elif choice == '4':
                # Exit
                print(f"\n{Fore.GREEN}[✓] Goodbye!{Style.RESET_ALL}\n")
                break
                
            else:
                print(f"{Fore.RED}[!] Invalid choice. Please select 1-4.{Style.RESET_ALL}")
                time.sleep(1)
        
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
            time.sleep(2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)


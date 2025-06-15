import ctypes
import sys
import json
import time
import threading
from datetime import datetime
import pydivert

# Admin check & elevation
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    params = ' '.join([f'"{arg}"' for arg in sys.argv])
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1)
    sys.exit()

blocklist_file = "block_list.json"
block_list_lock = threading.Lock()

try:
    with open(blocklist_file, "r") as f:
        block_list = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    block_list = {}

def save_blocklist():
    with block_list_lock:
        with open(blocklist_file, "w") as f:
            json.dump(block_list, f, indent=2)

def block_ip(ip, duration=60):
    with block_list_lock:
        block_list[ip] = {
            "blocked_at": datetime.now().isoformat(),
            "duration": duration
        }
    save_blocklist()
    print(f"[+] Blocked IP {ip} for {duration} seconds.")

def unblock_expired_ips():
    while True:
        now = datetime.now()
        expired = []
        with block_list_lock:
            for ip, info in block_list.items():
                try:
                    blocked_time = datetime.fromisoformat(info["blocked_at"])
                    if (now - blocked_time).total_seconds() >= info["duration"]:
                        expired.append(ip)
                except Exception as e:
                    print(f"[!] Error parsing time for IP {ip}: {e}")

            if expired:
                for ip in expired:
                    print(f"[✓] Unblocked IP {ip} after timeout.")
                    del block_list[ip]
                save_blocklist()
        time.sleep(5)

def ip_block_check(ip):
    with block_list_lock:
        return ip in block_list

def start_firewall_loop():
    try:
        with pydivert.WinDivert("true") as w:
            print("[*] Firewall loop started. Monitoring traffic...")
            while True:
                try:
                    packet = w.recv()
                    src_ip = packet.src_addr
                    dst_ip = packet.dst_addr

                    # Optional: Do not block localhost traffic
                    if src_ip.startswith("127.") or dst_ip.startswith("127."):
                        w.send(packet)
                        continue

                    if ip_block_check(src_ip) or ip_block_check(dst_ip):
                        # You can remove this print or limit its frequency if noisy
                        print(f"[DROP] {src_ip} -> {dst_ip}")
                        # Drop packet silently
                        continue
                    else:
                        w.send(packet)

                except Exception as e:
                    print(f"[!] Error processing packet: {e}")
    except Exception as e:
        print(f"[!] Firewall loop error: {e}")

def start_prevention():
    threading.Thread(target=unblock_expired_ips, daemon=True).start()
    threading.Thread(target=start_firewall_loop, daemon=True).start()

def main():
    print("[*] Starting IP blocker...")
    ip_to_block = "8.8.8.8"
    block_duration = 30  

    block_ip(ip_to_block, duration=block_duration)
    start_prevention()

    print("[*] Running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Exiting.")

if __name__ == "__main__":
    main()

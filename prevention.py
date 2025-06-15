import ctypes
import subprocess
import time
import sys
import threading
import json
from datetime import datetime


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def request_uac():
        command = 'powershell -Command "Start-Process cmd.exe -ArgumentList \'/c exit\' -Verb runAs"'
        try:
            subprocess.run(command, shell=True)
        except Exception as e:
            print(f"[!] Failed to show UAC prompt: {e}")  

def run_powershell(command):
    try:
        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"[!] PowerShell error: {result.stderr.strip()}")
            return None
    except Exception as e:
        print(f"[!] Exception while running PowerShell: {e}")
        return None

def is_ip_blocked(ip):
    rule_name = f"ShieldAI_Block_{ip}"
    command = f'Get-NetFirewallRule -DisplayName "{rule_name}"'
    output = run_powershell(command)
    return rule_name in output if output else False

def block_ip(ip):
    rule_name = f"ShieldAI_Block_{ip}"
    if is_ip_blocked(ip):
        print(f"[i] IP {ip} is already blocked.")
        return

    print(f"[*] Blocking IP {ip}...")
    command = f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -RemoteAddress {ip} -Action Block'
    if run_powershell(command):
        print(f"[✓] IP {ip} successfully blocked.")

def unblock_ip(ip):
    rule_name = f"ShieldAI_Block_{ip}"
    if not is_ip_blocked(ip):
        print(f"[i] IP {ip} is not currently blocked.")
        return

    print(f"[*] Unblocking IP {ip}...")
    command = f'Remove-NetFirewallRule -DisplayName "{rule_name}"'
    if run_powershell(command):
        print(f"[✓] IP {ip} successfully unblocked.")

def apply_prevention(attack_type, ip_address, block_duration=300):
    if attack_type != "BENIGN":
        print(f"[INFO] Blocking IP {ip_address} for {block_duration} seconds due to {attack_type}.")
        block_ip(ip_address)
        
        block_list[ip_address] = {
            "blocked_at": datetime.now().isoformat(),  
            "duration": block_duration
        }
        save_blocklist()

def ip_block_check(ip):
    """Check if the given IP is already present in the ShieldAI block list (block_list.json)."""
    load_blocklist()  # Ensure the latest version is loaded

    if ip in block_list:
        print(f"[✓] IP {ip} is already present in the block list.")
        return True
    else:
        print(f"[i] IP {ip} is not in the block list.")
        return False

def monitor_block_list():
    while True:
        now = datetime.now()
        to_unblock = []

        for ip, info in block_list.items():
            blocked_at = datetime.fromisoformat(info["blocked_at"])
            elapsed = (now - blocked_at).total_seconds()
            if elapsed >= info["duration"]:
                to_unblock.append(ip)

        for ip in to_unblock:
            unblock_ip(ip)
            del block_list[ip]
            print(f"[INFO] IP {ip} automatically unblocked after {info['duration']} seconds.")
            save_blocklist() 

        time.sleep(5)  

def unblock_all_ips():
    load_blocklist()  # Load current block list from file
    if not block_list:
        print("[i] No IPs to unblock.")
        return

    for ip in list(block_list.keys()):
        unblock_ip(ip)
        print(f"[INFO] Unblocked IP: {ip}")
        del block_list[ip]  # Remove from blocklist

    save_blocklist()
    print("[✓] All blocked IPs have been unblocked and block list cleared.")


def print_block_list():
    if not block_list:
        print("[i] No IPs currently blocked.\n")
    else:
        print("[*] Currently blocked IPs:")
        for ip, info in block_list.items():
            expires_in = info["duration"] - (datetime.now() - datetime.fromisoformat(info["blocked_at"])).total_seconds()
            print(f"  - {ip} (expires in {int(expires_in)} seconds)")
        print()

def elevate():
    print("[!] Admin rights required. Requesting UAC permission...\n")
    params = " ".join([f'"{arg}"' for arg in sys.argv])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)

def load_blocklist():
    """Load blocklist from a file."""
    try:
        with open("block_list.json", 'r') as f:
            global block_list
            block_list = json.load(f)
    except FileNotFoundError:
        block_list = {}
    except json.JSONDecodeError:
        print("[!] Error loading blocklist from file. Starting with an empty blocklist.")
        block_list = {}

def save_blocklist():
    """Save the current blocklist to a file."""
    with open("block_list.json", 'w') as f:
        json.dump(block_list, f, default=str)  # Use default=str to handle datetime objects

def main():
    if not is_admin():
        elevate()
        return

    print("ShieldAI Firewall Manager")
    print("=========================\n")

    # Load the blocklist from the file
    load_blocklist()

    # Start the block list monitor in a background thread
    monitor_thread = threading.Thread(target=monitor_block_list, daemon=True)
    monitor_thread.start()

    # Simulate attacks
    test_ips = [
        ("192.168.1.10", "DOS"),
        ("192.168.1.11", "BENIGN"),
        ("192.168.1.12", "DDOS"),
    ]

    for ip, attack in test_ips:
        apply_prevention(attack, ip, block_duration=15)

    try:
        while True:
            print_block_list()
            time.sleep(10)
    except KeyboardInterrupt:
        print("\n[!] Exiting...")

# if __name__ == "__main__":
#     main()
# ip = "192.168.100.5"
# unblock_ip(ip)
# del block_list[ip]
# print(f"[INFO] IP {ip} automatically unblocked after {info['duration']} seconds.")
# save_blocklist() 

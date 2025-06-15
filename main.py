from fastapi import FastAPI, WebSocket, Request, WebSocketDisconnect, HTTPException
from datetime import datetime, timedelta
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import sniff, IP, TCP, AsyncSniffer
import joblib, time, numpy as np, pandas as pd
import asyncio
import threading
import uvicorn
import socket
from dotenv import load_dotenv
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import logging
from tensorflow.keras.models import load_model
from queue import Queue
from prevention import apply_prevention, load_blocklist, monitor_block_list, ip_block_check, request_uac, unblock_all_ips
from plyer import notification
import atexit
import signal, sys

packet_queue = Queue()
sniffer = None

client_lock = asyncio.Lock()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

app = FastAPI()
otp_store = {}

#atexit.register(unblock_all_ips())

sniffing_thread = None

fig, ax = plt.subplots()
timestamps = []    
labels = []     

plot_lock = threading.Lock()

def update_plot(frame):
    with plot_lock:
        ax.clear() 
        ax.plot(timestamps, labels, marker='o', linestyle='-', color='b')
        ax.set_xlabel('Timestamps')
        ax.set_ylabel('Detection Label')
        ax.set_title('Real-time Attack Detection')
        ax.set_xticklabels(timestamps, rotation=45, ha='right')
        plt.tight_layout() 

ani = animation.FuncAnimation(fig, update_plot, frames=100, interval=1000, cache_frame_data=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

autoencoder = load_model("Autoencoder.h5")

attack_decoding = {
    0: "BENIGN", 1: "Bot", 2: "DDoS", 3: "DoS GoldenEye", 4: "DoS Hulk",
    5: "DoS Slowhttptest", 6: "DoS slowloris", 7: "FTP-Patator", 8: "Heartbleed",
    9: "Infiltration", 10: "PortScan", 11: "SSH-Patator", 12: "Web Attack - Brute Force",
    13: "Web Attack - Sql Injection", 14: "Web Attack - XSS"
}

def decode_attack_label(label):
    return attack_decoding.get(label, "Unknown")

clients = []
sniffing = False

flow_start_time = None
packet_times, forward_packets, backward_packets = [], [], []
all_packet_lengths, fwd_packet_lengths, bwd_packet_lengths = [], [], []
tcp_flags = {"SYN": 0, "ACK": 0, "PSH": 0, "FIN": 0, "RST": 0, "URG": 0}
init_win_fwd, init_win_bwd = None, None
active_times, idle_times = [], []

def reset_state():
    global flow_start_time, packet_times, forward_packets, backward_packets
    global all_packet_lengths, fwd_packet_lengths, bwd_packet_lengths, tcp_flags
    global init_win_fwd, init_win_bwd, active_times, idle_times

    flow_start_time = None
    packet_times.clear()
    forward_packets.clear()
    backward_packets.clear()
    all_packet_lengths.clear()
    fwd_packet_lengths.clear()
    bwd_packet_lengths.clear()
    tcp_flags.update({k: 0 for k in tcp_flags})
    init_win_fwd = init_win_bwd = None
    active_times.clear()
    idle_times.clear()

    connectivity_thread = threading.Thread(target=monitor_connectivity, daemon=True)
    connectivity_thread.start()

def extract_features_and_predict(packet):
    global flow_start_time, packet_times, forward_packets, backward_packets
    global all_packet_lengths, fwd_packet_lengths, bwd_packet_lengths, tcp_flags
    global init_win_fwd, init_win_bwd, active_times, idle_times

    timestamp = time.time()
    if flow_start_time is None:
        flow_start_time = timestamp

    flow_duration = timestamp - flow_start_time
    length = len(packet)
    all_packet_lengths.append(length)

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        dport = getattr(packet[IP], 'dport', 0)

        load_blocklist()

    # Start the block list monitor in a background thread
        monitor_thread = threading.Thread(target=monitor_block_list, daemon=True)
        monitor_thread.start()

        if ip_block_check(src) : return

        if not forward_packets or forward_packets[0][IP].src == src:
            forward_packets.append(packet)
            fwd_packet_lengths.append(length)
        else:
            backward_packets.append(packet)
            bwd_packet_lengths.append(length)

        packet_times.append(timestamp)

        if len(packet_times) > 1:
            iat = packet_times[-1] - packet_times[-2]
            active_times.append(iat if iat < 2 else 0)
            idle_times.append(iat if iat >= 2 else 0)

        if TCP in packet:
            flags = packet[TCP].flags
            tcp_flags["SYN"] += int(flags.S)
            tcp_flags["ACK"] += int(flags.A)
            tcp_flags["PSH"] += int(flags.P)
            tcp_flags["FIN"] += int(flags.F)
            tcp_flags["RST"] += int(flags.R)
            tcp_flags["URG"] += int(flags.U)

            if init_win_fwd is None and forward_packets:
                init_win_fwd = packet[TCP].window
            if init_win_bwd is None and backward_packets:
                init_win_bwd = packet[TCP].window

        iats = np.diff(packet_times) * 1000 if len(packet_times) > 1 else [0]
        act_data_pkt_fwd = len(forward_packets)
        down_up_ratio = (len(forward_packets) / len(backward_packets)) if backward_packets else len(forward_packets)

        features = {
            "Fwd IAT Max": np.max(iats) if len(iats) else 0,
            "Bwd Packet Length Mean": np.mean(bwd_packet_lengths) if bwd_packet_lengths else 0,
            "Bwd Packet Length Std": np.std(bwd_packet_lengths) if bwd_packet_lengths else 0,
            "Bwd IAT Max": np.max(iats) if len(iats) else 0,
            "Avg Fwd Segment Size": np.mean(fwd_packet_lengths) if fwd_packet_lengths else 0,
            "Active Mean": np.mean(active_times) if active_times else 0,
            "ACK Flag Count": tcp_flags["ACK"],
            "Fwd Packet Length Mean": np.mean(fwd_packet_lengths) if fwd_packet_lengths else 0,
            "Avg Bwd Segment Size": np.mean(bwd_packet_lengths) if bwd_packet_lengths else 0,
            "Flow IAT Min": np.min(iats) if len(iats) else 0,
            "Idle Min": np.min(idle_times) if idle_times else 0,
            "Flow Packets/s": len(all_packet_lengths) / flow_duration if flow_duration > 0 else 0,
            "Bwd Packet Length Min": min(bwd_packet_lengths) if bwd_packet_lengths else 0,
            "Subflow Fwd Bytes": sum(fwd_packet_lengths),
            "Active Max": np.max(active_times) if active_times else 0,
            "Bwd Packets/s": len(backward_packets) / flow_duration if flow_duration > 0 else 0,
            "FIN Flag Count": tcp_flags["FIN"],
            "Active Min": np.min(active_times) if active_times else 0,
            "min_seg_size_forward": min(fwd_packet_lengths) if fwd_packet_lengths else 0,
            "Bwd IAT Total": sum(iats),
            "Destination Port": dport,
            "Bwd IAT Std": np.std(iats) if len(iats) else 0,
            "Bwd IAT Min": np.min(iats) if len(iats) else 0,
            "Fwd Packet Length Min": min(fwd_packet_lengths) if fwd_packet_lengths else 0,
            "Total Length of Fwd Packets": sum(fwd_packet_lengths),
            "Fwd URG Flags": tcp_flags["URG"],
            "Init_Win_bytes_forward": init_win_fwd if init_win_fwd else 0,
            "Fwd Packets/s": len(forward_packets) / flow_duration if flow_duration > 0 else 0,
            "RST Flag Count": tcp_flags["RST"],
            "Subflow Bwd Bytes": sum(bwd_packet_lengths),
            "Packet Length Mean": np.mean(all_packet_lengths) if all_packet_lengths else 0,
            "Flow IAT Mean": np.mean(iats) if len(iats) else 0,
            "Fwd IAT Mean": np.mean(iats) if len(iats) else 0,
            "Packet Length Std": np.std(all_packet_lengths) if all_packet_lengths else 0,
            "PSH Flag Count": tcp_flags["PSH"],
            "URG Flag Count": tcp_flags["URG"],
            "Min Packet Length": min(all_packet_lengths) if all_packet_lengths else 0,
            "Bwd Header Length": sum(len(p) for p in backward_packets),
            "Idle Mean": np.mean(idle_times) if idle_times else 0,
            "Fwd IAT Std": np.std(iats) if len(iats) else 0,
            "Fwd Header Length": sum(len(p) for p in forward_packets),
            "Fwd IAT Total": sum(iats),
            "Subflow Bwd Packets": len(backward_packets),
            "Flow Bytes/s": len(all_packet_lengths) / flow_duration if flow_duration > 0 else 0,
            "Packet Length Variance": np.var(all_packet_lengths) if all_packet_lengths else 0,
            "CWE Flag Count": tcp_flags["URG"],
            "Flow IAT Max": np.max(iats) if len(iats) else 0,
            "Bwd Packet Length Max": max(bwd_packet_lengths) if bwd_packet_lengths else 0,
            "Max Packet Length": max(all_packet_lengths) if all_packet_lengths else 0,
            "Average Packet Size": np.mean(all_packet_lengths) if all_packet_lengths else 0,
            "Total Backward Packets": len(backward_packets),
            "Flow IAT Std": np.std(iats) if len(iats) else 0,
            "Subflow Fwd Packets": len(forward_packets),
            "Fwd Packet Length Std": np.std(fwd_packet_lengths) if fwd_packet_lengths else 0,
            "Fwd PSH Flags": tcp_flags["PSH"],
            "Bwd URG Flags": tcp_flags["URG"],
            "act_data_pkt_fwd": act_data_pkt_fwd,
            "Total Length of Bwd Packets": sum(bwd_packet_lengths),
            "Flow Duration": flow_duration,
            "Fwd IAT Min": np.min(iats) if len(iats) else 0,
            "Bwd PSH Flags": tcp_flags["PSH"],
            "Fwd Header Length.1": sum(len(p) for p in forward_packets),
            "Down/Up Ratio": down_up_ratio,
            "Fwd Packet Length Max": max(fwd_packet_lengths) if fwd_packet_lengths else 0,
            "SYN Flag Count": tcp_flags["SYN"],
            "Idle Std": np.std(idle_times) if idle_times else 0,
            "Total Fwd Packets": len(forward_packets),
            "Idle Max": np.max(idle_times) if idle_times else 0,
            "Bwd IAT Mean": np.mean(iats) if len(iats) else 0,
            "Init_Win_bytes_backward": init_win_bwd if init_win_bwd else 0,
            "Active Std": np.std(active_times) if active_times else 0,
        }

        df = pd.DataFrame([features])
        try:
            _, prob = autoencoder.predict(df, verbose=0)
            pred = np.argmax(prob)
            label = decode_attack_label(pred)

        except Exception as e:
            logger.error(f"Prediction error: {e}")
            label = "ERROR"

        with plot_lock:
            timestamps.append(timestamp)
            labels.append(label)

        if len(timestamps) > 50: 
            timestamps.pop(0)
            labels.pop(0)

        data = {
            "timestamp": timestamp,
            "src": src,
            "dst": dst,
            "label": label
        }

        if label in attack_decoding.values() and label != "BENIGN":
            notification.notify( title="ShieldAI Attack Alert", message=f"Attack detected: {label}",timeout=10)
            apply_prevention(label, src, block_duration=3600)

        asyncio.run(send_to_clients(data))

async def send_to_clients(data):
    disconnected_clients = []
    async with client_lock:
        for client in clients:
            try:
                await client.send_json(data)
            except WebSocketDisconnect:
                disconnected_clients.append(client)
            except Exception as e:
                print(f"[!] Error sending to client: {e}")
                disconnected_clients.append(client)
    for client in disconnected_clients:
        clients.remove(client)


def process_packet(packet):
    packet_queue.put(packet)

def packet_consumer():
    while sniffing:
        try:
            packet = packet_queue.get(timeout=1)
            extract_features_and_predict(packet)
        except Exception:
            continue 

def is_connected():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError:
        return False

def start_sniffing():
    global sniffer, sniffing
    sniffing = True
    if(is_connected()):
        reset_state()
        logger.info("[*] Sniffing started.")

        sniffer = AsyncSniffer(prn=process_packet, store=False)
        sniffer.start()

        consumer_thread = threading.Thread(target=packet_consumer, daemon=True)
        consumer_thread.start()

def stop_sniffing():
    global sniffer, sniffing
    if sniffing and sniffer is not None:
        try:
            sniffer.stop()
            logger.info("[*] Sniffing stopped.")
        except Exception as e:
            logger.error(f"[!] Error stopping sniffer: {e}")
    sniffing = False


def monitor_connectivity():
    was_connected = is_connected()

    while True:
        currently_connected = is_connected()
        if currently_connected and not was_connected:
            logger.info("[+] Connection restored. Restarting sniffing...")
            start_sniffing()
        elif not currently_connected and was_connected:
            logger.warning("[-] Disconnected from internet. Stopping sniffing...")
            stop_sniffing()

        was_connected = currently_connected
        time.sleep(5)  # check every 5 seconds


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    global sniffing, sniffing_thread
    
    await websocket.accept()
    clients.append(websocket)
    logger.info("[*] Client connected.")

    try:
        while True:
            msg = await websocket.receive_text()
            if msg == "start":
                if not sniffing:
                    sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
                    sniffing_thread.start()
            elif msg == "stop":
                sniffing = False
                if sniffer:
                    sniffer.stop()
                logger.info("[*] Sniffing stopped.")
    except WebSocketDisconnect:
        logger.info("[*] Client disconnected.")
        clients.remove(websocket)
        sniffing = False

if __name__ == "__main__":
    request_uac()
    threading.Thread(target=monitor_connectivity, daemon=True).start()
    uvicorn.run(app, host="0.0.0.0", port=8000)

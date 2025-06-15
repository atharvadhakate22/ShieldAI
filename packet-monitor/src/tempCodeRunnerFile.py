from scapy.all import sniff, IP, TCP
import joblib
import time
import pandas as pd
import numpy as np
import os
import json

xgb_model = joblib.load("xgb_model.pkl")

attack_decoding = {
    0: "BENIGN", 1: "Bot", 2: "DDoS", 3: "DoS GoldenEye", 4: "DoS Hulk",
    5: "DoS Slowhttptest", 6: "DoS slowloris", 7: "FTP-Patator", 8: "Heartbleed",
    9: "Infiltration", 10: "PortScan", 11: "SSH-Patator", 12: "Web Attack - Brute Force", 13: "Web Attack - Sql Injection", 14: "Web Attack - XSS"
}

def decode_attack_label(label):
    return attack_decoding.get(label, "Unknown")

# Global state
flow_start_time = None
packet_times = []
forward_packets = []
backward_packets = []
all_packet_lengths = []
fwd_packet_lengths = []
bwd_packet_lengths = []
tcp_flags = {"SYN": 0, "ACK": 0, "PSH": 0, "FIN": 0, "RST": 0, "URG": 0}
init_win_fwd = None
init_win_bwd = None
active_times = []
idle_times = []

# NDJSON file path
RESULTS_PATH = "packet-monitor/public/results.ndjson"

# Clear previous file if exists
with open(RESULTS_PATH, "w") as f:
    pass

def extract_features(packet):
    global flow_start_time, packet_times, forward_packets, backward_packets
    global all_packet_lengths, fwd_packet_lengths, bwd_packet_lengths, tcp_flags
    global init_win_fwd, init_win_bwd, active_times, idle_times

    timestamp = time.time()
    if flow_start_time is None:
        flow_start_time = timestamp

    flow_duration = timestamp - flow_start_time
    packet_length = len(packet)
    all_packet_lengths.append(packet_length)

    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        destination_port = packet[IP].dport if hasattr(packet[IP], "dport") else 0

        if not forward_packets or forward_packets[0][IP].src == src:
            forward_packets.append(packet)
            fwd_packet_lengths.append(packet_length)
        else:
            backward_packets.append(packet)
            bwd_packet_lengths.append(packet_length)

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
            "Destination Port": destination_port,
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
        prediction = int(xgb_model.predict(df)[0])
        label = decode_attack_label(prediction)

        result = {
            "timestamp": timestamp,
            "src": src,
            "dst": dst,
            "label": label
        }

        with open(RESULTS_PATH, "a") as f:
            f.write(json.dumps(result) + "\n")

        print(f"[+] Predicted: {label}")

print("[*] Starting sniffing...")
sniff(prn=extract_features, store=False, timeout=40)

print(f"\n[*] Analysis complete. NDJSON results saved to {RESULTS_PATH}")

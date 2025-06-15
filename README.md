# 🛡️ ShieldAI – Real-Time AI-Powered Intrusion Detection & Prevention

In today’s internet-driven world, **safeguarding network infrastructure against malicious activities** is more crucial than ever. **ShieldAI** is a real-time **cyber threat detection and prevention system** that leverages machine learning and AI to **detect, classify, and block cyberattacks** as they happen — directly from live network traffic.

Using **Scapy** for live packet sniffing and **FastAPI** for the backend, the system extracts **71+ features** per packet and feeds them into a **pre-trained Autoencoder and Deep Neural Network (DNN)** model to detect anomalies and predict threats such as:

- 🚨 DDoS Attacks  
- ⚠️ Port Scans  
- 🔑 Brute Force Logins  
- 🛠️ SQL Injections  
- ...and more.

Threat predictions are streamed in real-time to a **React-based dashboard**, allowing users to monitor and visualize threats dynamically. For active defense, **malicious IPs are automatically blocked** using **WinDivert** at the OS level.

> ShieldAI enhances proactive cybersecurity by offering a local, intelligent, and scalable defense system for modern network environments.

---

## 🔥 Key Features

- 🧠 **AI-Based Detection** (Autoencoder + DNN)
- 📦 **Live Packet Sniffing** (Scapy)
- ⚙️ **Backend**: FastAPI with async real-time pipelines
- 📈 **Frontend**: React.js with WebSocket & Chart.js visualization
- 🛡️ **Automatic IP Blocking**: WinDivert-based filtering

---

## 💡 How It Works

1. **Packet Capture**: Scapy captures packets in real-time.
2. **Feature Extraction**: 71 custom features are extracted from each packet (Xgboost).
3. **Threat Prediction**: Features are passed into a trained AI model (Autoencoder + DNN).
4. **Visualization**: Predictions are streamed to the frontend.
5. **Prevention**: If an attack is detected, the source IP is blocked instantly.

---

## 📦 Tech Stack

| Layer         | Tech Used                          |
|---------------|------------------------------------|
| Frontend      | React.js, Chart.js, Bootstrap      |
| Backend       | FastAPI, Uvicorn, Scapy            |
| AI Models     | TensorFlow/Keras, Autoencoder, DNN, Xgboost |
| IP Blocking   | WinDivert using WinDivert.sys Driver|


---

## ✅ Setup & Deployment

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn demo:app --reload

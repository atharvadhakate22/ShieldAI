import React, { useEffect, useRef, useState } from "react";
import "bootstrap/dist/css/bootstrap.min.css";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend);

const App = () => {
  const tableBodyRef = useRef(null);
  const counter = useRef(1);
  const seenPackets = useRef(new Set());
  const wsRef = useRef(null);
  const chartRef = useRef(null);

  const [graphData, setGraphData] = useState([]);
  const [isSniffing, setIsSniffing] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [plotUrl, setPlotUrl] = useState("/plot");
  const [showAlert, setShowAlert] = useState(false);
  const [alertInfo, setAlertInfo] = useState({ time: "", src: "", dst: "" });
  const [blockedIPs, setBlockedIPs] = useState(new Set());

  const handleStart = () => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send("start");
      setIsSniffing(true);
    }
  };

  useEffect(() => {
    const fetchBlockList = async () => {
      try {
        const res = await fetch("/block_list.json");
        const json = await res.json();
        const blockedSet = new Set(json.blocked_ips); 
        setBlockedIPs(blockedSet);
      } catch (err) {
        console.error("Failed to load block list:", err);
      }
    };
  
    fetchBlockList();
    setupWebSocket();
  }, []);
  

  const handleStop = () => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send("stop");
      setIsSniffing(false);
    }
  };

  const processPacket = (pkt) => {

    if (blockedIPs.has(pkt.src)) return;

    const pktId = `${pkt.timestamp}-${pkt.src}-${pkt.dst}-${pkt.label}`;
    if (seenPackets.current.has(pktId)) return;
    seenPackets.current.add(pktId);

    const timestamp = pkt.timestamp
      ? new Date(pkt.timestamp * 1000).toLocaleTimeString()
      : "N/A";

    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${counter.current++}</td>
      <td>${timestamp}</td>
      <td>${pkt.src || "N/A"}</td>
      <td>${pkt.dst || "N/A"}</td>
      <td>
        <span class="fw-bold badge ${pkt.label === "BENIGN" ? "bg-success" : "bg-danger"}">
          ${pkt.label || "Unknown"}
        </span>
      </td>
    `;

    if (pkt.label !== "BENIGN") {
      setAlertInfo({ time: timestamp, src: pkt.src || "N/A", dst: pkt.dst || "N/A" });
      setShowAlert(true);
      setTimeout(() => setShowAlert(false), 5000);
    }

    if (tableBodyRef.current) {
      const table = tableBodyRef.current;
      table.prepend(row);
      while (table.rows.length > 100) table.deleteRow(-1);
    }

    setGraphData((prev) => {
      const updated = [...prev, { label: pkt.label, timestamp }];
      return updated.slice(-15);
    });
  };

  const setupWebSocket = () => {
    const ws = new WebSocket("ws://localhost:8000/ws");
    wsRef.current = ws;

    ws.onopen = () => {
      console.log("WebSocket connected");
      ws.send("start");
      setIsSniffing(true);
    };

    ws.onmessage = (event) => {
      try {
        const pkt = JSON.parse(event.data);
        processPacket(pkt);
      } catch (err) {
        console.error("JSON parse error:", err.message);
      }
    };

    ws.onerror = (err) => console.error("WebSocket error:", err);
    ws.onclose = () => {
      console.warn("WebSocket closed, retrying in 5s...");
      setIsSniffing(false);
      setTimeout(setupWebSocket, 5000);
    };
  };

  useEffect(setupWebSocket, []);

  useEffect(() => {
    let interval;
    if (showModal) {
      interval = setInterval(() => {
        setPlotUrl(`/plot?ts=${Date.now()}`);
      }, 3000);
    }
    return () => clearInterval(interval);
  }, [showModal]);

  const data = {
    labels: graphData.map((d) => d.timestamp),
    datasets: [
      {
        label: "Threat Level",
        data: graphData.map((d) => (d.label === "BENIGN" ? 0 : 1)),
        borderColor: "rgba(0, 123, 255, 1)",
        backgroundColor: (ctx) => {
          const chart = ctx.chart;
          const { ctx: canvas, chartArea } = chart;
          if (!chartArea) return;
          const gradient = canvas.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
          gradient.addColorStop(0, "rgba(0, 123, 255, 0.4)");
          gradient.addColorStop(1, "rgba(0, 123, 255, 0.05)");
          return gradient;
        },
        fill: true,
        tension: 0.4,
        pointRadius: 6,
        pointHoverRadius: 8,
        pointBackgroundColor: (ctx) =>
          ctx.raw === 1 ? "rgba(220,53,69,1)" : "rgba(40,167,69,1)",
        borderWidth: 2,
      },
    ],
  };

  const options = {
    responsive: true,
    animation: { duration: 700, easing: "easeOutCubic" },
    layout: { padding: { top: 20, bottom: 20, left: 10, right: 10 } },
    plugins: {
      title: {
        display: true,
        text: "Real Time Attack Prediction",
        font: { size: 20, weight: "bold" },
        color: "#212529",
      },
      tooltip: {
        callbacks: {
          label: (ctx) => `Status: ${ctx.raw === 0 ? "BENIGN" : "Attack"}`,
        },
        backgroundColor: "#f8f9fa",
        titleColor: "#000",
        bodyColor: "#000",
        borderColor: "#ced4da",
        borderWidth: 1,
      },
      legend: { display: false },
    },
    scales: {
      x: {
        title: { display: true, text: "Time", font: { weight: "bold" } },
        ticks: { maxRotation: 90, minRotation: 45, color: "#495057" },
        grid: { color: "#dee2e6" },
      },
      y: {
        min: -0.1,
        max: 1.1,
        ticks: {
          stepSize: 1,
          callback: (val) => (val === 0 ? "BENIGN" : "Attack"),
          color: "#495057",
        },
        title: { display: true, text: "Label", font: { weight: "bold" } },
        grid: { color: "#dee2e6" },
      },
    },
    onClick: (event, elements) => {
      if (!elements.length) return;
      const index = elements[0].index;
      const clickedPoint = graphData[index];
      if (clickedPoint && clickedPoint.label !== "BENIGN") {
        alert(`Attack Detected: ${clickedPoint.label}`);
      }
    },
  };

  return (
    <>
      <nav className="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm">
        <div className="container-fluid d-flex justify-content-between">
          <div className="d-flex align-items-center gap-3">
            <span className="navbar-brand fw-bold fs-4">
              <img
                src="./encrypted.png"
                alt="Encrypted Packet"
                width="30"
                height="30"
                style={{ marginRight: "8px", marginBottom: "4px" }}
              />
              <span className="text-primary">Shield</span>
              <span className="text-light">AI</span>
            </span>
            <button className="btn btn-outline-warning btn-sm" onClick={() => setShowModal(true)}>
              📊 Visualization
            </button>
          </div>
        </div>
      </nav>

      <div className="container mt-4">
        <div className="d-flex justify-content-between align-items-center mb-3">
          <h3 className="text-primary">Real-Time Threat Detection</h3>
          <div>
            <button className="btn btn-success me-2" onClick={handleStart} disabled={isSniffing}>
              ▶ Start Sniffing
            </button>
            <button className="btn btn-danger" onClick={handleStop} disabled={!isSniffing}>
              ⏹ Stop Sniffing
            </button>
          </div>
        </div>

        <div className="table-responsive rounded shadow" style={{ maxHeight: "70vh", overflowY: "auto" }}>
          <table className="table table-striped table-hover align-middle table-bordered">
            <thead className="table-dark text-center">
              <tr>
                <th>#</th>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Label</th>
              </tr>
            </thead>
            <tbody ref={tableBodyRef} className="text-center"></tbody>
          </table>
        </div>
      </div>

      {showModal && (
        <div className="position-fixed top-0 start-0 w-100 h-100 bg-white d-flex justify-content-center align-items-center" style={{ zIndex: 1050 }}>
          <div className="position-absolute top-0 end-0 p-3">
            <button
              className="btn"
              style={{
                fontSize: "2.5rem",
                color: "#000",
                background: "transparent",
                border: "none",
                lineHeight: 1,
              }}
              onClick={() => setShowModal(false)}
              aria-label="Close"
            >
              &times;
            </button>
          </div>
          <div className="container-fluid d-flex justify-content-center align-items-center h-100">
            <div className="bg-white rounded shadow-sm p-4" style={{ width: "90%", maxWidth: "1200px", height: "80vh" }}>
              <Line ref={chartRef} data={data} options={options} />
            </div>
          </div>
        </div>
      )}

      {showAlert && (
        <div className="toast show position-fixed bottom-0 end-0 m-3 text-bg-danger border-0 shadow" role="alert" style={{ zIndex: 1060, minWidth: "300px" }}>
          <div className="toast-header bg-danger text-white">
            <strong className="me-auto">Alert: Attack Detected</strong>
            <small>{alertInfo.time}</small>
          </div>
          <div className="toast-body">
            <div><strong>Source:</strong> {alertInfo.src}</div>
            <div><strong>Destination:</strong> {alertInfo.dst}</div>
          </div>
        </div>
      )}
    </>
  );
};

export default App;

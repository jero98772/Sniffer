from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import subprocess
import asyncio
import json
import os
from collections import Counter
from typing import List, Dict
import re

app = FastAPI()

# Set up templates directory for serving the HTML
templates = Jinja2Templates(directory="templates")

# Create templates directory if it doesn't exist
os.makedirs("templates", exist_ok=True)

# Save the HTML template
with open("templates/index.html", "w") as f:
    f.write("""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Packet Dashboard</title>
  <!-- Chart.js for plotting -->
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1, h2 { color: #333; }
    .container { max-width: 1200px; margin: 0 auto; }
    .form-group { margin-bottom: 20px; }
    .form-control { padding: 8px; width: 100px; }
    .btn { padding: 8px 16px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
    .btn:hover { background-color: #45a049; }
    #packetList { list-style-type: none; padding: 0; }
    #packetList li { background: #f4f4f4; margin: 5px 0; padding: 10px; border-radius: 4px; }
    .charts-container { display: flex; flex-wrap: wrap; justify-content: space-between; }
    .chart-box { width: 48%; margin-bottom: 20px; }
    .status { margin-top: 10px; color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Real-Time Packet Dashboard</h1>
    
    <div class="form-group">
      <label for="captureTime">Capture Duration (seconds): </label>
      <input type="number" id="captureTime" class="form-control" value="30" min="1">
      <button id="startCapture" class="btn">Start Capture</button>
      <div id="captureStatus" class="status">Ready to capture packets</div>
    </div>
    
    <div class="charts-container">
      <div class="chart-box">
        <h2>Most Frequent Source IPs</h2>
        <canvas id="sourceIpChart" width="400" height="300"></canvas>
      </div>
      <div class="chart-box">
        <h2>Protocol Distribution</h2>
        <canvas id="protocolChart" width="400" height="300"></canvas>
      </div>
    </div>
    
    <h2>Latest Packets</h2>
    <ul id="packetList"></ul>
  </div>
  
  <script>
    // Initialize Charts
    const sourceIpChart = new Chart(
      document.getElementById('sourceIpChart').getContext('2d'), {
        type: 'bar',
        data: {
          labels: [],
          datasets: [{
            label: 'Packet Count',
            data: [],
            backgroundColor: 'rgba(54, 162, 235, 0.6)'
          }]
        },
        options: {
          scales: { y: { beginAtZero: true } }
        }
      }
    );
    
    const protocolChart = new Chart(
      document.getElementById('protocolChart').getContext('2d'), {
        type: 'pie',
        data: {
          labels: [],
          datasets: [{
            data: [],
            backgroundColor: [
              'rgba(255, 99, 132, 0.6)',
              'rgba(54, 162, 235, 0.6)',
              'rgba(255, 206, 86, 0.6)',
              'rgba(75, 192, 192, 0.6)',
              'rgba(153, 102, 255, 0.6)'
            ]
          }]
        }
      }
    );
    
    // WebSocket connection
    let ws;
    
    function connectWebSocket() {
      ws = new WebSocket(`ws://${window.location.host}/ws`);
      
      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === 'status') {
          document.getElementById('captureStatus').textContent = data.message;
          return;
        }
        
        // Update packet list
        const packet = data.packet;
        const li = document.createElement("li");
        li.textContent = `Packet ${packet.id}: ${packet.src_ip} → ${packet.dst_ip}, Protocol: ${packet.protocol} (${packet.hostname})`;
        const packetList = document.getElementById("packetList");
        packetList.prepend(li);
        
        // Keep only the last 20 entries
        if (packetList.children.length > 20) {
          packetList.removeChild(packetList.lastChild);
        }
        
        // Update Source IP chart
        const ipCounts = data.ip_counts;
        sourceIpChart.data.labels = Object.keys(ipCounts).slice(0, 10);
        sourceIpChart.data.datasets[0].data = Object.values(ipCounts).slice(0, 10);
        sourceIpChart.update();
        
        // Update Protocol chart
        const protocolCounts = data.protocol_counts;
        protocolChart.data.labels = Object.keys(protocolCounts);
        protocolChart.data.datasets[0].data = Object.values(protocolCounts);
        protocolChart.update();
      };
      
      ws.onclose = () => {
        console.log('WebSocket connection closed');
        setTimeout(connectWebSocket, 2000); // Try to reconnect after 2 seconds
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        ws.close();
      };
    }
    
    // Start capture button
    document.getElementById('startCapture').addEventListener('click', () => {
      const duration = document.getElementById('captureTime').value;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
          action: 'start_capture',
          duration: parseInt(duration)
        }));
        document.getElementById('captureStatus').textContent = 'Starting packet capture...';
      }
    });
    
    // Initialize WebSocket connection
    connectWebSocket();
  </script>
</body>
</html>""")

# Connection manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

# Packet processing
class PacketAnalyzer:
    def __init__(self):
        self.ip_counter = Counter()
        self.protocol_counter = Counter()
        self.current_packet_id = 0

    def parse_packet_line(self, line):
        pattern = r'Packet (\d+): ([\d\.]+) -> ([\d\.]+), Src MAC: ([\w:]+), Dst MAC: ([\w:]+), Protocol: (\d+) (.+)'
        match = re.match(pattern, line)
        
        if match:
            packet_id, src_ip, dst_ip, src_mac, dst_mac, protocol, hostname = match.groups()
            
            # Update counters
            self.ip_counter[src_ip] += 1
            self.protocol_counter[protocol] += 1
            
            return {
                "id": packet_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "protocol": protocol,
                "hostname": hostname
            }
        return None

    def get_ip_counts(self, top_n=10):
        return dict(self.ip_counter.most_common(top_n))
    
    def get_protocol_counts(self):
        # Map protocol numbers to names for better readability
        protocol_names = {
            '1': 'ICMP',
            '6': 'TCP',
            '17': 'UDP',
            '128': 'Other'
        }
        
        result = {}
        for proto, count in self.protocol_counter.items():
            name = protocol_names.get(proto, f"Protocol {proto}")
            result[name] = count
        
        return result

packet_analyzer = PacketAnalyzer()

@app.get("/", response_class=HTMLResponse)
async def get_html(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            
            # Handle client commands
            try:
                message = json.loads(data)
                if message.get("action") == "start_capture":
                    duration = message.get("duration", 30)
                    # Start capture in a separate task
                    asyncio.create_task(run_packet_capture(duration))
                    
            except json.JSONDecodeError:
                # Simple ping or non-JSON message
                pass
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)

async def run_packet_capture(duration: int):
    """Run the packet capture program as a subprocess"""
    await manager.broadcast(json.dumps({
        "type": "status",
        "message": f"Starting packet capture for {duration} seconds..."
    }))
    
    # Reset counters for new capture
    packet_analyzer.ip_counter.clear()
    packet_analyzer.protocol_counter.clear()
    
    # Run the packet capture program
    try:
        # Remove old capture file if it exists
        if os.path.exists("capture.txt"):
            os.remove("capture.txt")
            
        # Start the process
        process = await asyncio.create_subprocess_shell(
            f"./packet_capture -t {duration} -o capture.txt",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Wait for the program to start and create the file
        await asyncio.sleep(1)
        
        # Start reading the file as it's being written
        await manager.broadcast(json.dumps({
            "type": "status",
            "message": f"Capturing packets... ({duration} seconds remaining)"
        }))
        
        # Set up file monitoring
        await monitor_capture_file(duration)
        
    except Exception as e:
        await manager.broadcast(json.dumps({
            "type": "status",
            "message": f"Error: {str(e)}"
        }))

async def monitor_capture_file(duration: int):
    """Monitor the capture file for new data"""
    start_time = asyncio.get_event_loop().time()
    file_position = 0
    
    # Create empty file if it doesn't exist yet
    if not os.path.exists("capture.txt"):
        open("capture.txt", "w").close()
    
    while asyncio.get_event_loop().time() - start_time < duration + 2:  # Add 2 sec buffer
        try:
            with open("capture.txt", "r") as f:
                f.seek(file_position)
                new_lines = f.readlines()
                file_position = f.tell()
                
                for line in new_lines:
                    if line.strip():
                        packet = packet_analyzer.parse_packet_line(line.strip())
                        if packet:
                            # Send packet info to all connected clients
                            await manager.broadcast(json.dumps({
                                "packet": packet,
                                "ip_counts": packet_analyzer.get_ip_counts(),
                                "protocol_counts": packet_analyzer.get_protocol_counts()
                            }))
            
            # Update status with remaining time
            elapsed = asyncio.get_event_loop().time() - start_time
            remaining = max(0, int(duration - elapsed))
            if remaining % 5 == 0 or remaining <= 5:  # Update every 5 seconds or during final countdown
                await manager.broadcast(json.dumps({
                    "type": "status",
                    "message": f"Capturing packets... ({remaining} seconds remaining)"
                }))
                
            await asyncio.sleep(0.5)  # Check for updates every 0.5 seconds
            
        except Exception as e:
            print(f"Error reading capture file: {e}")
            await asyncio.sleep(1)
    
    await manager.broadcast(json.dumps({
        "type": "status",
        "message": "Packet capture completed. Ready for next capture."
    }))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
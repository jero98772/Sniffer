(ns packet-capture.core
  (:require [org.httpkit.server :as server]
            [compojure.core :refer [defroutes GET POST]]
            [compojure.route :as route]
            [ring.middleware.defaults :refer [wrap-defaults site-defaults]]
            [ring.middleware.json :refer [wrap-json-response wrap-json-body]]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.java.shell :as shell]
            [hiccup.core :as hiccup]
            [hiccup.page :as page]
            [cheshire.core :as json]
            [clojure.core.async :as async])
  (:import [java.util.concurrent Executors]
           [java.util.concurrent TimeUnit]
           [java.io RandomAccessFile]))

(def clients (atom {}))

;; Data storage for packet analysis
(def packet-data (atom {:ip-counts {}
                        :protocol-counts {}
                        :packets []}))

;; Helper functions
(defn reset-data! []
  (reset! packet-data {:ip-counts {}
                       :protocol-counts {}
                       :packets []}))

(defn update-ip-count! [ip]
  (swap! packet-data update-in [:ip-counts ip] (fnil inc 0)))

(defn update-protocol-count! [protocol]
  (swap! packet-data update-in [:protocol-counts protocol] (fnil inc 0)))

(defn add-packet! [packet]
  (swap! packet-data update :packets #(take 20 (conj % packet))))

;; Parse a line from the capture file
(defn parse-packet-line [line]
  (let [pattern #"Packet (\d+): ([\d\.]+) -> ([\d\.]+), Src MAC: ([\w:]+), Dst MAC: ([\w:]+), Protocol: (\d+) (.+)"
        matcher (re-matcher pattern line)]
    (when (re-find matcher)
      (let [[_ packet-id src-ip dst-ip src-mac dst-mac protocol hostname] (re-groups matcher)]
        {:id packet-id
         :src-ip src-ip
         :dst-ip dst-ip
         :src-mac src-mac
         :dst-mac dst-mac
         :protocol protocol
         :hostname hostname}))))

;; Run packet capture command
(defn run-packet-capture [duration]
  (future
    (try
      (println "Starting packet capture for" duration "seconds")
      (let [cmd ["./packet_capture" "-t" (str duration) "-o" "capture.txt"]]
        (shell/sh "sudo" (first cmd) (second cmd) (nth cmd 2) (nth cmd 3) (nth cmd 4)))
      (println "Packet capture completed")
      (catch Exception e
        (println "Error in packet capture:" (.getMessage e))))))

;; Monitor capture file for changes
(defn monitor-capture-file [duration]
  (let [file-path "capture.txt"
        start-time (System/currentTimeMillis)
        end-time (+ start-time (* duration 1000))
        scheduler (Executors/newSingleThreadScheduledExecutor)
        file-position (atom 0)
        
        ;; Send status update to all clients
        send-status (fn [message]
                      (doseq [[client-id channel] @clients]
                        (server/send! channel (json/generate-string {:type "status" :message message}))))
        
        ;; Send packet data to all clients
        send-packet-data (fn [packet]
                           (let [data {:packet packet
                                       :ip-counts (:ip-counts @packet-data)
                                       :protocol-counts (:protocol-counts @packet-data)}]
                             (doseq [[client-id channel] @clients]
                               (server/send! channel (json/generate-string data)))))
        
        ;; Task to read new lines from the file
        read-task (fn []
                    (try
                      (when (.exists (io/file file-path))
                        (with-open [raf (RandomAccessFile. file-path "r")]
                          (.seek raf @file-position)
                          (loop [line (.readLine raf)]
                            (when line
                              (let [packet (parse-packet-line line)]
                                (when packet
                                  ;; Update statistics
                                  (update-ip-count! (:src-ip packet))
                                  (update-protocol-count! (:protocol packet))
                                  (add-packet! packet)
                                  ;; Send to clients
                                  (send-packet-data packet)))
                              (recur (.readLine raf))))
                          (reset! file-position (.getFilePointer raf))))
                      
                      ;; Update status every 5 seconds
                      (let [current-time (System/currentTimeMillis)
                            remaining (max 0 (int (/ (- end-time current-time) 1000)))]
                        (when (or (zero? (mod remaining 5)) (<= remaining 5))
                          (send-status (str "Capturing packets... (" remaining " seconds remaining)"))))
                      
                      (catch Exception e
                        (println "Error reading capture file:" (.getMessage e)))))
        
        ;; Schedule the task
        _ (.scheduleAtFixedRate scheduler read-task 0 500 TimeUnit/MILLISECONDS)]
    
    ;; Send initial status
    (send-status (str "Starting packet capture for " duration " seconds..."))
    
    ;; Wait for capture to complete
    (async/go
      (async/<! (async/timeout (* (+ duration 2) 1000))) ;; Add 2 second buffer
      (.shutdown scheduler)
      (send-status "Packet capture completed. Ready for next capture."))))

;; WebSocket handler
(defn ws-handler [request]
  (server/with-channel request channel
    (let [client-id (str (java.util.UUID/randomUUID))]
      (println "Client connected:" client-id)
      (swap! clients assoc client-id channel)
      
      (server/on-close channel
                       (fn [status]
                         (println "Client disconnected:" client-id)
                         (swap! clients dissoc client-id)))
      
      (server/on-receive channel
                         (fn [data]
                           (try
                             (let [msg (json/parse-string data true)]
                               (when (= (:action msg) "start_capture")
                                 (let [duration (or (:duration msg) 30)]
                                   ;; Reset data for new capture
                                   (reset-data!)
                                   ;; Start capture
                                   (run-packet-capture duration)
                                   ;; Monitor file
                                   (monitor-capture-file duration))))
                             (catch Exception e
                               (println "Error processing message:" (.getMessage e)))))))))

;; HTML template
(defn index-page []
  (page/html5
   [:head
    [:meta {:charset "UTF-8"}]
    [:title "Packet Dashboard"]
    [:script {:src "https://cdn.jsdelivr.net/npm/chart.js"}]
    [:style "
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
    "]]
   [:body
    [:div.container
     [:h1 "Real-Time Packet Dashboard"]
     
     [:div.form-group
      [:label {:for "captureTime"} "Capture Duration (seconds): "]
      [:input#captureTime.form-control {:type "number" :value "30" :min "1"}]
      [:button#startCapture.btn "Start Capture"]
      [:div#captureStatus.status "Ready to capture packets"]]
     
     [:div.charts-container
      [:div.chart-box
       [:h2 "Most Frequent Source IPs"]
       [:canvas#sourceIpChart {:width "400" :height "300"}]]
      [:div.chart-box
       [:h2 "Protocol Distribution"]
       [:canvas#protocolChart {:width "400" :height "300"}]]]
     
     [:h2 "Latest Packets"]
     [:ul#packetList]]
    
    [:script "
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
          const li = document.createElement('li');
          li.textContent = `Packet ${packet.id}: ${packet.src_ip} → ${packet.dst_ip}, Protocol: ${packet.protocol} (${packet.hostname})`;
          const packetList = document.getElementById('packetList');
          packetList.prepend(li);
          
          // Keep only the last 20 entries
          if (packetList.children.length > 20) {
            packetList.removeChild(packetList.lastChild);
          }
          
          // Update Source IP chart
          const ipCounts = data.ip_counts;
          const ipLabels = Object.keys(ipCounts).slice(0, 10);
          const ipValues = ipLabels.map(key => ipCounts[key]);
          sourceIpChart.data.labels = ipLabels;
          sourceIpChart.data.datasets[0].data = ipValues;
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
    "]]))

;; Routes
(defroutes app-routes
  (GET "/" [] (index-page))
  (GET "/ws" [] ws-handler)
  (route/resources "/")
  (route/not-found "Not Found"))

;; Middleware
(def app
  (-> app-routes
      (wrap-defaults (assoc-in site-defaults [:security :anti-forgery] false))
      wrap-json-response
      (wrap-json-body {:keywords? true})))

;; Server
(defn start-server [port]
  (reset! clients {})
  (reset-data!)
  (println "Starting server on port" port)
  (server/run-server app {:port port}))

;; Entry point
(defn -main [& args]
  (let [port (Integer/parseInt (or (first args) "8080"))]
    (start-server port)))
AI Powered Threat Detection Engine

Threat Detection Engine is an AI-assisted Intrusion Detection & Prevention module that identifies suspicious patterns in API/web traffic using:

Machine Learning (LSTM Model)
Rule-based security checks
User behavior anomaly detection
Threat Intelligence lookup (AbuseIPDB optional)

This system instantly responds with ALLOW / WARN / BLOCK decisions and logs all events for investigation.

 Feature                               Type      Description                                    
 -------------------------------  :-----------:  ---------------------------------------------- 
 SQL Injection Detection               Rule      Detects malicious SELECT, UNION, DROP patterns 
 XSS Detection                         Rule      Flags `<script>` injections                    
 Brute Force Login                  Behavioral   Repeated failed access attempts                
 Directory Scanning                 Behavioral   High count of random path hits                 
 DDoS Request Flood               Rate Limiting  Too many requests in short time                
 Bot Detection                      User-Agent   Curl, sqlmap, nmap, automation tools           
 Threat Intelligence Lookup            API       Checks IP reputation                           
 Machine Learning Classification        ML       Predicts attack type & confidence              
 IP Blocklisting                       IPS       Blocks malicious IP automatically              
 Logging System                        SOC       Stores decisions & audit evidence              

Machine Learning Module

Model: LSTM Neural Network

Predicts threat based on:
🔹 src_ip
🔹 dst_ip
🔹 protocol
🔹 port
🔹 packet_size

Trained using custom dataset → ml/train.py
Real-time prediction → ml/predict.py

Model Output:

Label (normal / attack type)

Confidence Score

If confidence > 0.92 → Automatic BLOCK
If 0.80–0.92 → WARN

microsoc-command-centre/
│
├── app.py  
├── classifier.py  
├── blocklist.py  
├── rate_limiter.py  
├── threat_intel.py  
│
└── ml/
      ├── train.py
      ├── predict.py
      ├── protocol_encoder.pkl
      ├── scaler.pkl
      ├── label_encoder.pkl
      └── ml/

| File                      | Purpose              |
| ------------------------- | -------------------- |
| `ml/train.py`             | Train the LSTM model |
| `ml/predict.py`           | Predict attacks      |
| `ml/ml/threat_lstm.keras` | Trained LSTM model   |
| `ml/protocol_encoder.pkl` | Protocol transformer |
| `ml/scaler.pkl`           | Feature scaler       |
| `ml/label_encoder.pkl`    | Output label encoder |


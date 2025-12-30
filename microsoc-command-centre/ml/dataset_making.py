import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

num_rows = 6000  # dataset size
start_time = datetime.now()

timestamps = []
src_ips = []
dst_ips = []
ports = []
protocols = []
packet_sizes = []
labels = []

protocol_list = ['TCP', 'UDP', 'ICMP']
attack_types = ['Normal', 'DoS', 'PortScan', 'SQLi', 'XSS']

def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

for i in range(num_rows):
    timestamps.append(start_time + timedelta(seconds=i))
    src_ips.append(random_ip())
    dst_ips.append(random_ip())


    port = random.randint(1, 65535)
    protocol = random.choice(protocol_list)
    packet_size = random.randint(60, 1500)

    prob = random.random()

    if prob < 0.80:   
        label = "Normal"

    elif prob < 0.88:  
        label = "DoS"
        protocol = 'UDP'
        packet_size = random.randint(800, 1500)

    elif prob < 0.94:  
        label = "PortScan"
        port = random.randint(1, 200)  # scanning small port range repeatedly
        protocol = 'TCP'
        packet_size = random.randint(60, 300)

    elif prob < 0.97:  # 3% SQL Injection
        label = "SQLi"
        port = random.choice([80, 443]) # web servers
        protocol = 'TCP'
        packet_size = random.randint(150, 400)

    else:  # 3% XSS
        label = "XSS"
        port = random.choice([80, 443])
        protocol = 'TCP'
        packet_size = random.randint(200, 600)

    ports.append(port)
    protocols.append(protocol)
    packet_sizes.append(packet_size)
    labels.append(label)

df = pd.DataFrame({
    'Timestamp': timestamps,
    'Source_IP': src_ips,
    'Destination_IP': dst_ips,
    'Port': ports,
    'Protocol': protocols,
    'Packet_Size': packet_sizes,
    'Label': labels
})

df.to_csv("lstm_threat_dataset.csv", index=False)
print("LSTM Dataset created successfully → lstm_threat_dataset.csv")

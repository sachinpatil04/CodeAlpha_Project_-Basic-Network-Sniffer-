from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import threading
import queue
import time

app = Flask(__name__)

packet_queue = queue.Queue()

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "Other"
        sport = dport = "-"
        payload = "<none>"

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        elif ICMP in packet:
            proto = "ICMP"

        if Raw in packet:
            payload = packet[Raw].load
        else:
            payload = ""

        try:
            payload = payload.decode(errors="ignore").strip()
            # Filter out non-printable characters
            payload = ''.join(c for c in payload if c.isprintable())
            # Truncate long payloads
            if len(payload) > 100:
                payload = payload[:100] + '...'
        except:
            payload = "<undecodable>"

        packet_info = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "src_port": sport,
            "dst_port": dport,
            "payload": payload
        }
        packet_queue.put(packet_info)

def start_sniff():
    sniff(prn=packet_callback, store=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/packets')
def get_packets():
    packets = []
    while not packet_queue.empty():
        packets.append(packet_queue.get())
    return jsonify(packets)

if __name__ == '__main__':
    threading.Thread(target=start_sniff, daemon=True).start()
    app.run(debug=True)

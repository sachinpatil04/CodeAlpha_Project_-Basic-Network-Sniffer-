import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
from datetime import datetime
import threading

# GUI setup
root = tk.Tk()
root.title("Basic Network Sniffer")

frame = ttk.Frame(root, padding=10)
frame.grid(row=0, column=0, sticky="nsew")
root.grid_rowconfigure(0, weight=1)
root.grid_columnconfigure(0, weight=1)

# Interface Dropdown
ttk.Label(frame, text="Select Interface:").grid(column=0, row=0, sticky=tk.W)
interfaces = get_if_list()
iface_var = tk.StringVar(value=interfaces[0])
iface_menu = ttk.Combobox(frame, textvariable=iface_var, values=interfaces, width=70)
iface_menu.grid(column=1, row=0, columnspan=2, sticky="we")

# Packet count
ttk.Label(frame, text="Packet Count (0 = infinite):").grid(column=0, row=1, sticky=tk.W)
count_entry = ttk.Entry(frame)
count_entry.insert(0, "10")
count_entry.grid(column=1, row=1, sticky="we")

# Timeout
ttk.Label(frame, text="Timeout (0 = no timeout):").grid(column=0, row=2, sticky=tk.W)
timeout_entry = ttk.Entry(frame)
timeout_entry.insert(0, "30")
timeout_entry.grid(column=1, row=2, sticky="we")

# Protocol filter
ttk.Label(frame, text="Protocol Filter (tcp, udp, icmp, arp, bootp, 0):").grid(column=0, row=3, sticky=tk.W)
filter_entry = ttk.Entry(frame)
filter_entry.insert(0, "0")
filter_entry.grid(column=1, row=3, sticky="we")

# Output box
output_box = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=20)
output_box.grid(column=0, row=5, columnspan=3, pady=10, sticky="nsew")
frame.grid_rowconfigure(5, weight=1)

# Helper to write to GUI and log file
def write_output(text):
    output_box.insert(tk.END, text + "\n")
    output_box.see(tk.END)
    with open("sniffer_log.txt", "a", encoding="utf-8") as log:
        log.write(text + "\n")

# Callback for each packet
def packet_callback(packet):
    write_output("Packet callback called")  # Debug log to confirm callback is called
    if IP in packet:
        now = datetime.now()
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

        if packet.haslayer(Raw):
            try:
                raw_data = bytes(packet[Raw]).decode(errors="ignore").strip()
                if raw_data:
                    payload = raw_data
            except:
                payload = "<undecodable>"

        log = (
            f"--- Packet Captured ---\n"
            f"Time: {now}\n"
            f"Source IP: {src_ip}\n"
            f"Destination IP: {dst_ip}\n"
            f"Protocol: {proto}\n"
            f"Source Port: {sport}\n"
            f"Destination Port: {dport}\n"
            f"Payload: {payload}\n"
        )
        write_output(log)
    else:
        write_output("Non-IP packet detected.\n")

# Start sniffing
def start_capture():
    output_box.delete(1.0, tk.END)  # clear output
    with open("sniffer_log.txt", "w", encoding="utf-8") as f:
        f.write("")  # clear old log

    iface = iface_var.get()
    count = int(count_entry.get() or 0)
    timeout = int(timeout_entry.get() or 0)
    proto = filter_entry.get().lower()
    bpf = None  # Temporarily disable filter to capture all packets

    write_output(f"\nStarting packet capture on interface: {iface}")
    write_output(f"Filter: {proto}, Count: {count}, Timeout: {timeout}\n")
    write_output("Note: Please run this script with administrator/root privileges for packet capture to work properly.\n")

    def run_sniff():
        try:
            write_output("Starting sniffing now...")
            sniff(
                iface=None,  # Capture on all interfaces
                prn=packet_callback,
                filter=bpf,
                count=0 if count == 0 else count,
                timeout=None if timeout == 0 else timeout
            )
            write_output("Capture complete. Log saved to 'sniffer_log.txt'.\n")
        except Exception as e:
            write_output(f"Error during sniffing: {e}\n")

    threading.Thread(target=run_sniff, daemon=True).start()

# Button
start_button = ttk.Button(frame, text="Start Capture", command=start_capture)
start_button.grid(column=1, row=4, pady=5)

# Launch GUI
root.mainloop()

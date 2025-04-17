import socket
import struct
import threading
import csv
import time
import requests
from collections import defaultdict
from flask import Flask, render_template, send_file, jsonify
from flask_socketio import SocketIO, emit
import dpkt

app = Flask(__name__, template_folder='templates')
socketio = SocketIO(app)

PROTOCOLS = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
PACKET_LOG = []
PACKET_COUNT = defaultdict(int)
CSV_FILE = "packet_log.csv"
PCAP_FILE = "packet_log.pcap"
THRESHOLD = 200
ALERT_WINDOW = 10
TRAFFIC_HISTORY = defaultdict(list)
PAUSE_UPDATES = False
PAUSE_MODE = "soft"

packet_rate_history = []
dns_queries = []
ip_country_cache = {}  # cache for IP geolocation

with open(CSV_FILE, 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'Protocol', 'Source IP', 'Destination IP', 'Country'])

pcap_writer = dpkt.pcap.Writer(open(PCAP_FILE, 'wb'))

def get_country(ip):
    if ip in ip_country_cache:
        return ip_country_cache[ip]
    try:
        if ip.startswith("192.") or ip.startswith("127."):
            ip_country_cache[ip] = "Local"
        else:
            res = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=1)
            ip_country_cache[ip] = res.json().get("country", "Unknown")
        return ip_country_cache[ip]
    except:
        ip_country_cache[ip] = "Unknown"
        return "Unknown"

def extract_dns_name(data):
    try:
        dns = dpkt.dns.DNS(data)
        if dns.qd and len(dns.qd) > 0:
            name = dns.qd[0].name
            return name.decode() if isinstance(name, bytes) else name
    except:
        return None

def parse_packet(packet, raw_data):
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = struct.unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    if eth_protocol == 8:
        ip_header = packet[eth_length:eth_length+20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        ihl = iph[0] & 0xF
        iph_length = ihl * 4
        protocol = iph[6]

        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        if s_addr.startswith("127.") or d_addr.startswith("127."):
            return None

        proto_name = PROTOCOLS.get(protocol, 'OTHER')

        domain = None
        if proto_name == 'UDP':
            udp_offset = eth_length + iph_length
            udp_header = packet[udp_offset:udp_offset+8]
            udph = struct.unpack('!HHHH', udp_header)
            sport, dport = udph[0], udph[1]
            if sport == 53 or dport == 53:
                domain = extract_dns_name(packet[udp_offset+8:])
                if domain:
                    dns_queries.append(domain)

        return {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': s_addr,
            'dest_ip': d_addr,
            'protocol': proto_name,
            'country': get_country(s_addr),
            'dns': domain or ""
        }
    return None

def check_alerts(ip):
    now = time.time()
    TRAFFIC_HISTORY[ip] = [t for t in TRAFFIC_HISTORY[ip] if now - t <= ALERT_WINDOW]
    TRAFFIC_HISTORY[ip].append(now)
    if len(TRAFFIC_HISTORY[ip]) > THRESHOLD:
        socketio.emit('alert', {'ip': ip, 'count': len(TRAFFIC_HISTORY[ip])})

def packet_sniffer():
    global pcap_writer
    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        while True:
            raw_data, _ = sniffer.recvfrom(65535)

            if PAUSE_UPDATES and PAUSE_MODE == "hard":
                time.sleep(0.1)
                continue

            parsed = parse_packet(raw_data, raw_data)
            if parsed:
                PACKET_LOG.append(parsed)
                PACKET_COUNT[parsed['source_ip']] += 1
                check_alerts(parsed['source_ip'])

                with open(CSV_FILE, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([parsed['timestamp'], parsed['protocol'], parsed['source_ip'], parsed['dest_ip'], parsed['country']])

                pcap_writer.writepkt(raw_data)

                if PAUSE_UPDATES and PAUSE_MODE == "soft":
                    continue

                socketio.emit('packet', parsed)
                socketio.emit('stats', dict(PACKET_COUNT))
    except Exception as e:
        print(f"Sniffer error: {e}")

def emit_packet_rate():
    prev_count = 0
    while True:
        time.sleep(1)
        current_count = sum(PACKET_COUNT.values())
        rate = current_count - prev_count
        prev_count = current_count
        timestamp = time.strftime('%H:%M:%S')
        packet_rate_history.append((timestamp, rate))
        if len(packet_rate_history) > 300:
            packet_rate_history.pop(0)
        socketio.emit('packet_rate', {'timestamp': timestamp, 'count': rate})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download')
def download_csv():
    return send_file(CSV_FILE, as_attachment=True)

@app.route('/download/pcap')
def download_pcap():
    return send_file(PCAP_FILE, as_attachment=True)

@app.route('/rate_csv')
def rate_csv():
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Packets/sec'])
    writer.writerows(packet_rate_history)
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='traffic_rate.csv')

@app.route('/dns_queries')
def dns_query_list():
    return jsonify(dns_queries)

@app.route('/pause')
def pause():
    global PAUSE_UPDATES
    PAUSE_UPDATES = True
    return "Paused"

@app.route('/resume')
def resume():
    global PAUSE_UPDATES
    PAUSE_UPDATES = False
    return "Resumed"

@app.route('/pause_mode/<mode>')
def set_pause_mode(mode):
    global PAUSE_MODE
    if mode in ["soft", "hard"]:
        PAUSE_MODE = mode
        return f"Pause mode set to {mode}"
    return "Invalid mode", 400

@app.route('/clear')
def clear():
    global pcap_writer
    PACKET_LOG.clear()
    PACKET_COUNT.clear()
    TRAFFIC_HISTORY.clear()
    packet_rate_history.clear()
    dns_queries.clear()
    ip_country_cache.clear()
    with open(CSV_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'Protocol', 'Source IP', 'Destination IP', 'Country'])
    with open(PCAP_FILE, 'wb') as f:
        pcap_writer = dpkt.pcap.Writer(f)
    return "Cleared"

if __name__ == '__main__':
    threading.Thread(target=packet_sniffer, daemon=True).start()
    threading.Thread(target=emit_packet_rate, daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=5000)

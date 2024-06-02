from scapy.all import PcapReader
import matplotlib.pyplot as plt
from collections import defaultdict
import pandas as pd
import geoip2.database

target_ip = '192.168.10.100'

# Function to read a limited number of packets from a pcap file in a memory-efficient manner
def read_pcap(file_path, max_packets=10000):
    with PcapReader(file_path) as pcap_reader:
        for i, packet in enumerate(pcap_reader):
            if i >= max_packets:
                break
            yield packet.time, packet

# Function to extract IP and TCP/UDP information
def extract_info(packet):
    if not packet.haslayer('IP'):
        return None, None, None
    ip = packet['IP']
    src_ip = ip.src
    dst_ip = ip.dst
    if packet.haslayer('TCP'):
        protocol = 'TCP'
    elif packet.haslayer('UDP'):
        protocol = 'UDP'
    else:
        protocol = 'OTHER'
    return src_ip, dst_ip, protocol

# Function to implement the sliding window and calculate the metric
def sliding_window_analysis(pcap_file, window_size=1, max_packets=10000):
    packet_counts = defaultdict(lambda: [0, 0])  # {ip: [sent, received]}
    window_metrics = []
    window_start = None
    window_packets = []
    
    for timestamp, packet in read_pcap(pcap_file, max_packets):
        if window_start is None:
            window_start = timestamp
        src_ip, dst_ip, protocol = extract_info(packet)
        if src_ip is None:
            continue
        window_packets.append((timestamp, src_ip, dst_ip))
        
        if timestamp - window_start >= window_size:
            # Calculate the metric for the window
            for ts, src, dst in window_packets:
                if dst == target_ip:
                    packet_counts['received'][0] += 1
                elif src == target_ip:
                    packet_counts['sent'][1] += 1
            if len(packet_counts) > 0:
                sent_count = packet_counts['sent'][1]
                received_count = packet_counts['received'][0]
                balance_metric = (received_count - sent_count) / (received_count + sent_count)
                window_metrics.append((window_start, balance_metric))
            # Move to the next window
            window_start = timestamp
            window_packets = []
            packet_counts = defaultdict(lambda: [0, 0])
    
    # Ensure the last window is processed
    if window_packets:
        for ts, src, dst in window_packets:
            if dst == target_ip:
                packet_counts['received'][0] += 1
            elif src == target_ip:
                packet_counts['sent'][1] += 1
        if len(packet_counts) > 0:
            sent_count = packet_counts['sent'][1]
            received_count = packet_counts['received'][0]
            balance_metric = (received_count - sent_count) / (received_count + sent_count)
            window_metrics.append((window_start, balance_metric))
    
    # Debug: Print window metrics count
    print(f"Total windows processed: {len(window_metrics)}")
    
    return window_metrics

# Function to plot the metrics
def plot_metrics(metrics):
    times, values = zip(*metrics)
    plt.figure(figsize=(10, 6))
    plt.plot(times, values, marker='o')
    plt.title('Traffic Balance Metric Over Time')
    plt.xlabel('Time (s)')
    plt.ylabel('Balance Metric')
    plt.ylim([-1, 1])
    plt.grid(True)
    plt.show()

# Time-based packet analysis function
def time_based_analysis(pcap_file, bin_size=1, max_packets=10000):
    bins = defaultdict(lambda: [0, 0])  # {time_bin: [sent, received]}
    for timestamp, packet in read_pcap(pcap_file, max_packets):
        src_ip, dst_ip, protocol = extract_info(packet)
        if src_ip is None:
            continue
        bin_time = int(timestamp // bin_size) * bin_size
        if dst_ip == target_ip:
            bins[bin_time][0] += 1
        elif src_ip == target_ip:
            bins[bin_time][1] += 1
    bin_times, bin_metrics = [], []
    for bin_time, (received, sent) in sorted(bins.items()):
        bin_times.append(bin_time)
        bin_metrics.append((received - sent) / max(1, (received + sent)))
    
    # Debug: Print bin counts
    print(f"Total bins processed: {len(bin_times)}")
    
    return bin_times, bin_metrics

# Function to plot the time-based analysis
def plot_time_based_analysis(bin_times, bin_metrics, bin_size):
    if not bin_times or not bin_metrics:
        print("No bin data to plot.")
        return

    plt.figure(figsize=(10, 6))
    plt.plot(bin_times, bin_metrics, marker='o')
    plt.title('Average Balance Metric Per Time Bin')
    plt.xlabel('Time (s)')
    plt.ylabel('Average Balance Metric')
    plt.ylim([-1, 1])
    plt.grid(True)
    plt.show()

# Function to analyze top source IPs and their countries
def ip_analysis(pcap_file, max_packets=10000):
    country_counts = defaultdict(int)
    reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
    
    for timestamp, packet in read_pcap(pcap_file, max_packets):
        src_ip, dst_ip, protocol = extract_info(packet)
        if src_ip is None:
            continue
        try:
            response = reader.country(src_ip)
            country = response.country.name
        except Exception:
            country = 'Unknown'
        country_counts[country] += 1
    
    top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return top_countries

# Function to display top IPs and countries in a table
def display_top_countries(top_countries):
    if not top_countries:
        print("No country data to display.")
        return

    df = pd.DataFrame(top_countries, columns=['Country', 'Count'])
    print(df)

# Main analysis function
def analyze_pcap(pcap_file, window_size=1, bin_size=1, max_packets=10000):
    metrics = sliding_window_analysis(pcap_file, window_size, max_packets)
    plot_metrics(metrics)
    bin_times, bin_metrics = time_based_analysis(pcap_file, bin_size, max_packets)
    plot_time_based_analysis(bin_times, bin_metrics, bin_size)
    top_countries = ip_analysis(pcap_file, max_packets)
    display_top_countries(top_countries)

# Run the complete analysis
pcap_file = 'OUTPUTFILE.pcap'  # Corrected to the actual pcap file path
analyze_pcap(pcap_file, window_size=1, bin_size=1, max_packets=10000)

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
import socket
import platform
from colorama import Fore, Back, Style, init
import subprocess
import json

# Initialize colorama
init(autoreset=True)

# Page configuration
st.set_page_config(
    page_title="Scapy Network Traffic Analyzer",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: #f8f9fa;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #667eea;
    }
    .alert-danger {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
        padding: 0.75rem;
        border-radius: 0.25rem;
    }
    .alert-warning {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        color: #856404;
        padding: 0.75rem;
        border-radius: 0.25rem;
    }
    .alert-success {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
        padding: 0.75rem;
        border-radius: 0.25rem;
    }
    .protocol-tcp { color: #e74c3c; }
    .protocol-udp { color: #3498db; }
    .protocol-icmp { color: #f39c12; }
    .protocol-other { color: #95a5a6; }
</style>
""", unsafe_allow_html=True)

class ScapyNetworkMonitor:
    def __init__(self):
        self.packets = deque(maxlen=1000)
        self.traffic_stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.packet_sizes = deque(maxlen=100)
        self.capture_running = False
        self.capture_thread = None
        self.interface = None
        self.packet_count = 0
        self.start_time = datetime.now()
        
    def get_available_interfaces(self):
        """Get available network interfaces"""
        try:
            interfaces = get_if_list()
            return interfaces
        except:
            return ["eth0", "wlan0", "lo"]  # Default interfaces
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        try:
            timestamp = datetime.now()
            packet_info = {
                'timestamp': timestamp,
                'size': len(packet),
                'protocol': 'Other'
            }
            
            # Extract protocol information
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info.update({
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'protocol': ip_layer.proto
                })
                
                # Update IP statistics
                self.ip_stats[ip_layer.src] += 1
                self.ip_stats[ip_layer.dst] += 1
                
                # Protocol specific handling
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    packet_info.update({
                        'protocol': 'TCP',
                        'src_port': tcp_layer.sport,
                        'dst_port': tcp_layer.dport,
                        'flags': tcp_layer.flags
                    })
                    self.port_stats[tcp_layer.sport] += 1
                    self.port_stats[tcp_layer.dport] += 1
                    
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    packet_info.update({
                        'protocol': 'UDP',
                        'src_port': udp_layer.sport,
                        'dst_port': udp_layer.dport
                    })
                    self.port_stats[udp_layer.sport] += 1
                    self.port_stats[udp_layer.dport] += 1
                    
                elif packet.haslayer(ICMP):
                    packet_info['protocol'] = 'ICMP'
            
            # Update statistics
            self.packets.append(packet_info)
            self.protocol_stats[packet_info['protocol']] += 1
            self.packet_sizes.append(len(packet))
            self.packet_count += 1
            
        except Exception as e:
            st.error(f"Error processing packet: {str(e)}")
    
    def start_capture(self, interface="any", duration=None):
        """Start packet capture"""
        if self.capture_running:
            return False
        
        self.capture_running = True
        self.interface = interface
        
        def capture_packets():
            try:
                if interface == "any":
                    sniff(prn=self.packet_handler, stop_filter=lambda x: not self.capture_running, timeout=duration)
                else:
                    sniff(iface=interface, prn=self.packet_handler, stop_filter=lambda x: not self.capture_running, timeout=duration)
            except Exception as e:
                st.error(f"Capture error: {str(e)}")
            finally:
                self.capture_running = False
        
        self.capture_thread = threading.Thread(target=capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        return True
    
    def stop_capture(self):
        """Stop packet capture"""
        self.capture_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def get_traffic_summary(self):
        """Get traffic summary statistics"""
        if not self.packets:
            return {}
        
        total_bytes = sum(p['size'] for p in self.packets)
        duration = (datetime.now() - self.start_time).total_seconds()
        
        return {
            'total_packets': len(self.packets),
            'total_bytes': total_bytes,
            'avg_packet_size': total_bytes / len(self.packets) if self.packets else 0,
            'duration': duration,
            'packets_per_second': len(self.packets) / duration if duration > 0 else 0,
            'bytes_per_second': total_bytes / duration if duration > 0 else 0
        }
    
    def get_protocol_distribution(self):
        """Get protocol distribution"""
        return dict(self.protocol_stats)
    
    def get_top_ips(self, limit=10):
        """Get top IP addresses by packet count"""
        return dict(sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:limit])
    
    def get_top_ports(self, limit=10):
        """Get top ports by packet count"""
        return dict(sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:limit])
    
    def detect_anomalies(self):
        """Detect potential network anomalies"""
        alerts = []
        
        if not self.packets:
            return alerts
        
        # Check for port scanning
        recent_packets = [p for p in self.packets if (datetime.now() - p['timestamp']).seconds < 60]
        if recent_packets:
            unique_ports = set()
            for p in recent_packets:
                if 'dst_port' in p:
                    unique_ports.add(p['dst_port'])
            
            if len(unique_ports) > 20:  # Many different ports in short time
                alerts.append({
                    'type': 'danger',
                    'message': f"Potential port scan detected: {len(unique_ports)} unique ports in last minute"
                })
        
        # Check for unusual traffic volume
        if len(self.packets) > 500:  # High packet count
            alerts.append({
                'type': 'warning',
                'message': f"High traffic volume: {len(self.packets)} packets captured"
            })
        
        # Check for large packets
        large_packets = [p for p in self.packets if p['size'] > 1500]
        if len(large_packets) > len(self.packets) * 0.1:  # >10% large packets
            alerts.append({
                'type': 'warning',
                'message': f"High number of large packets: {len(large_packets)} packets > 1500 bytes"
            })
        
        return alerts

def format_bytes(bytes_value):
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"

def get_system_info():
    """Get system network information"""
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = "Unable to resolve"
    
    return {
        'Hostname': hostname,
        'Local IP': local_ip,
        'Platform': platform.system(),
        'Architecture': platform.architecture()[0],
        'Python Version': platform.python_version()
    }

def main():
    # Initialize session state
    if 'monitor' not in st.session_state:
        st.session_state.monitor = ScapyNetworkMonitor()
    
    if 'capture_started' not in st.session_state:
        st.session_state.capture_started = False
    
    monitor = st.session_state.monitor
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>📡 Scapy Network Traffic Analyzer</h1>
        <p>Advanced packet capture and network analysis with Scapy</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar configuration
    st.sidebar.header("🛠️ Packet Capture Settings")
    
    # Interface selection
    interfaces = monitor.get_available_interfaces()
    selected_interface = st.sidebar.selectbox(
        "Select Network Interface:",
        ["any"] + interfaces,
        index=0
    )
    
    # Capture duration
    capture_duration = st.sidebar.number_input(
        "Capture Duration (seconds)", 
        min_value=5, 
        max_value=300, 
        value=30
    )
    
    # Capture controls
    col1, col2 = st.sidebar.columns(2)
    
    with col1:
        if st.button("🚀 Start Capture", disabled=monitor.capture_running):
            if monitor.start_capture(selected_interface, capture_duration):
                st.session_state.capture_started = True
                st.success("Capture started!")
                st.rerun()
    
    with col2:
        if st.button("⏹️ Stop Capture", disabled=not monitor.capture_running):
            monitor.stop_capture()
            st.session_state.capture_started = False
            st.success("Capture stopped!")
            st.rerun()
    
    # Display capture status
    if monitor.capture_running:
        st.sidebar.markdown("🟢 **Status:** Capturing packets...")
        st.sidebar.markdown(f"**Interface:** {monitor.interface}")
    else:
        st.sidebar.markdown("🔴 **Status:** Not capturing")
    
    # Main dashboard
    if monitor.packets:
        # Traffic summary
        summary = monitor.get_traffic_summary()
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "📦 Total Packets",
                f"{summary['total_packets']:,}",
                delta=None
            )
        
        with col2:
            st.metric(
                "💾 Total Data",
                format_bytes(summary['total_bytes']),
                delta=None
            )
        
        with col3:
            st.metric(
                "📊 Avg Packet Size",
                format_bytes(summary['avg_packet_size']),
                delta=None
            )
        
        with col4:
            st.metric(
                "⚡ Packets/sec",
                f"{summary['packets_per_second']:.1f}",
                delta=None
            )
        
        # Additional metrics
        col1, col2 = st.columns(2)
        with col1:
            st.metric(
                "📈 Data Rate",
                format_bytes(summary['bytes_per_second']) + "/s",
                delta=None
            )
        
        with col2:
            st.metric(
                "⏱️ Capture Duration",
                f"{summary['duration']:.1f}s",
                delta=None
            )
        
        # Security alerts
        alerts = monitor.detect_anomalies()
        if alerts:
            st.markdown("### 🚨 Security Alerts")
            for alert in alerts:
                if alert['type'] == 'danger':
                    st.markdown(f'<div class="alert-danger">⚠️ {alert["message"]}</div>', unsafe_allow_html=True)
                elif alert['type'] == 'warning':
                    st.markdown(f'<div class="alert-warning">⚡ {alert["message"]}</div>', unsafe_allow_html=True)
        
        # Tabs for different analyses
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Protocol Analysis", 
            "🌐 IP Analysis", 
            "🔌 Port Analysis", 
            "📈 Traffic Trends", 
            "🔍 Packet Details"
        ])
        
        with tab1:
            st.markdown("### Protocol Distribution")
            
            protocol_data = monitor.get_protocol_distribution()
            if protocol_data:
                # Create matplotlib pie chart
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
                
                # Pie chart
                colors = ['#e74c3c', '#3498db', '#f39c12', '#2ecc71', '#9b59b6']
                wedges, texts, autotexts = ax1.pie(
                    protocol_data.values(), 
                    labels=protocol_data.keys(), 
                    autopct='%1.1f%%',
                    colors=colors[:len(protocol_data)]
                )
                ax1.set_title('Protocol Distribution')
                
                # Bar chart
                protocols = list(protocol_data.keys())
                counts = list(protocol_data.values())
                bars = ax2.bar(protocols, counts, color=colors[:len(protocol_data)])
                ax2.set_title('Protocol Packet Counts')
                ax2.set_ylabel('Packet Count')
                plt.xticks(rotation=45)
                
                # Add value labels on bars
                for bar, count in zip(bars, counts):
                    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(counts)*0.01,
                            str(count), ha='center', va='bottom')
                
                plt.tight_layout()
                st.pyplot(fig)
                
                # Protocol table
                protocol_df = pd.DataFrame([
                    {'Protocol': k, 'Packets': v, 'Percentage': f"{(v/sum(protocol_data.values())*100):.1f}%"}
                    for k, v in protocol_data.items()
                ])
                st.dataframe(protocol_df, use_container_width=True)
        
        with tab2:
            st.markdown("### IP Address Analysis")
            
            top_ips = monitor.get_top_ips(15)
            if top_ips:
                # Top IPs chart
                fig, ax = plt.subplots(figsize=(12, 6))
                ips = list(top_ips.keys())[:10]  # Top 10
                counts = list(top_ips.values())[:10]
                
                bars = ax.barh(ips, counts, color='#3498db')
                ax.set_title('Top 10 IP Addresses by Packet Count')
                ax.set_xlabel('Packet Count')
                
                # Add value labels
                for bar, count in zip(bars, counts):
                    ax.text(bar.get_width() + max(counts)*0.01, bar.get_y() + bar.get_height()/2,
                           str(count), ha='left', va='center')
                
                plt.tight_layout()
                st.pyplot(fig)
                
                # IP table
                ip_df = pd.DataFrame([
                    {'IP Address': k, 'Packet Count': v}
                    for k, v in top_ips.items()
                ])
                st.dataframe(ip_df, use_container_width=True)
        
        with tab3:
            st.markdown("### Port Analysis")
            
            top_ports = monitor.get_top_ports(15)
            if top_ports:
                # Top ports chart
                fig, ax = plt.subplots(figsize=(12, 6))
                ports = [str(p) for p in list(top_ports.keys())[:10]]
                counts = list(top_ports.values())[:10]
                
                bars = ax.bar(ports, counts, color='#e74c3c')
                ax.set_title('Top 10 Ports by Packet Count')
                ax.set_xlabel('Port Number')
                ax.set_ylabel('Packet Count')
                plt.xticks(rotation=45)
                
                # Add value labels
                for bar, count in zip(bars, counts):
                    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(counts)*0.01,
                           str(count), ha='center', va='bottom')
                
                plt.tight_layout()
                st.pyplot(fig)
                
                # Port table with service identification
                port_services = {
                    80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
                    25: 'SMTP', 53: 'DNS', 110: 'POP3', 143: 'IMAP',
                    993: 'IMAPS', 995: 'POP3S', 587: 'SMTP', 3389: 'RDP'
                }
                
                port_df = pd.DataFrame([
                    {
                        'Port': k, 
                        'Packet Count': v,
                        'Service': port_services.get(k, 'Unknown')
                    }
                    for k, v in top_ports.items()
                ])
                st.dataframe(port_df, use_container_width=True)
        
        with tab4:
            st.markdown("### Traffic Trends")
            
            if len(monitor.packets) > 1:
                # Prepare time series data
                df_packets = pd.DataFrame(monitor.packets)
                df_packets['minute'] = df_packets['timestamp'].dt.floor('min')
                
                # Group by minute
                traffic_by_minute = df_packets.groupby('minute').agg({
                    'size': ['count', 'sum'],
                    'timestamp': 'first'
                }).reset_index()
                
                traffic_by_minute.columns = ['minute', 'packet_count', 'total_bytes', 'timestamp']
                
                if len(traffic_by_minute) > 1:
                    # Traffic over time
                    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
                    
                    # Packet count over time
                    ax1.plot(traffic_by_minute['minute'], traffic_by_minute['packet_count'], 
                            marker='o', color='#3498db', linewidth=2)
                    ax1.set_title('Packets per Minute')
                    ax1.set_ylabel('Packet Count')
                    ax1.grid(True, alpha=0.3)
                    
                    # Bytes over time
                    ax2.plot(traffic_by_minute['minute'], traffic_by_minute['total_bytes'], 
                            marker='s', color='#e74c3c', linewidth=2)
                    ax2.set_title('Bytes per Minute')
                    ax2.set_ylabel('Bytes')
                    ax2.set_xlabel('Time')
                    ax2.grid(True, alpha=0.3)
                    
                    # Format x-axis
                    for ax in [ax1, ax2]:
                        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
                        ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=1))
                        plt.setp(ax.xaxis.get_majorticklabels(), rotation=45)
                    
                    plt.tight_layout()
                    st.pyplot(fig)
                
                # Packet size distribution
                st.markdown("#### Packet Size Distribution")
                fig, ax = plt.subplots(figsize=(10, 5))
                ax.hist(monitor.packet_sizes, bins=20, color='#2ecc71', alpha=0.7, edgecolor='black')
                ax.set_title('Packet Size Distribution')
                ax.set_xlabel('Packet Size (bytes)')
                ax.set_ylabel('Frequency')
                ax.grid(True, alpha=0.3)
                st.pyplot(fig)
        
        with tab5:
            st.markdown("### Recent Packet Details")
            
            if monitor.packets:
                # Display recent packets
                recent_packets = list(monitor.packets)[-20:]  # Last 20 packets
                packet_details = []
                
                for i, packet in enumerate(recent_packets):
                    detail = {
                        'Index': len(monitor.packets) - len(recent_packets) + i + 1,
                        'Timestamp': packet['timestamp'].strftime('%H:%M:%S.%f')[:-3],
                        'Protocol': packet['protocol'],
                        'Size': packet['size'],
                        'Source': packet.get('src_ip', 'N/A'),
                        'Destination': packet.get('dst_ip', 'N/A'),
                        'Src Port': packet.get('src_port', 'N/A'),
                        'Dst Port': packet.get('dst_port', 'N/A')
                    }
                    packet_details.append(detail)
                
                packet_df = pd.DataFrame(packet_details)
                st.dataframe(packet_df, use_container_width=True)
                
                # Packet filtering
                st.markdown("#### Filter Packets")
                col1, col2 = st.columns(2)
                
                with col1:
                    protocol_filter = st.selectbox(
                        "Filter by Protocol:",
                        ["All"] + list(monitor.get_protocol_distribution().keys())
                    )
                
                with col2:
                    ip_filter = st.text_input("Filter by IP Address (contains):")
                
                # Apply filters
                filtered_packets = list(monitor.packets)
                if protocol_filter != "All":
                    filtered_packets = [p for p in filtered_packets if p['protocol'] == protocol_filter]
                if ip_filter:
                    filtered_packets = [p for p in filtered_packets 
                                      if ip_filter in p.get('src_ip', '') or ip_filter in p.get('dst_ip', '')]
                
                st.markdown(f"**Filtered Results:** {len(filtered_packets)} packets")
                
                if filtered_packets:
                    filtered_details = []
                    for packet in filtered_packets[-10:]:  # Show last 10 filtered
                        detail = {
                            'Timestamp': packet['timestamp'].strftime('%H:%M:%S.%f')[:-3],
                            'Protocol': packet['protocol'],
                            'Size': packet['size'],
                            'Source → Destination': f"{packet.get('src_ip', 'N/A')} → {packet.get('dst_ip', 'N/A')}",
                            'Ports': f"{packet.get('src_port', 'N/A')} → {packet.get('dst_port', 'N/A')}"
                        }
                        filtered_details.append(detail)
                    
                    filtered_df = pd.DataFrame(filtered_details)
                    st.dataframe(filtered_df, use_container_width=True)
    
    else:
        # No data captured yet
        st.info("👆 Click 'Start Capture' in the sidebar to begin monitoring network traffic.")
        
        # Show system info while waiting
        st.markdown("### 💻 System Information")
        system_info = get_system_info()
        
        col1, col2 = st.columns(2)
        with col1:
            for key, value in system_info.items():
                st.text(f"{key}: {value}")
        
        with col2:
            st.markdown("#### Available Interfaces")
            for interface in interfaces:
                st.text(f"• {interface}")
    
    # Footer
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown(f"**Last Updated:** {datetime.now().strftime('%H:%M:%S')}")
    
    with col2:
        if monitor.capture_running:
            st.markdown("🟢 **Capture:** Active")
        else:
            st.markdown("🔴 **Capture:** Stopped")
    
    with col3:
        st.markdown(f"**Packets Captured:** {len(monitor.packets)}")
    
    # Auto-refresh for real-time updates
    if monitor.capture_running:
        time.sleep(2)
        st.rerun()

if __name__ == "__main__":
    main()
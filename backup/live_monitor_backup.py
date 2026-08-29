import streamlit as st
import pandas as pd
from scapy.all import sniff
from scapy.config import conf
conf.use_pcap = True
from datetime import datetime

st.set_page_config(
    page_title="Live Network Monitor",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Live Network Traffic Monitor")
st.write("Capture network packets and view basic traffic statistics.")

if "packets" not in st.session_state:
    st.session_state.packets = []

def process_packet(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]

        protocol = "Other"

        if packet.haslayer("TCP"):
            protocol = "TCP"
        elif packet.haslayer("UDP"):
            protocol = "UDP"
        elif packet.haslayer("ICMP"):
            protocol = "ICMP"

        packet_info = {
            "Time": datetime.now().strftime("%H:%M:%S"),
            "Source IP": ip_layer.src,
            "Destination IP": ip_layer.dst,
            "Protocol": protocol,
            "Packet Size": len(packet)
        }

        st.session_state.packets.append(packet_info)

st.subheader("Live Capture")

packet_count = st.number_input(
    "Number of packets to capture",
    min_value=1,
    max_value=100,
    value=10
)

if st.button("▶ Start Network Capture", type="primary"):

    st.info("Capturing network traffic...")

    sniff(
        count=int(packet_count),
        prn=process_packet,
        store=False
    )

    st.success("✅ Packet capture completed!")

if st.button("🗑️ Clear Results"):
    st.session_state.packets = []

if st.session_state.packets:

    df = pd.DataFrame(st.session_state.packets)

    st.subheader("Captured Network Traffic")

    st.dataframe(
        df,
        use_container_width=True
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            "Packets Captured",
            len(df)
        )

    with col2:
        st.metric(
            "Unique Source IPs",
            df["Source IP"].nunique()
        )

    with col3:
        st.metric(
            "Unique Destination IPs",
            df["Destination IP"].nunique()
        )

    st.subheader("Protocol Distribution")

    protocol_counts = df["Protocol"].value_counts()

    st.bar_chart(protocol_counts)

else:
    st.info(
        "No packets captured yet. Click 'Start Network Capture' to begin."
    )
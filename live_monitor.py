import streamlit as st
import pandas as pd
import joblib
import numpy as np
from scapy.all import sniff
from scapy.config import conf
conf.use_pcap = True
from datetime import datetime

# Load AI model and preprocessing components
model = joblib.load("rf.sav")
scaler = joblib.load("scaler.sav")
label_encoders = joblib.load("label_encoders.sav")


st.set_page_config(
    page_title="Live Network Monitor",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Live Network Traffic Monitor")
st.write("Capture network packets and view basic traffic statistics.")

if "packets" not in st.session_state:
    st.session_state.packets = []

if "capture_count" not in st.session_state:
    st.session_state.capture_count = 0

if "capture_history" not in st.session_state:
    st.session_state.capture_history = []

def process_packet(packet):
    print("PACKET RECEIVED")

    if packet.haslayer("IP"):
        print("IP PACKET RECEIVED")
        ip_layer = packet["IP"]

    elif packet.haslayer("IPv6"):
        print("IPv6 PACKET RECEIVED")
        ip_layer = packet["IPv6"]

    else:
        return

    protocol = "Other"

    if packet.haslayer("TCP"):
        protocol = "TCP"
    elif packet.haslayer("UDP"):
        protocol = "UDP"
    elif packet.haslayer("ICMP"):
        protocol = "ICMP"

    # Basic traffic information
    src_bytes = len(packet)
    dst_bytes = 0
    count = 1
    same_srv_rate = 1.0
    diff_srv_rate = 0.0
    dst_host_srv_count = 1
    dst_host_same_srv_rate = 1.0
    dst_host_same_src_port_rate = 0.0

    # Values compatible with the trained model
    service = "http"
    flag = "SF"

    # Use TCP information when available
    if packet.haslayer("TCP"):
        tcp = packet["TCP"]

        if tcp.dport == 80 or tcp.sport == 80:
            service = "http"
        elif tcp.dport == 443 or tcp.sport == 443:
            service = "http"
        elif tcp.dport == 22 or tcp.sport == 22:
            service = "ssh"

        flag = "SF"

    # Prepare input for the trained AI model
    try:
        input_data = pd.DataFrame([{
            "service": service,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": count,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate": dst_host_same_srv_rate,
            "dst_host_same_src_port_rate": dst_host_same_src_port_rate
        }])

        # Encode categorical features
        for feature in ["service", "flag"]:
            input_data[feature] = (
                label_encoders[feature]
                .transform(input_data[feature].astype(str))
            )

        # Make all values numeric
        input_data = input_data.apply(pd.to_numeric)

        # Scale the features
        input_scaled = scaler.transform(input_data)

        # AI prediction
        prediction = model.predict(input_scaled)[0]
        probability = model.predict_proba(input_scaled)[0]

        if prediction == 0:
            classification = "ANOMALY"
            confidence = probability[0] * 100
        else:
            classification = "NORMAL"
            confidence = probability[1] * 100

    except Exception as e:
        classification = "UNKNOWN"
        confidence = 0
        print("AI prediction error:", e)

    packet_info = {
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Source IP": ip_layer.src,
        "Destination IP": ip_layer.dst,
        "Protocol": protocol,
        "Packet Size": len(packet),
        "AI Classification": classification,
        "AI Confidence": f"{confidence:.2f}%"
    }

    st.session_state.packets.append(packet_info)

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
    st.session_state.capture_count += 1

    st.session_state.capture_history.append({
        "Session": st.session_state.capture_count,
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Packets": len(st.session_state.packets)
    })

    st.success("✅ Packet capture completed!")

    st.caption(
        f"Last capture completed at {datetime.now().strftime('%H:%M:%S')}"
    )

    st.caption(
        f"📦 Packets captured in this session: {len(st.session_state.packets)}"
    )

if st.button("🗑️ Clear Results"):
    st.session_state.packets = []

if st.session_state.packets:

    df = pd.DataFrame(st.session_state.packets)

    st.subheader("Captured Network Traffic")

    st.dataframe(
        df,
        width="stretch"
    )

    st.download_button(
        label="📥 Download Traffic Report",
        data=df.to_csv(index=False),
        file_name="network_traffic_report.csv",
        mime="text/csv"
    )

    # AI Summary Metrics
    total_packets = len(df)
    normal_packets = (df["AI Classification"] == "NORMAL").sum()
    anomaly_packets = (df["AI Classification"] == "ANOMALY").sum()

    confidence_values = (
        df["AI Confidence"]
        .str.replace("%", "", regex=False)
        .astype(float)
    )

    average_confidence = confidence_values.mean()

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total Packets", total_packets)

    with col2:
        st.metric("Normal Packets", normal_packets)

    with col3:
        st.metric("Anomalies Detected", anomaly_packets)

    with col4:
        st.metric("Average AI Confidence", f"{average_confidence:.2f}%")

    with col5:
        st.metric("Capture Sessions", st.session_state.capture_count)

    # Threat Level
    if anomaly_packets == 0:
        threat_level = "🟢 LOW"
    elif anomaly_packets <= 2:
        threat_level = "🟠 MEDIUM"
    else:
        threat_level = "🔴 HIGH"

    st.metric("Threat Level", threat_level)

    if threat_level == "🟢 LOW":
        st.success("🟢 SYSTEM STATUS: LOW RISK")
    elif threat_level == "🟠 MEDIUM":
        st.warning("🟠 SYSTEM STATUS: MEDIUM RISK")
    else:
        st.error("🔴 SYSTEM STATUS: HIGH RISK")

    st.subheader("🧠 AI Threat Summary")

    if anomaly_packets > 0:
        st.error(
            f"⚠️ Threat detected! {anomaly_packets} anomalous packet(s) found."
        )
    else:
        st.success(
            "✅ No network anomalies detected in the captured traffic."
        )

    st.subheader("🤖 AI Classification Distribution")

    classification_counts = df["AI Classification"].value_counts()

    st.bar_chart(classification_counts)

    st.subheader("📊 AI Classification Breakdown")

    normal_percentage = (normal_packets / total_packets) * 100
    anomaly_percentage = (anomaly_packets / total_packets) * 100

    col1, col2 = st.columns(2)

    with col1:
        st.metric(
            "🟢 Normal Traffic",
            f"{normal_percentage:.1f}%"
        )
        st.progress(normal_percentage / 100)

    with col2:
        st.metric(
            "🔴 Anomalous Traffic",
            f"{anomaly_percentage:.1f}%"
        )
        st.progress(anomaly_percentage / 100)

    st.subheader("Protocol Distribution")

    protocol_counts = df["Protocol"].value_counts()

    st.bar_chart(protocol_counts)

    st.subheader("📋 Capture Session History")

    if st.session_state.capture_history:
        history_df = pd.DataFrame(st.session_state.capture_history)
        st.dataframe(history_df, width="stretch")

    st.subheader("📦 Packet Size Analysis")

    average_packet_size = df["Packet Size"].mean()
    minimum_packet_size = df["Packet Size"].min()
    maximum_packet_size = df["Packet Size"].max()

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Average Packet Size", f"{average_packet_size:.2f} bytes")

    with col2:
        st.metric("Minimum Packet Size", f"{minimum_packet_size} bytes")

    with col3:
        st.metric("Maximum Packet Size", f"{maximum_packet_size} bytes")

    st.subheader("📈 Packet Size Distribution")

    st.line_chart(df["Packet Size"])

else:
    st.info(
        "No packets captured yet. Click 'Start Network Capture' to begin."
    )
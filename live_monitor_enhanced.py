import streamlit as st
import pandas as pd
import joblib
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
from scapy.config import conf
from datetime import datetime

conf.use_pcap = True

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
st.write("Capture network packets and analyze network traffic using AI.")

# Session state
if "packets" not in st.session_state:
    st.session_state.packets = []

if "capture_count" not in st.session_state:
    st.session_state.capture_count = 0

if "capture_history" not in st.session_state:
    st.session_state.capture_history = []


def get_service(packet):
    """Identify a basic network service from the packet."""

    if packet.haslayer(TCP):
        tcp = packet[TCP]

        ports = [tcp.sport, tcp.dport]

        if 80 in ports:
            return "http"
        if 443 in ports:
            return "http_443"
        if 22 in ports:
            return "ssh"
        if 21 in ports:
            return "ftp"
        if 25 in ports:
            return "smtp"
        if 23 in ports:
            return "telnet"

    if packet.haslayer(UDP):
        udp = packet[UDP]

        ports = [udp.sport, udp.dport]

        if 53 in ports:
            return "domain_u"

        if 123 in ports:
            return "ntp_u"

    return "other"


def get_flag(packet):
    """Determine a basic TCP connection flag."""

    if packet.haslayer(TCP):
        tcp = packet[TCP]

        flags = str(tcp.flags)

        if "S" in flags and "A" not in flags:
            return "S0"

        if "R" in flags:
            return "REJ"

        if "A" in flags:
            return "SF"

        return "SF"

    return "SF"


def process_packet(packet):

    # Accept IPv4 and IPv6 packets
    if packet.haslayer(IP):
        ip_layer = packet[IP]

    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]

    else:
        return

    # Determine protocol
    if packet.haslayer(TCP):
        protocol = "TCP"

    elif packet.haslayer(UDP):
        protocol = "UDP"

    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    else:
        protocol = "Other"

    # Extract basic packet information
    packet_size = len(packet)
    service = get_service(packet)
    flag = get_flag(packet)

    # Basic traffic statistics
    current_packets = st.session_state.packets

    count = len(current_packets) + 1

    same_service_count = 0
    different_service_count = 0

    for previous in current_packets:
        if previous["Service"] == service:
            same_service_count += 1
        else:
            different_service_count += 1

    total_previous = same_service_count + different_service_count

    if total_previous > 0:
        same_srv_rate = same_service_count / total_previous
        diff_srv_rate = different_service_count / total_previous
    else:
        same_srv_rate = 1.0
        diff_srv_rate = 0.0

    # Destination host service statistics
    destination_ip = ip_layer.dst

    destination_matches = [
        p for p in current_packets
        if p["Destination IP"] == destination_ip
    ]

    dst_host_srv_count = len(destination_matches) + 1

    if destination_matches:
        same_host_service = sum(
            1 for p in destination_matches
            if p["Service"] == service
        )

        dst_host_same_srv_rate = (
            same_host_service / len(destination_matches)
        )
    else:
        dst_host_same_srv_rate = 1.0

    # Source port relationship
    source_port = None

    if packet.haslayer(TCP):
        source_port = packet[TCP].sport

    elif packet.haslayer(UDP):
        source_port = packet[UDP].sport

    if source_port is not None and destination_matches:

        same_source_port = sum(
            1 for p in destination_matches
            if p.get("Source Port") == source_port
        )

        dst_host_same_src_port_rate = (
            same_source_port / len(destination_matches)
        )

    else:
        dst_host_same_src_port_rate = 0.0

    # Bytes
    src_bytes = packet_size
    dst_bytes = 0

    # Prepare AI input
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
            input_data[feature] = label_encoders[feature].transform(
                input_data[feature].astype(str)
            )

        # Scale input
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

    # Source port
    if packet.haslayer(TCP):
        source_port_value = packet[TCP].sport
    elif packet.haslayer(UDP):
        source_port_value = packet[UDP].sport
    else:
        source_port_value = None

    packet_info = {
        "Time": datetime.now().strftime("%H:%M:%S"),
        "Source IP": ip_layer.src,
        "Destination IP": ip_layer.dst,
        "Protocol": protocol,
        "Service": service,
        "Source Port": source_port_value,
        "Packet Size": packet_size,
        "AI Classification": classification,
        "AI Confidence": f"{confidence:.2f}%"
    }

    st.session_state.packets.append(packet_info)


# Packet capture control
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
        f"Last capture completed at "
        f"{datetime.now().strftime('%H:%M:%S')}"
    )

    st.caption(
        f"📦 Packets captured: {len(st.session_state.packets)}"
    )


if st.button("🗑️ Clear Results"):

    st.session_state.packets = []

    st.success("Results cleared.")


# Dashboard
if st.session_state.packets:

    df = pd.DataFrame(st.session_state.packets)

    st.subheader("📡 Captured Network Traffic")

    st.dataframe(
        df,
        use_container_width=True
    )

    # Download report
    st.download_button(
        label="📥 Download Traffic Report",
        data=df.to_csv(index=False),
        file_name="network_traffic_report.csv",
        mime="text/csv"
    )

    # AI metrics
    total_packets = len(df)

    normal_packets = (
        df["AI Classification"] == "NORMAL"
    ).sum()

    anomaly_packets = (
        df["AI Classification"] == "ANOMALY"
    ).sum()

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
        st.metric(
            "Average AI Confidence",
            f"{average_confidence:.2f}%"
        )

    with col5:
        st.metric(
            "Capture Sessions",
            st.session_state.capture_count
        )

    # Threat level
    if anomaly_packets == 0:
        threat_level = "🟢 LOW"

    elif anomaly_packets <= 2:
        threat_level = "🟠 MEDIUM"

    else:
        threat_level = "🔴 HIGH"

    st.metric(
        "Threat Level",
        threat_level
    )

    if threat_level == "🟢 LOW":

        st.success(
            "🟢 SYSTEM STATUS: LOW RISK"
        )

    elif threat_level == "🟠 MEDIUM":

        st.warning(
            "🟠 SYSTEM STATUS: MEDIUM RISK"
        )

    else:

        st.error(
            "🔴 SYSTEM STATUS: HIGH RISK"
        )

    # AI threat summary
    st.subheader("🧠 AI Threat Summary")

    if anomaly_packets > 0:

        st.error(
            f"⚠️ Threat detected! "
            f"{anomaly_packets} anomalous packet(s) found."
        )

    else:

        st.success(
            "✅ No network anomalies detected "
            "in the captured traffic."
        )

    # Classification distribution
    st.subheader("🤖 AI Classification Distribution")

    classification_counts = (
        df["AI Classification"].value_counts()
    )

    st.bar_chart(classification_counts)

    # Classification breakdown
    st.subheader("📊 AI Classification Breakdown")

    normal_percentage = (
        normal_packets / total_packets
    ) * 100

    anomaly_percentage = (
        anomaly_packets / total_packets
    ) * 100

    col1, col2 = st.columns(2)

    with col1:

        st.metric(
            "🟢 Normal Traffic",
            f"{normal_percentage:.1f}%"
        )

        st.progress(
            normal_percentage / 100
        )

    with col2:

        st.metric(
            "🔴 Anomalous Traffic",
            f"{anomaly_percentage:.1f}%"
        )

        st.progress(
            anomaly_percentage / 100
        )

    # Protocol distribution
    st.subheader("🌐 Protocol Distribution")

    protocol_counts = df["Protocol"].value_counts()

    st.bar_chart(protocol_counts)

    # Service distribution
    st.subheader("🔌 Service Distribution")

    service_counts = df["Service"].value_counts()

    st.bar_chart(service_counts)

    # Session history
    st.subheader("📋 Capture Session History")

    if st.session_state.capture_history:

        history_df = pd.DataFrame(
            st.session_state.capture_history
        )

        st.dataframe(
            history_df,
            use_container_width=True
        )

    # Packet size
    st.subheader("📦 Packet Size Analysis")

    average_packet_size = (
        df["Packet Size"].mean()
    )

    minimum_packet_size = (
        df["Packet Size"].min()
    )

    maximum_packet_size = (
        df["Packet Size"].max()
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Average Packet Size",
            f"{average_packet_size:.2f} bytes"
        )

    with col2:

        st.metric(
            "Minimum Packet Size",
            f"{minimum_packet_size} bytes"
        )

    with col3:

        st.metric(
            "Maximum Packet Size",
            f"{maximum_packet_size} bytes"
        )

    st.subheader("📈 Packet Size Distribution")

    st.line_chart(
        df["Packet Size"]
    )

else:

    st.info(
        "No packets captured yet. "
        "Click 'Start Network Capture' to begin."
    )
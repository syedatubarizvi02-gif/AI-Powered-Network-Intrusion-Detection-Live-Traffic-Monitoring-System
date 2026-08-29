import streamlit as st
import pandas as pd
import joblib
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
from datetime import datetime
from scapy.config import conf

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="AI Network Security System",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# LOAD AI MODEL
# ============================================================

try:
    model = joblib.load("rf.sav")
    scaler = joblib.load("scaler.sav")
    label_encoders = joblib.load("label_encoders.sav")

except Exception as e:
    st.error(f"Unable to load AI model files: {e}")
    st.stop()

# ============================================================
# FEATURES USED BY THE AI MODEL
# ============================================================

features = [
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "count",
    "same_srv_rate",
    "diff_srv_rate",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_same_src_port_rate"
]

# ============================================================
# SESSION STATE
# ============================================================

if "packets" not in st.session_state:
    st.session_state.packets = []

if "capture_count" not in st.session_state:
    st.session_state.capture_count = 0

# ============================================================
# SIDEBAR NAVIGATION
# ============================================================

st.sidebar.title("🛡️ AI Network Security")

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Home",
        "🧠 AI Intrusion Detection",
        "📡 Live Network Monitoring",
        "📊 Traffic Analysis",
        "ℹ️ About Project"
    ]
)

# ============================================================
# HOME
# ============================================================

if page == "🏠 Home":

    st.title("🛡️ AI-Powered Network Security System")

    st.markdown(
        """
        ### Welcome

        This system combines **Machine Learning-based Intrusion Detection**
        with **Live Network Traffic Monitoring**.

        The application uses a trained **Random Forest machine learning model**
        to classify network traffic as:

        - 🟢 **NORMAL**
        - 🔴 **ANOMALY**
        """
    )

    st.divider()

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("AI Engine", "Random Forest")

    with col2:
        st.metric("Detection Type", "Network Intrusion")

    with col3:
        st.metric("Monitoring", "Live Traffic")

    st.divider()

    st.subheader("System Workflow")

    st.markdown(
        """
        **Network Traffic**
        ↓  
        **Feature Extraction**
        ↓  
        **AI / Machine Learning Model**
        ↓  
        **Threat Classification**
        ↓  
        **Security Dashboard**
        """
    )

# ============================================================
# AI INTRUSION DETECTION
# ============================================================

elif page == "🧠 AI Intrusion Detection":

    st.title("🧠 AI Intrusion Detection")

    st.write(
        "Enter network traffic characteristics and let the trained "
        "machine learning model classify the traffic."
    )

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("Service & Connection")

        service_options = list(label_encoders["service"].classes_)

        service = st.selectbox(
            "Service",
            service_options,
            index=(
                service_options.index("http")
                if "http" in service_options
                else 0
            )
        )

        flag_options = list(label_encoders["flag"].classes_)

        flag = st.selectbox(
            "Flag",
            flag_options,
            index=(
                flag_options.index("SF")
                if "SF" in flag_options
                else 0
            )
        )

        src_bytes = st.number_input(
            "Source Bytes",
            min_value=0,
            max_value=381709090,
            value=0
        )

        dst_bytes = st.number_input(
            "Destination Bytes",
            min_value=0,
            max_value=5151385,
            value=0
        )

        count = st.number_input(
            "Count",
            min_value=1,
            max_value=511,
            value=1
        )

        dst_host_srv_count = st.number_input(
            "Destination Host Service Count",
            min_value=0,
            max_value=255,
            value=255
        )

    with col2:

        st.subheader("Traffic Statistics")

        same_srv_rate = st.slider(
            "Same Service Rate",
            0.0,
            1.0,
            1.0,
            0.01
        )

        diff_srv_rate = st.slider(
            "Different Service Rate",
            0.0,
            1.0,
            0.0,
            0.01
        )

        dst_host_same_srv_rate = st.slider(
            "Destination Host Same Service Rate",
            0.0,
            1.0,
            1.0,
            0.01
        )

        dst_host_same_src_port_rate = st.slider(
            "Destination Host Same Source Port Rate",
            0.0,
            1.0,
            0.0,
            0.01
        )

    st.divider()

    if st.button(
        "🔍 Analyze Network Traffic",
        type="primary",
        use_container_width=True
    ):

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
            "dst_host_same_src_port_rate":
                dst_host_same_src_port_rate
        }])

        try:

            for feature in ["service", "flag"]:
                input_data[feature] = label_encoders[
                    feature
                ].transform(
                    input_data[feature].astype(str)
                )

            input_scaled = scaler.transform(input_data)

            prediction = model.predict(input_scaled)[0]
            probability = model.predict_proba(input_scaled)[0]

            if prediction == 0:

                confidence = probability[0] * 100

                st.error(
                    f"🚨 THREAT DETECTED — ANOMALY\n\n"
                    f"Confidence: {confidence:.2f}%"
                )

            else:

                confidence = probability[1] * 100

                st.success(
                    f"🟢 TRAFFIC NORMAL\n\n"
                    f"Confidence: {confidence:.2f}%"
                )

            st.subheader("Probability Breakdown")

            col1, col2 = st.columns(2)

            with col1:
                st.metric(
                    "Anomaly Probability",
                    f"{probability[0] * 100:.2f}%"
                )

            with col2:
                st.metric(
                    "Normal Probability",
                    f"{probability[1] * 100:.2f}%"
                )

        except Exception as e:

            st.error(f"Prediction error: {e}")

# ============================================================
# LIVE NETWORK MONITORING
# ============================================================

elif page == "📡 Live Network Monitoring":

    st.title("📡 Live Network Traffic Monitor")

    st.write(
        "Capture network packets and analyze them using the same "
        "AI intrusion detection model."
    )

    packet_count = st.number_input(
        "Number of packets to capture",
        min_value=1,
        max_value=100,
        value=10
    )

    def get_service(packet):

        if packet.haslayer(TCP):

            ports = [
                packet[TCP].sport,
                packet[TCP].dport
            ]

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

            ports = [
                packet[UDP].sport,
                packet[UDP].dport
            ]

            if 53 in ports:
                return "domain_u"

            if 123 in ports:
                return "ntp_u"

        return "other"

    def get_flag(packet):

        if packet.haslayer(TCP):

            flags = str(packet[TCP].flags)

            if "S" in flags and "A" not in flags:
                return "S0"

            if "R" in flags:
                return "REJ"

            if "A" in flags:
                return "SF"

        return "SF"

    def process_packet(packet):

        if packet.haslayer(IP):

            ip_layer = packet[IP]

        elif packet.haslayer(IPv6):

            ip_layer = packet[IPv6]

        else:

            return

        if packet.haslayer(TCP):

            protocol = "TCP"

        elif packet.haslayer(UDP):

            protocol = "UDP"

        elif packet.haslayer(ICMP):

            protocol = "ICMP"

        else:

            protocol = "Other"

        packet_size = len(packet)

        service = get_service(packet)

        flag = get_flag(packet)

        previous_packets = st.session_state.packets

        count = len(previous_packets) + 1

        same_service_count = sum(
            1
            for p in previous_packets
            if p["Service"] == service
        )

        different_service_count = sum(
            1
            for p in previous_packets
            if p["Service"] != service
        )

        total_previous = (
            same_service_count +
            different_service_count
        )

        if total_previous:

            same_srv_rate = (
                same_service_count /
                total_previous
            )

            diff_srv_rate = (
                different_service_count /
                total_previous
            )

        else:

            same_srv_rate = 1.0
            diff_srv_rate = 0.0

        destination_ip = ip_layer.dst

        destination_matches = [
            p
            for p in previous_packets
            if p["Destination IP"] == destination_ip
        ]

        dst_host_srv_count = (
            len(destination_matches) + 1
        )

        if destination_matches:

            same_host_service = sum(
                1
                for p in destination_matches
                if p["Service"] == service
            )

            dst_host_same_srv_rate = (
                same_host_service /
                len(destination_matches)
            )

        else:

            dst_host_same_srv_rate = 1.0

        if packet.haslayer(TCP):

            source_port = packet[TCP].sport

        elif packet.haslayer(UDP):

            source_port = packet[UDP].sport

        else:

            source_port = None

        if source_port is not None and destination_matches:

            same_source_port = sum(
                1
                for p in destination_matches
                if p.get("Source Port") == source_port
            )

            dst_host_same_src_port_rate = (
                same_source_port /
                len(destination_matches)
            )

        else:

            dst_host_same_src_port_rate = 0.0

        input_data = pd.DataFrame([{
            "service": service,
            "flag": flag,
            "src_bytes": packet_size,
            "dst_bytes": 0,
            "count": count,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "dst_host_srv_count": dst_host_srv_count,
            "dst_host_same_srv_rate":
                dst_host_same_srv_rate,
            "dst_host_same_src_port_rate":
                dst_host_same_src_port_rate
        }])

        try:

            for feature in ["service", "flag"]:

                input_data[feature] = label_encoders[
                    feature
                ].transform(
                    input_data[feature].astype(str)
                )

            input_scaled = scaler.transform(input_data)

            prediction = model.predict(
                input_scaled
            )[0]

            probability = model.predict_proba(
                input_scaled
            )[0]

            if prediction == 0:

                classification = "ANOMALY"
                confidence = probability[0] * 100

            else:

                classification = "NORMAL"
                confidence = probability[1] * 100

        except Exception:

            classification = "UNKNOWN"
            confidence = 0

        if packet.haslayer(TCP):

            source_port_value = packet[TCP].sport

        elif packet.haslayer(UDP):

            source_port_value = packet[UDP].sport

        else:

            source_port_value = None

        packet_info = {
            "Time":
                datetime.now().strftime("%H:%M:%S"),

            "Source IP":
                ip_layer.src,

            "Destination IP":
                ip_layer.dst,

            "Protocol":
                protocol,

            "Service":
                service,

            "Source Port":
                source_port_value,

            "Packet Size":
                packet_size,

            "AI Classification":
                classification,

            "AI Confidence":
                f"{confidence:.2f}%"
        }

        st.session_state.packets.append(
            packet_info
        )

    col1, col2 = st.columns(2)

    with col1:

        if st.button(
            "▶️ Start Network Capture",
            type="primary",
            use_container_width=True
        ):

            st.info("Capturing network traffic...")

            sniff(
                count=int(packet_count),
                prn=process_packet,
                store=False
            )

            st.session_state.capture_count += 1

            st.success(
                "✅ Packet capture completed!"
            )

    with col2:

        if st.button(
            "🗑️ Clear Results",
            use_container_width=True
        ):

            st.session_state.packets = []

            st.success(
                "Results cleared."
            )

    if st.session_state.packets:

        df = pd.DataFrame(
            st.session_state.packets
        )

        st.subheader(
            "📡 Captured Network Traffic"
        )

        st.dataframe(
            df,
            use_container_width=True
        )

        st.download_button(
            "📥 Download Traffic Report",
            df.to_csv(index=False),
            "network_traffic_report.csv",
            "text/csv"
        )

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

        average_confidence = (
            confidence_values.mean()
        )

        st.divider()

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Total Packets",
                total_packets
            )

        with col2:
            st.metric(
                "Normal Packets",
                normal_packets
            )

        with col3:
            st.metric(
                "Anomalies Detected",
                anomaly_packets
            )

        with col4:
            st.metric(
                "Average AI Confidence",
                f"{average_confidence:.2f}%"
            )

        if anomaly_packets == 0:

            st.success(
                "🟢 SYSTEM STATUS: LOW RISK"
            )

        elif anomaly_packets <= 2:

            st.warning(
                "🟠 SYSTEM STATUS: MEDIUM RISK"
            )

        else:

            st.error(
                "🔴 SYSTEM STATUS: HIGH RISK"
            )

        st.subheader(
            "🤖 AI Classification Distribution"
        )

        st.bar_chart(
            df["AI Classification"].value_counts()
        )

        st.subheader(
            "🌐 Protocol Distribution"
        )

        st.bar_chart(
            df["Protocol"].value_counts()
        )

        st.subheader(
            "🔌 Service Distribution"
        )

        st.bar_chart(
            df["Service"].value_counts()
        )

        st.subheader(
            "📦 Packet Size Analysis"
        )

        col1, col2, col3 = st.columns(3)

        with col1:

            st.metric(
                "Average",
                f"{df['Packet Size'].mean():.2f} bytes"
            )

        with col2:

            st.metric(
                "Minimum",
                f"{df['Packet Size'].min()} bytes"
            )

        with col3:

            st.metric(
                "Maximum",
                f"{df['Packet Size'].max()} bytes"
            )

    else:

        st.info(
            "No packets captured yet. "
            "Click 'Start Network Capture' to begin."
        )

# ============================================================
# TRAFFIC ANALYSIS
# ============================================================

elif page == "📊 Traffic Analysis":

    st.title("📊 Traffic Analysis")

    if not st.session_state.packets:

        st.info(
            "No captured traffic is available yet. "
            "Go to Live Network Monitoring and capture packets first."
        )

    else:

        df = pd.DataFrame(
            st.session_state.packets
        )

        st.subheader("Traffic Overview")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "Total Packets",
                len(df)
            )

        with col2:
            st.metric(
                "Normal",
                (
                    df["AI Classification"] ==
                    "NORMAL"
                ).sum()
            )

        with col3:
            st.metric(
                "Anomalies",
                (
                    df["AI Classification"] ==
                    "ANOMALY"
                ).sum()
            )

        st.subheader(
            "Protocol Distribution"
        )

        st.bar_chart(
            df["Protocol"].value_counts()
        )

        st.subheader(
            "Packet Size Distribution"
        )

        st.line_chart(
            df["Packet Size"]
        )

# ============================================================
# ABOUT PROJECT
# ============================================================

elif page == "ℹ️ About Project":

    st.title("ℹ️ About the Project")

    st.markdown(
        """
        ## AI-Powered Network Intrusion Detection
        and Live Traffic Monitoring System

        This project combines **Artificial Intelligence,
        Machine Learning and network traffic monitoring**
        to identify potentially malicious network activity.

        ### Key Components

        - 🤖 Random Forest intrusion detection model
        - 📡 Live packet capture using Scapy
        - 🔍 Network traffic feature extraction
        - 🚨 Anomaly detection
        - 📊 Interactive security dashboard
        - 📥 Traffic report export

        ### AI Detection

        The machine learning model analyzes selected
        network traffic features and produces a classification
        with a confidence score.

        ### Live Monitoring

        The live monitoring component captures network packets,
        extracts relevant traffic characteristics and passes
        them through the same trained AI model.

        ### Objective

        The objective is to provide an interactive prototype
        for monitoring network traffic and identifying
        potentially anomalous activity.
        """
    )
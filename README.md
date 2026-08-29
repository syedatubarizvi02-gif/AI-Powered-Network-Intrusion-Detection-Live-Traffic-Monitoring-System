*# 🛡️ AI-Powered Live Network Intrusion Detection System*



*An AI-powered cybersecurity application that captures live network traffic, extracts network-level features, and uses a trained \*\*Random Forest machine-learning model\*\* to classify traffic as \*\*NORMAL\*\* or \*\*ANOMALY\*\*.*



*The project combines \*\*real-time packet capture, machine learning, statistical traffic analysis, and an interactive Streamlit dashboard\*\* into a single network security monitoring application.*



*---*



*## 🚀 Project Overview*



*Traditional network monitoring tools can show packets and connection information, but identifying potentially malicious traffic requires additional analysis.*



*This project adds a machine-learning layer to network monitoring.*



*The system:*



*1. Captures live network packets using \*\*Scapy\*\**

*2. Identifies IP traffic and network protocols*

*3. Extracts relevant traffic characteristics*

*4. Converts the captured information into features compatible with the trained ML pipeline*

*5. Encodes categorical features*

*6. Applies feature scaling*

*7. Sends the processed data to a \*\*Random Forest classifier\*\**

*8. Calculates prediction probabilities*

*9. Classifies traffic as \*\*NORMAL\*\* or \*\*ANOMALY\*\**

*10. Displays the results through an interactive \*\*Streamlit dashboard\*\**



*---*



*## ✨ Key Features*



*### 📡 Live Network Packet Capture*



*Captures live network traffic directly from the system using Scapy.*



*### 🤖 Machine Learning Detection*



*Uses a trained Random Forest classifier to identify potentially anomalous network traffic.*



*### 🧠 AI Confidence*



*Displays prediction probabilities and AI confidence for the classification.*



*### 🚨 Threat-Level Assessment*



*The dashboard summarizes detected anomalies into:*



*\* 🟢 LOW*

*\* 🟠 MEDIUM*

*\* 🔴 HIGH*



*### 🌐 Protocol Analysis*



*Displays the distribution of captured network protocols such as:*



*\* TCP*

*\* UDP*

*\* ICMP*

*\* Other*



*### 🔌 Service Analysis*



*Displays detected network services associated with captured traffic.*



*### 📊 Traffic Statistics*



*Provides:*



*\* Total packets*

*\* Normal packets*

*\* Anomalous packets*

*\* Average AI confidence*

*\* Capture sessions*

*\* Average packet size*

*\* Minimum packet size*

*\* Maximum packet size*



*### 📈 Visual Analytics*



*The dashboard provides charts for:*



*\* AI classification distribution*

*\* Protocol distribution*

*\* Service distribution*

*\* Packet-size distribution*



*### 📋 Capture History*



*Maintains information about previous packet-capture sessions during the application session.*



*### 📥 Traffic Report*



*Captured traffic can be exported as a CSV report.*



*---*



*## 🏗️ System Architecture*



*```text*

&#x20;                *┌─────────────────────┐*

&#x20;                *│   Network Traffic   │*

&#x20;                *└──────────┬──────────┘*

&#x20;                           *│*

&#x20;                           *▼*

&#x20;                *┌─────────────────────┐*

&#x20;                *│   Scapy Packet      │*

&#x20;                *│      Capture        │*

&#x20;                *└──────────┬──────────┘*

&#x20;                           *│*

&#x20;                           *▼*

&#x20;                *┌─────────────────────┐*

&#x20;                *│ Feature Extraction  │*

&#x20;                *│                     │*

&#x20;                *│ IP / Protocol /     │*

&#x20;                *│ Service / Packet    │*

&#x20;                *│ Statistics          │*

&#x20;                *└──────────┬──────────┘*

&#x20;                           *│*

&#x20;                           *▼*

&#x20;                *┌─────────────────────┐*

&#x20;                *│ Preprocessing       │*

&#x20;                *│                     │*

&#x20;                *│ Label Encoding      │*

&#x20;                *│ Standard Scaling    │*

&#x20;                *└──────────┬──────────┘*

&#x20;                           *│*

&#x20;                           *▼*

&#x20;                *┌─────────────────────┐*

&#x20;                *│ Random Forest       │*

&#x20;                *│ Classifier          │*

&#x20;                *└──────────┬──────────┘*

&#x20;                           *│*

&#x20;                   *┌───────┴───────┐*

&#x20;                   *▼               ▼*

&#x20;             *┌──────────┐    ┌──────────┐*

&#x20;             *│ NORMAL   │    │ ANOMALY  │*

&#x20;             *└────┬─────┘    └────┬─────┘*

&#x20;                  *│               │*

&#x20;                  *└───────┬───────┘*

&#x20;                          *▼*

&#x20;                *┌─────────────────────┐*

&#x20;                *│ Streamlit Security  │*

&#x20;                *│     Dashboard       │*

&#x20;                *└─────────────────────┘*

*```*



*---*



*## 🧠 Machine Learning Pipeline*



*The trained model uses selected network traffic features.*



*### Input Features*



*| Feature                       | Description                                                         |*

*| ----------------------------- | ------------------------------------------------------------------- |*

*| `service`                     | Network service type                                                |*

*| `flag`                        | Connection status flag                                              |*

*| `src\_bytes`                   | Bytes transferred from source                                       |*

*| `dst\_bytes`                   | Bytes transferred to destination                                    |*

*| `count`                       | Number of connections to the same host                              |*

*| `same\_srv\_rate`               | Rate of connections using the same service                          |*

*| `diff\_srv\_rate`               | Rate of connections using different services                        |*

*| `dst\_host\_srv\_count`          | Number of connections to the same destination host and service      |*

*| `dst\_host\_same\_srv\_rate`      | Rate of connections to the same destination host and service        |*

*| `dst\_host\_same\_src\_port\_rate` | Rate of connections using the same destination host and source port |*



*### Preprocessing*



*Categorical features such as `service` and `flag` are processed using saved label encoders.*



*Numerical features are passed through the saved `StandardScaler`.*



*The processed feature vector is then supplied to the trained Random Forest model.*



*---*



*## 🌲 Machine Learning Model*



*The project uses a \*\*Random Forest Classifier\*\*.*



*Random Forest is an ensemble-learning algorithm that combines multiple decision trees to produce a classification result.*



*The saved model is stored in:*



*```text*

*rf.sav*

*```*



*The preprocessing components are stored separately:*



*```text*

*scaler.sav*

*label\_encoders.sav*

*target\_encoder.sav*

*```*



*The model was trained using network intrusion-detection data based on the \*\*NSL-KDD dataset\*\*.*



*---*



*## 📡 Live Monitoring*



*The enhanced live-monitoring application is implemented in:*



*```text*

*live\_monitor\_enhanced.py*

*```*



*It uses Scapy to capture packets and extracts information such as:*



*\* Source IP*

*\* Destination IP*

*\* Protocol*

*\* Packet size*

*\* Network service*

*\* AI classification*

*\* AI confidence*



*The captured information is displayed in the Streamlit dashboard.*



*---*



*## 📊 Dashboard*



*The dashboard provides a consolidated view of the captured network activity.*



*### Main Metrics*



*```text*

*Total Packets*

*Normal Packets*

*Anomalies Detected*

*Average AI Confidence*

*Capture Sessions*

*Threat Level*

*```*



*### Security Status*



*The application automatically presents a system-risk status based on the number of detected anomalous packets.*



*```text*

*🟢 LOW RISK*

*🟠 MEDIUM RISK*

*🔴 HIGH RISK*

*```*



*---*



*## 🧪 Example Detection*



*The project can distinguish between different traffic patterns.*



*### Normal Traffic Example*



*```text*

*Service: http*

*Flag: SF*

*Source Bytes: 200*

*Destination Bytes: 5000*

*Count: 5*

*Same Service Rate: 1.0*

*Different Service Rate: 0.0*

*Destination Host Service Count: 255*

*Destination Host Same Service Rate: 1.0*

*Destination Host Same Source Port Rate: 0.0*

*```*



*### Potential Anomaly Example*



*```text*

*Service: private*

*Flag: S0*

*Source Bytes: 0*

*Destination Bytes: 0*

*Count: 100*

*Same Service Rate: 0.05*

*Different Service Rate: 0.95*

*Destination Host Service Count: 10*

*Destination Host Same Service Rate: 0.1*

*Destination Host Same Source Port Rate: 0.9*

*```*



*The anomaly example was successfully classified by the trained model with a high anomaly probability during testing.*



*---*



*## 📁 Project Structure*



*```text*

*streamlit-ml-intrusion-detection-system-main/*

*│*

*├── dataset/*

*│*

*├── files/*

*│*

*├── screenshots/*

*│   ├── 01\_dashboard\_metrics.png*

*│   ├── 02\_packet\_table.png*

*│   ├── 03\_ai\_analysis.png*

*│   ├── 04\_network\_analysis.png*

*│   └── 05\_packet\_analysis.png*

*│*

*├── docs/*

*│*

*├── live\_monitor.py*

*├── live\_monitor\_enhanced.py*

*├── live\_monitor\_backup.py*

*├── live\_monitor\_working\_backup.py*

*│*

*├── main.py*

*├── main\_backup.py*

*│*

*├── train\_model.py*

*│*

*├── rf.sav*

*├── scaler.sav*

*├── label\_encoders.sav*

*├── target\_encoder.sav*

*│*

*├── requirements.txt*

*├── LICENSE*

*└── README.md*

*```*



*---*



*## ⚙️ Technologies Used*



*### Programming Language*



*\* Python*



*### Machine Learning*



*\* Scikit-learn*

*\* Random Forest*

*\* StandardScaler*

*\* Label Encoding*



*### Network Security / Packet Analysis*



*\* Scapy*



*### Data Processing*



*\* Pandas*

*\* NumPy*



*### Web Application*



*\* Streamlit*



*### Model Persistence*



*\* Joblib*



*---*



*## 🛠️ Installation*



*### 1. Navigate to the project*



*```bash*

*cd streamlit-ml-intrusion-detection-system-main*

*```*



*### 2. Install dependencies*



*```bash*

*pip install -r requirements.txt*

*```*



*### 3. Run the enhanced live monitor*



*```bash*

*python -m streamlit run live\_monitor\_enhanced.py*

*```*



*The application will provide a local URL similar to:*



*```text*

*http://localhost:8503*

*```*



*Open the URL in a web browser.*



*---*



*## ▶️ Using the Application*



*1. Start the Streamlit application.*

*2. Set the number of packets to capture.*

*3. Click \*\*Start Network Capture\*\*.*

*4. Allow the application to capture network traffic.*

*5. Review the captured packet table.*

*6. Review AI classifications.*

*7. Check anomaly counts and threat level.*

*8. Analyze protocol and service distributions.*

*9. Review packet-size statistics.*

*10. Download the traffic report if required.*



*---*



*## 📸 Project Screenshots*



*The `screenshots/` directory contains demonstrations of the working application, including:*



*\* Live monitoring dashboard*

*\* Captured network traffic*

*\* AI threat analysis*

*\* Network protocol/service analysis*

*\* Packet-size analysis*



*---*



*## ⚠️ Important Project Limitation*



*The live monitor currently derives a \*\*limited set of model-compatible features from individual captured packets\*\* rather than reconstructing the complete flow-level feature set used by the original NSL-KDD training data.*



*Therefore, the live-monitor predictions should be treated as a \*\*demonstration/prototype of ML-assisted network monitoring\*\*, not as a production-grade intrusion-detection system.*



*For a production implementation, flow aggregation, richer feature extraction, packet/connection correlation, model calibration, and evaluation against live network datasets would be required.*



*---*



*## 🔮 Future Improvements*



*Possible future enhancements include:*



*\* Flow-based feature extraction*

*\* More comprehensive packet analysis*

*\* Real-time anomaly alerts*

*\* IP reputation checking*

*\* Attack-category classification*

*\* Historical traffic storage*

*\* Database integration*

*\* Interactive traffic timelines*

*\* Automated incident reports*

*\* Email or notification alerts*

*\* Model retraining using newer datasets*

*\* Performance monitoring and model drift detection*

*\* Deployment on a dedicated monitoring server*



*---*



*## 🎯 Project Objective*



*The primary objective of this project is to demonstrate how \*\*machine learning can be integrated with real-time network traffic monitoring to assist in identifying potentially anomalous activity\*\*.*



*The project combines:*



*\*\*Cybersecurity + Network Monitoring + Machine Learning + Data Analysis + Web Dashboard\*\**



*into one integrated application.*



*---*



*## 📄 License*



*This project is licensed under the MIT License.*



*---*



*## 👩‍💻 Project Status*



*\*\*Status: Working Prototype ✅\*\**



*The application has been tested with live packet capture and successfully displays network traffic statistics and machine-learning classifications through the Streamlit dashboard.*




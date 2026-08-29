*# Technical Documentation*



*## AI-Powered Live Network Intrusion Detection System*



*---*



*## 1. Purpose*



*This project is a machine-learning-assisted network security monitoring application.*



*The system captures live network packets, extracts traffic-related information, processes selected features, and uses a trained Random Forest classifier to classify network traffic as either:*



*\* \*\*NORMAL\*\**

*\* \*\*ANOMALY\*\**



*The results are presented through an interactive Streamlit dashboard.*



*---*



*## 2. Technology Stack*



*| Component            | Technology                             |*

*| -------------------- | -------------------------------------- |*

*| Programming Language | Python                                 |*

*| Web Framework        | Streamlit                              |*

*| Packet Capture       | Scapy                                  |*

*| Machine Learning     | Scikit-learn                           |*

*| ML Algorithm         | Random Forest Classifier               |*

*| Data Processing      | Pandas, NumPy                          |*

*| Model Persistence    | Joblib                                 |*

*| Dataset              | NSL-KDD-based intrusion detection data |*



*---*



*## 3. System Architecture*



*```text*

*Network Interface*

&#x20;      *│*

&#x20;      *▼*

*Live Packet Capture*

&#x20;      *│*

&#x20;      *▼*

*Packet Feature Extraction*

&#x20;      *│*

&#x20;      *▼*

*Feature Preparation*

&#x20;      *│*

&#x20;      *├── Categorical Encoding*

&#x20;      *│*

&#x20;      *└── Numerical Scaling*

&#x20;      *│*

&#x20;      *▼*

*Random Forest Classifier*

&#x20;      *│*

&#x20;      *├───────────────┐*

&#x20;      *▼               ▼*

&#x20;   *NORMAL          ANOMALY*

&#x20;      *│               │*

&#x20;      *└───────┬───────┘*

&#x20;              *▼*

&#x20;      *Streamlit Dashboard*

&#x20;              *│*

&#x20;      *┌───────┼────────┐*

&#x20;      *▼       ▼        ▼*

&#x20;  *Metrics  Charts   Threat Status*

*```*



*---*



*## 4. Live Monitoring Pipeline*



*The enhanced monitoring application is implemented in:*



*```text*

*live\_monitor\_enhanced.py*

*```*



*The monitoring workflow consists of the following stages.*



*### Stage 1 — Packet Capture*



*Scapy is used to capture packets from the available network interface.*



*The user specifies the number of packets to capture through the Streamlit interface.*



*### Stage 2 — Packet Analysis*



*Captured packets are inspected to obtain information such as:*



*\* Source IP address*

*\* Destination IP address*

*\* Protocol*

*\* Packet size*

*\* Network service*

*\* Traffic statistics*



*### Stage 3 — Feature Preparation*



*Relevant information is converted into a feature representation compatible with the trained machine-learning pipeline.*



*Categorical values are encoded using the saved encoders.*



*Numerical values are processed using the saved scaler.*



*### Stage 4 — AI Classification*



*The processed feature vector is passed to the Random Forest classifier.*



*The classifier produces:*



*\* Predicted class*

*\* Class probability*



*### Stage 5 — Dashboard Presentation*



*The Streamlit interface presents the results using metrics, tables, charts, and threat-status indicators.*



*---*



*## 5. Machine Learning Pipeline*



*The trained model uses the following ten features:*



*```text*

*service*

*flag*

*src\_bytes*

*dst\_bytes*

*count*

*same\_srv\_rate*

*diff\_srv\_rate*

*dst\_host\_srv\_count*

*dst\_host\_same\_srv\_rate*

*dst\_host\_same\_src\_port\_rate*

*```*



*### Categorical Features*



*The following features are categorical:*



*```text*

*service*

*flag*

*```*



*They are transformed using the saved label encoders.*



*### Numerical Features*



*The remaining features represent numerical network traffic characteristics.*



*The saved `StandardScaler` is used to normalize the input before classification.*



*---*



*## 6. Model*



*The project uses a:*



*\*\*Random Forest Classifier\*\**



*The trained model is stored in:*



*```text*

*rf.sav*

*```*



*The Random Forest model is an ensemble classifier consisting of multiple decision trees.*



*The final classification is obtained from the ensemble of decision-tree predictions.*



*The model also provides class probabilities through `predict\_proba()`.*



*---*



*## 7. Preprocessing Components*



*### Random Forest Model*



*```text*

*rf.sav*

*```*



*Purpose:*



*Stores the trained Random Forest intrusion-detection classifier.*



*### StandardScaler*



*```text*

*scaler.sav*

*```*



*Purpose:*



*Applies the scaling transformation expected by the trained model.*



*### Label Encoders*



*```text*

*label\_encoders.sav*

*```*



*Purpose:*



*Converts categorical network features into numerical representations.*



*The current application uses encoders for:*



*```text*

*service*

*flag*

*```*



*### Target Encoder*



*```text*

*target\_encoder.sav*

*```*



*Purpose:*



*Stores the encoding used for the target/classification labels during model development.*



*---*



*## 8. Model-Compatible Feature Schema*



*The saved scaler reports the following feature order:*



*```text*

*1. service*

*2. flag*

*3. src\_bytes*

*4. dst\_bytes*

*5. count*

*6. same\_srv\_rate*

*7. diff\_srv\_rate*

*8. dst\_host\_srv\_count*

*9. dst\_host\_same\_srv\_rate*

*10. dst\_host\_same\_src\_port\_rate*

*```*



*Maintaining the correct feature order is important because the trained preprocessing pipeline expects these features in this sequence.*



*---*



*## 9. Classification Logic*



*The classifier returns a predicted class and probability distribution.*



*The application interprets the model output as:*



*```text*

*Prediction = 0 → ANOMALY*

*Prediction = 1 → NORMAL*

*```*



*The dashboard then displays the corresponding classification.*



*For anomalous traffic, the anomaly probability is displayed as the confidence value.*



*For normal traffic, the normal probability is displayed as the confidence value.*



*The probability breakdown displays both values:*



*```text*

*Anomaly Probability*

*Normal Probability*

*```*



*---*



*## 10. Dashboard Components*



*The live monitoring dashboard provides several analytical components.*



*### Total Packets*



*Number of packets captured during the current capture session.*



*### Normal Packets*



*Number of packets classified as normal.*



*### Anomalies Detected*



*Number of packets classified as anomalous.*



*### Average AI Confidence*



*Average classification confidence across the captured packets.*



*### Capture Sessions*



*Number of packet-capture sessions performed during the application session.*



*### Threat Level*



*A summarized security indicator based on the observed classifications.*



*---*



*## 11. Traffic Analysis*



*The dashboard provides additional traffic analysis.*



*### Protocol Distribution*



*Shows the distribution of protocols observed during packet capture.*



*Examples include:*



*```text*

*TCP*

*UDP*

*ICMP*

*```*



*### Service Distribution*



*Shows the network services identified from the captured traffic.*



*### Packet Size Analysis*



*The application calculates:*



*\* Average packet size*

*\* Minimum packet size*

*\* Maximum packet size*



*### Packet Size Distribution*



*A graphical representation of packet-size observations is provided for the captured traffic.*



*---*



*## 12. Capture Session History*



*The application maintains capture-session information so that multiple monitoring sessions can be reviewed during the active application session.*



*This provides a basic historical view of:*



*\* Capture sessions*

*\* Packet counts*

*\* Normal classifications*

*\* Anomalous classifications*

*\* Average confidence*



*---*



*## 13. Example Traffic Testing*



*The application includes example traffic patterns for testing the classification interface.*



*### Normal Traffic*



*Example:*



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



*### Potential Anomaly*



*Example:*



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



*The potential-anomaly example was observed to produce a high anomaly probability during application testing.*



*---*



*## 14. Testing Performed*



*The project was tested at multiple levels.*



*### Model Loading Test*



*The saved Random Forest model was successfully loaded using Joblib.*



*The saved scaler and label encoders were also successfully loaded.*



*### Manual Classification Test*



*The Streamlit classification interface was tested with both normal and potential-anomaly example values.*



*The application produced:*



*```text*

*NORMAL*

*```*



*for normal traffic input and:*



*```text*

*ANOMALY*

*```*



*for the potential-anomaly input.*



*### Live Packet Capture Test*



*The enhanced application successfully captured live network packets.*



*A test capture produced:*



*```text*

*Packets captured: 10*

*Normal packets: 10*

*Anomalies detected: 0*

*Average AI confidence: 84.40%*

*```*



*The dashboard also successfully displayed protocol distribution, service distribution, packet-size statistics, and classification information.*



*---*



*## 15. Project Files*



*```text*

*live\_monitor\_enhanced.py*

*```*



*Enhanced live network monitoring application.*



*```text*

*live\_monitor.py*

*```*



*Original live monitoring implementation.*



*```text*

*main.py*

*```*



*Manual network traffic classification interface.*



*```text*

*train\_model.py*

*```*



*Model training and preprocessing pipeline.*



*```text*

*rf.sav*

*```*



*Trained Random Forest model.*



*```text*

*scaler.sav*

*```*



*Saved feature scaler.*



*```text*

*label\_encoders.sav*

*```*



*Saved categorical feature encoders.*



*```text*

*target\_encoder.sav*

*```*



*Saved target encoder.*



*```text*

*dataset/*

*```*



*Training/data resources.*



*```text*

*screenshots/*

*```*



*Screenshots documenting the working application.*



*```text*

*docs/*

*```*



*Project technical documentation.*



*---*



*## 16. Running the Application*



*From the project directory:*



*```cmd*

*python -m streamlit run live\_monitor\_enhanced.py*

*```*



*The application runs locally through Streamlit.*



*The current working configuration uses:*



*```text*

*http://localhost:8503*

*```*



*---*



*## 17. Important Compatibility Note*



*The saved machine-learning artifacts were created using an earlier Scikit-learn version than the currently installed version.*



*During testing, Scikit-learn displayed an `InconsistentVersionWarning` indicating that the saved estimators were created with version `1.6.1` while the current environment uses version `1.9.0`.*



*The model, scaler, and encoders nevertheless loaded successfully during testing.*



*For a reproducible deployment, the project should use the same Scikit-learn version that was used when the model artifacts were created, or the model should be retrained and re-saved using the deployment environment.*



*---*



*## 18. Security and Operational Limitations*



*This project is a working cybersecurity prototype and should not be considered a production intrusion-prevention system.*



*The live monitor currently derives a limited set of model-compatible features from captured packets. The original training dataset uses flow/connection-level characteristics, so a production implementation would require more comprehensive flow aggregation and feature extraction.*



*Additional production requirements would include:*



*\* Network-flow reconstruction*

*\* More complete feature extraction*

*\* Model calibration*

*\* Larger live-network evaluation*

*\* False-positive/false-negative analysis*

*\* Persistent event storage*

*\* Authentication and access control*

*\* Secure deployment*

*\* Alerting and incident-response integration*



*---*



*## 19. Future Enhancements*



*Potential future improvements include:*



*1. Flow-based feature extraction*

*2. Attack-category classification*

*3. Real-time alert notifications*

*4. IP reputation integration*

*5. Historical database storage*

*6. Automated incident reports*

*7. Network traffic timelines*

*8. Model retraining*

*9. Model-drift monitoring*

*10. Deployment on a dedicated security monitoring server*



*---*



*## 20. Conclusion*



*The project demonstrates the integration of machine learning with live network monitoring.*



*It combines:*



*```text*

*Network Packet Capture*

&#x20;       *+*

*Feature Engineering*

&#x20;       *+*

*Machine Learning*

&#x20;       *+*

*Traffic Analysis*

&#x20;       *+*

*Interactive Security Dashboard*

*```*



*The resulting application provides a practical demonstration of how machine-learning techniques can assist in identifying potentially anomalous network activity.*



*\*\*Project Status: Working Prototype ✅\*\**




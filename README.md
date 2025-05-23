  # An Adaptive AI Framework for Detecting Known and Emergent Cyber Threats 

## 📍Project Summary
An Adaptive AI Framework for Detecting Known and Emergent Cyber Threats is a modular cybersecurity platform designed to proactively identify a wide spectrum of cyber threats using machine learning. The framework integrates supervised ensemble learning for classifying known threats and unsupervised anomaly detection for discovering zero-day and previously unseen attacks. It incorporates continuous feedback, real-time ingestion, and ethical design principles to ensure adaptability, transparency, and operational reliability.

## Proposed Solution
The proposed system is an end-to-end adaptive cybersecurity detection platform desgined to proactively identify both known and unknown threats across enterprise environments. It unifies supervised classification, unsupervised anomaly detection, and continuous analyst feedback into modular, scalable, and secure architecture.

### Core Design Objectives
- Detect known threats with high precision using labeled intelligence.
- Identify zero-day and emerging threats through anomaly detection.
- Adapt over time using feedback-driven learning.
- Ensure privacy, transparency, and compliance by design.
- Support real-time ingestion, multi-source data fusion, and SIEM-ready alerting.

### System Architecture
The system consists of the following key components:

**1. Data Ingestion Layer**
- Aggregates labeled and unlabeled data from local and cloud sources.
- Supports ingestion from:
  - Local datasets (Android malware, phishing URLs, spam/ham emails, dga custom).
  - Real-time threat intelligence feeds (ThreatFox, Malware Bazaar, PhishTank, Ransomwatch, 
    fireHOL)
  - Behavioral telemetry (network logs, DNS queries, file access events).
- Implements timestamping, deduplication, and raw file versioning for auditability.

**2. Preprocessing & Feature Engineering Layer**
- Cleans and transforms incoming data into consistent formats.
- Extracts key features such as:
  - URL length, domain entropy, CPU usage, file access frequency, session duration.
- Performs:
  - Normalization and encoding of categorical values.
  - Anomaly score baseline generation.
  - Threat context enrichment (e.g., IOC lookup, IP reputaion tagging)
  
**3. AI-Based Threat Detection Layer**
- Known Threat Detection:
  - Implements a stacking ensemble of:
    - Random Forest
    - XGBoost
    - Combined with a Logistic Regression meta-learner
  - Trained on labeled malicious and benign samples
  - Produces predicted labels and confidence scores
- Unknown Threat Detection:
  - Hybrid unsupervised detection using:
    - Isolation Forest for structural isolation
    - Mahalanobis Distance for multivariate anomaly scoring
  - Trained on benign behavioral profiles
  - Assigns anomaly scores to detect zero-day threats and unknown attack vectors.

**4. Threat Alerting & Response Engine**
- Maps detection results into a unified alert schema.
- Outputs include:
  - Threat type (malware, phishing, DGA, anomaly).
  - Severity score and detection confidence.
  - Feature vector and detection metadata.
- Alerts are:
  - Logged in structured JSON.
  - Forwarded to SIEM dashboards or incident response systems.

<p align="center">
  <img src="images/Final Architecture Diagram.png" alt="System Architecture" width="725"/>
  <br>
  <b>Figure 1:</b> Adaptive AI Threat Detection System Architecture
</p>

**5. Feedback-Driven Adaptive Learning Loop**
- Incorporates security analyst validation for alerts (true positive, false positives, etc.).
- Uses feedback to:
  - Retrain supervised models with corrected labels.
  - Recalibrate anomaly detection thresholds.
  - Update enrichment features (e.g., new threat types, custom rules).
- Ensures the detection pipeline evolves with the threat landscape.

**6. Security, Privacy & Compliance Layer**
- Implements secure-by-design features:
  - End-to-end encryption (data in transit and at rest).
  - Role-based access control (RBAC) and MFA enforcement.
  - Anonymization of personally identifiable information (PII).

## Dataset Overview

| Dataset Name          | Source             | Type         | Label Type     | Used For                     |
|-----------------------|--------------------|--------------|----------------|------------------------------|
| Android Malware       | Local CSV          | Network Logs | Malicious Only | Known threat detection       |
| Phishing URLs         | `malicious_phish`  | URLs         | Multi-label     | Known & unknown detection    |
| Spam/Ham Emails       | Local              | Text         | Binary (spam)   | Supervised classification    |
| DGA Domains           | Custom CSV         | Domain Names | Labeled         | DGA detection, supervised    |
| ThreatFox             | API/CSV            | IOCs         | Unlabeled       | Real-time enrichment         |
| MalwareBazaar         | API/CSV            | File Hashes  | Labeled         | IOC validation and context   |

## Model Evaluation Results
This section summarizes the classification performance of the supervised ensemble model for known threats and the unsupervised anomaly detection model for unknown/emergent threats.
- **Known Threat Detection - Supervised Stacking Model**
**Accuracy**: 91.77%
  
| Label Type       | Class | Precision | Recall | F1-Score | Support |
| ---------------- | ----- | --------- | ------ | -------- | ------- |
| Benign           | 0     | 0.8796    | 0.9643 | 0.9200   | 374,140 |
| Malicious        | 1     | 0.9621    | 0.8729 | 0.9153   | 388,355 |
|                  |       |           |        |          |         |
| **Macro Avg**    | —     | 0.9209    | 0.9186 | 0.9177   | 762,495 |
| **Weighted Avg** | —     | 0.9216    | 0.9177 | 0.9176   | 762,495 |

- **Unknown Threat Detection - Hybrid Anomaly Detection Model**

**Default Threshold Evaluation**

| Label Type       | Class | Precision | Recall | F1-Score | Support |
| ---------------- | ----- | --------- | ------ | -------- | ------- |
| Normal           | 0     | 0.9918    | 0.9630 | 0.9772   | 247,970 |
| Anomalous        | 1     | 0.9739    | 0.9942 | 0.9840   | 344,268 |
|                  |       |           |        |          |         |
| **Macro Avg**    | —     | 0.9828    | 0.9786 | 0.9806   | 592,238 |
| **Weighted Avg** | —     | 0.9814    | 0.9812 | 0.9811   | 592,238 |


**Optimized Threshold Evaluation (Threshold = 0.4854)**

| Label Type       | Class | Precision | Recall | F1-Score | Support |
| ---------------- | ----- | --------- | ------ | -------- | ------- |
| Normal           | 0     | 0.9959    | 0.9630 | 0.9792   | 247,970 |
| Anomalous        | 1     | 0.9740    | 0.9972 | 0.9854   | 344,268 |
|                  |       |           |        |          |         |
| **Macro Avg**    | —     | 0.9850    | 0.9801 | 0.9823   | 592,238 |
| **Weighted Avg** | —     | 0.9832    | 0.9829 | 0.9828   | 592,238 |


## Tools, Frameworks, and Technologies
The system is developed in Python 3.10+, leveraging a modular architecture that supports both supervised and unsupervised machine learning techniques for cyber threat detection. For known threat classification, the framework uses the scikit-learn library for model training and evaluation, alongside xgboost for efficient and high-performance gradient boosting. Ensemble stacking is implemented using Random Forest, XGBoost, and Logistic Regression as the meta-learner.

To support unsupervised detection of unknown or emergent threats, the project uses the pyod library, incorporating Isolation Forest and Mahalanobis Distance for anomaly scoring. These models are trained on benign behavioral baselines and calibrated with real-world anomaly injections.

Data preprocessing and transformation are handled using pandas and numpy, ensuring efficient manipulation of structured threat intelligence and log data. Model persistence is achieved through joblib, enabling fast model saving and loading for reuse in production or retraining workflows.

Visualization of model performance (e.g., ROC curves, feature importance, and anomaly score distributions) is performed using matplotlib and seaborn. Jupyter Notebooks are used during experimentation phases to analyze performance metrics, tune hyperparameters, and perform threshold optimization.

All training, validation, and inference processes are fully logged using Python’s built-in logging module. This enables traceability, auditability, and debugging support. Furthermore, the system is designed to support real-time integration with SIEM tools by exporting alerts and metadata in structured JSON format.

The architecture also includes built-in mechanisms for analyst feedback collection, dynamic threshold recalibration, and periodic retraining, ensuring the system continuously evolves as new threat vectors emerge. Security and privacy are addressed through data anonymization, role-based access controls, and encryption protocols applied throughout the data lifecycle.

## How it Works - Customer Perspective
This system is designed to run in the background of your organization’s infrastructure, continuously monitoring and detecting cyber threats with minimal manual effort. It automatically collects data from internal logs and external threat feeds, analyzes it using AI models, and identifies both known and unknown threats in real time.

When a threat is detected, the system generates an alert with all relevant context such as severity, source, and type making it easy for your security team to respond quickly. Alerts can be forwarded directly to your existing dashboards or SIEM tools.

To reduce false positives, the system learns from analyst feedback and adapts its detection logic over time. This ensures high accuracy and reduces alert fatigue. Throughout the process, data privacy is preserved through anonymization and secure handling, meeting modern compliance standards.

Overall, the system delivers intelligent, adaptive, and real-time threat detection improving your cybersecurity posture without disrupting daily operations.

## Conclusion & Future Work
This project demonstrates a complete, AI-driven framework capable of detecting both known and emergent cyber threats with high accuracy and adaptability. By combining supervised ensemble learning with unsupervised anomaly detection, the system provides a robust solution to modern cybersecurity challenges delivering real-time, intelligent, and continuously evolving protection.

The feedback loop and retraining mechanism ensure that the system improves over time, adapting to new attack patterns while maintaining low false positive rates. Its modular design and compliance-aware architecture make it suitable for deployment in enterprise, academic, and research environments.

In future iterations, the framework will be enhanced with features such as explainable AI (XAI) integration, online learning for real-time model updates, edge-device deployment for IoT environments, and deeper integration with SOC automation and orchestration platforms.

This marks a significant step toward building scalable, autonomous, and trustworthy AI security systems ready to support real-world operations.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-IDS-red)
![Status](https://img.shields.io/badge/Status-Active-success)
![License](https://img.shields.io/badge/License-MIT-yellow)
# 🛡️ Intrusion Detection System (IDS)

A Python-based Intrusion Detection System that monitors system activity, detects suspicious behavior, logs security events, and generates alerts for potential intrusions.

---

## 📌 Overview

This project demonstrates the implementation of a lightweight Intrusion Detection System (IDS) using Python. It continuously monitors predefined events, identifies suspicious activities based on configurable rules, and records alerts for security analysis.

---
##Project architecture

main.py
    │
    ▼
detector.py
    │
    ▼
config.py
    │
    ▼
logger.py
    │
    ▼
alerts.log

## ✨ Features

* 🔍 Detects suspicious activities
* ⚙️ Configurable detection rules
* 📝 Event logging
* 🚨 Real-time alert generation
* 📂 Modular Python architecture
* 📊 Easy to extend with additional detection methods

---

## 📁 Project Structure

```text
Intusion-detection/
│
├── __pycache__/
├── alerts.log
├── config.py
├── detector.py
├── logger.py
├── main.py
├── requirements.txt
├── utils.py
└── README.md
```

---

## 🛠 Technologies Used

* Python 3.x
* Logging Module
* File Handling
* Rule-Based Detection

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/badivana/Intusion-detection.git
```

Move into the project directory:

```bash
cd Intusion-detection
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Project

Start the intrusion detection system:

```bash
python main.py
```

The application will monitor events and generate alerts whenever suspicious activity is detected.

---

## 📄 Project Files

| File          | Description                    |
| ------------- | ------------------------------ |
| `main.py`     | Entry point of the application |
| `detector.py` | Detection engine               |
| `config.py`   | Configuration settings         |
| `logger.py`   | Logging functionality          |
| `utils.py`    | Helper functions               |
| `alerts.log`  | Generated security alerts      |

---

## 🔄 Workflow

Incoming Event
      │
      ▼
 Event Monitoring
      │
      ▼
 Rule-Based Detection
      │
      ▼
 Suspicious Activity?
      │
 ┌────┴─────┐
 │          │
No         Yes
 │          │
 ▼          ▼
Continue   Log Event
            │
            ▼
      Generate Alert

---

## 📈 Future Enhancements

* Machine Learning-based anomaly detection
* Web dashboard
* Email notifications
* Real-time monitoring interface
* Database integration
* Network packet analysis
* Threat severity classification

---

## 🎯 Applications

* Network Security
* Cybersecurity Research
* Educational Projects
* Security Monitoring
* System Administration

---

## 👨‍💻 Author

**Prajwal B T**

Information Science Engineering Student

Interested in Cybersecurity, Artificial Intelligence, and Software Development.

---

## ⭐ Support

If you found this project useful, consider giving it a ⭐ on GitHub.

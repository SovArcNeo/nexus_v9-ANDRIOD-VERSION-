[![System](https://img.shields.io/badge/SYSTEM-NEXUS_MOBILE_v9.0-00FF41?style=for-the-badge&labelColor=000000)](https://github.com/SovArcNeo)
[![Platform](https://img.shields.io/badge/PLATFORM-ANDROID_%2F_LINUX-orange?style=for-the-badge&labelColor=000000)](https://termux.com/)
[![AI Core](https://img.shields.io/badge/AI-PURE_PYTHON_NEURAL_NET-blue?style=for-the-badge&labelColor=000000)](https://github.com/SovArcNeo)
[![Security](https://img.shields.io/badge/SECURITY-MAXIMUM_LEVEL-red?style=for-the-badge&labelColor=000000)](https://github.com/SovArcNeo)
[![License](https://img.shields.io/badge/LICENSE-MIT-gray?style=for-the-badge&labelColor=000000)](LICENSE)

# NEXUS UNIFIED v9.0 (Mobile Edition)
## Sovereign Network Intelligence & Host Monitoring System

**NEXUS v9** is the field-deployable core of the Sovereign Defense Grid. Optimized for **Android (Pydroid3 / Termux)** and Linux environments, it provides a unified command dashboard for network intelligence, host monitoring, and autonomous threat assessment without requiring root access or external APIs.

It features a **Pure Python Neural Network** fallback system, ensuring ML capabilities remain active even on devices where `numpy` or `scikit-learn` cannot be installed.

---

## ⚡ Mobile Command Center
> *Pocket-sized Sovereign Intelligence. Real-time visualization of the invisible war.*

The v9 Dashboard (`DashboardController`) renders a high-fidelity text UI compatible with mobile terminal emulators, providing real-time telemetry on:
* **Network Intelligence:** Async scanning results from `AGENT_AGESIS_B`.
* **Host Threat Level:** ML-driven assessment of local device metrics.
* **Agent Status:** Tracking of autonomous sub-systems (Alpha, Bravo, Charlie).

## 📱 Mission Control Center
> *When you are on the go it goes with you.*

| **Main Dashboard** | **Live System** |
|:---:|:---:|
|![Nexus_v9_load](https://github.com/user-attachments/assets/f4611f70-7e08-465c-b5c6-7650e013cc19)| ![Nexus_v9_1](https://github.com/user-attachments/assets/ac70a791-9aa3-44bc-b516-3bf6132451d3)|
| **Enterprise level security in the plam of your hand.** | **People are mobile your security should be too.** |

 

---

## ⚡ System Architecture

### 🧠 Adaptive Neural Core
NEXUS v9 implements a dual-mode AI engine designed for mobile constraints:
1.  **Performance Mode:** Uses `numpy` and `scikit-learn` if detected.
2.  **Field Mode (Fallback):** Automatically switches to a custom **Pure Python Neural Network** implementation (`class NeuralNetwork`) if libraries are missing. This ensures the system *never* fails to boot, even in restricted environments.

### 📡 Async Network Scanner
* **Non-Blocking I/O:** Uses `asyncio` to scan hundreds of ports concurrently without freezing the mobile UI.
* **Risk Scoring:** Real-time calculation of device risk based on open ports, services, and response times.
* **Device Fingerprinting:** Passive identification of OS and service versions.

### 🛡️ Host Security Monitor
* **Anomaly Detector:** Statistical analysis of CPU, Memory, and Process variance to detect intrusion attempts or malware.
* **Audit Logging:** JSON-structured security logs with tamper-evident timestamping.
* **Auto-Defense:** Capable of triggering "Defensive Mode" based on threat thresholds.

---

## 🚀 Quick Start (Android/Termux)

Turn your device into a defense node.

1.  **Install Dependencies**
    *Recommended: Pydroid 3 or Termux*
    ```bash
    pip install -r requirements.txt
    # Note: System runs in "Field Mode" if dependencies fail
    ```

2.  **Initialize NEXUS**
    ```bash
    python nexus_v9.py
    ```

3.  **Engage Agents**
    Use the Command Interface to:
    * `[1]` Scan Local Network
    * `[13]` Activate ML Threat Engine
    * `[14]` Start Host Threat Monitor

---

## 🔧 Configuration
The system auto-generates `config.json` on first launch. Key parameters:
* **SECURITY_LEVEL:** Defaults to `MAXIMUM`.
* **ANOMALY_THRESHOLD:** Sensitivity of the statistical detection engine (Default: 2.5).
* **AUTO_DEFENSIVE:** Enable/Disable automated countermeasures.

---

## ⚖️ Legal & Ethical Use Declaration
**NEXUS v9** is engineered for **defensive security research**, mobile network hardening, and educational purposes.
* **Authorization:** Do not scan networks you do not own or have explicit permission to test.
* **Compliance:** Users are responsible for adhering to all local, state, and federal laws regarding network monitoring and encryption tools.

**© 2025 SovArcNeo // THE NEXUS PROJECT**

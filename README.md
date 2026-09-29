# 🛡️ Enterprise Threat Intelligence Aggregator (Non-AI)

An enterprise-grade, non-AI Threat Intelligence (TI) Aggregator built to automate the collection, parsing, normalization, and correlation of Indicators of Compromise (IOCs) from live open-source security feeds.

## 🚀 Key Architectural Features
* **Regex-Driven Parsing:** Utilizes high-precision regular expressions to extract malicious IPs, URLs, domains, and hashes without the overhead or unpredictability of Machine Learning.
* **Network-Level Validation:** Evaluates extracted indicators through Python's structural network modules to discard invalid or private assets.
* **Cross-Feed Correlation Engine:** Measures the presence of threat objects across multiple security vendors to dynamically rank risk status (Medium, High, Critical).
* **Automated Blocklist Provisioning:** Exports ready-to-use rule outputs tailored for modern Firewalls, Web Filters, and EDR systems.

## 🗂️ Project Repository Map
* `app.py`: Streamlit-driven analytical frontend UI layout.
* `aggregator.py`: Operational core handling downloads, clean parsing, and correlation.
* `requirements.txt`: Specified platform library dependencies.

## ⚙️ How to Launch Locally

1. **Clone the repository:**
   ```bash
   git clone <your-github-repo-link>
   cd threat-intel-aggregator
   ```

2. **Install necessary dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Execute the Application:**
   ```bash
   streamlit run app.py
   ```

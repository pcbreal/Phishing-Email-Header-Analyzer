# Phishing Email Header Analyzer 📨🔍

A lightweight CLI tool for **Security / CTI analysts** to triage email headers:
- Summarizes **SPF / DKIM / DMARC** verdicts
- Maps the **Received** hop chain
- Flags anomalies (domain misalignment, missing headers, lookalikes)
- Colorized terminal output (green/yellow/red)
- **No network calls** (safe offline)

## Quick Start
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python src/header_analyzer.py --file sample_headers/suspicious_example.eml
# or:
cat sample_headers/legit_example.eml | python src/header_analyzer.py

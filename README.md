# 🛠️ Toolio — Automated Nmap Reporting Tool

## DISCLAIMER: THIS TOOL IS FOR DEMONSTRATION PURPOSES DO NOT SCAN WITHOUT EXPLICIT CONSENT

**Toolio** is a Python-based command-line utility that automates network scanning and reporting using **Nmap**.  
It runs targeted or bulk scans, parses Nmap’s XML output, and generates clean, human-readable **HTML**, **JSON**, and **Markdown** reports — ideal for pentesting documentation or reconnaissance summaries.

---

## 🚀 Features

- 🧠 **Automated Nmap Execution** — runs system-installed Nmap with flexible scan options  
- ⚡ **Parallel Scanning** — supports multiprocessing for multiple targets  
- 📊 **Structured Output** — generates reports in HTML, JSON, and Markdown formats  
- 🧩 **Easy Customization** — simple CLI options for ports, scan types, and thread count  
- 💾 **Self-contained** — no external Python dependencies beyond the standard library  

---

## 📂 Project Structure

toolio/  

├── docs/ # Documentation and architecture overview  

├── requirements.txt # Python version requirements  

├── toolio.py # Main Python script  

└── README.md # This file


## 💻 Installation

Toolio requires **Python 3.8+** and **Nmap** installed on your system.

```bash
# Clone the repository
git clone https://github.com/jbanks7220/toolio.git
cd toolio

# Make sure Nmap is installed
sudo apt install nmap

# (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

## ⚙️ Usage

Run Toolio from the command line:
```
python3 toolio.py --targets scanme.nmap.org --ports 22,80,443
```
Or scan multiple targets from a file:
```
python3 toolio.py --targets-file examples/targets.txt --top-ports 100
```
Toolio will create a timestamped set of reports (HTML, JSON, and Markdown) inside the output directory (default: nmap_reports/).

## 🧩 Architecture Overview

Toolio is built around four main components:

**Nmap Runner** — executes Nmap commands using subprocess

**XML Parser** — processes and extracts structured data from Nmap’s XML output

**Report Generators** — converts parsed data into HTML, JSON, and Markdown formats

**CLI Interface** — built with argparse for clean and flexible command-line usage

For more details, see docs/architecture.md

# 📸 Demonstration

## 🎥 Watch the video demonstration:

https://github.com/user-attachments/assets/f9d3aa6f-f665-413d-9674-91a1f76f1f1d

A short terminal demo showing Toolio scanning scanme.nmap.org, followed by the HTML, JSON, and Markdown reports generated.

## 👤 Author

Developed by Jamir Banks

💼 Designed for portfolio demonstration and red team tooling practice.

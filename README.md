# 🔎 Automated Reconnaissance & Vulnerability Scanning Framework
Python-based penetration testing tool that performs recon, scanning, and generates reports in JSON, HTML, and PDF formats.

## 📌 Project Overview
The **Automated Reconnaissance & Enumeration Framework** is a Python-based security tool developed as part of a penetration testing internship project.  

This framework integrates multiple reconnaissance and vulnerability assessment techniques into a **single automated workflow**, allowing security professionals and learners to identify open ports, detect running services, probe subdomains, and highlight potential vulnerabilities.  

Unlike traditional manual testing, this project emphasizes **automation, efficiency, and structured reporting**, making it a useful resource for students, ethical hackers, and penetration testers looking to streamline their assessment process.  

---

## 🎯 Objectives
The primary objectives of this project include:  
- Automating repetitive reconnaissance tasks to save time.  
- Identifying open ports and service banners for potential attack surfaces.  
- Detecting subdomains that could expand the attack perimeter.  
- Testing endpoints for common vulnerabilities such as **SQL Injection, XSS, and Open Redirects**.  
- Checking for **default or weak credentials** in commonly exploited services.  
- Performing **API endpoint security tests** to highlight unauthorized access risks.  
- Generating professional **reports in JSON, HTML, and PDF formats** to present findings clearly.  

---

## ⚙️ Features
✔️ Subdomain Enumeration (DNS resolution + Certificate Transparency logs)  
✔️ Port Scanning with multi-threading for speed  
✔️ Service Banner Grabbing to detect technologies  
✔️ HTTP Probing (status codes, server type, powered-by headers)  
✔️ Basic Web Vulnerability Scanning (SQLi, XSS, Open Redirects)  
✔️ Default Credentials Checks for FTP, SSH, MySQL, and others  
✔️ API Security Testing on pre-defined endpoints  
✔️ Structured Report Generation in **JSON, HTML, and PDF** with charts  

---

## 🛠 Tools & Technologies Used
The project was built using a mix of **Python standard libraries** and **third-party packages**:  

- **Python 3.x** (Primary language)  
- **Socket Programming** – for port scanning and connectivity checks  
- **Requests Library** – for HTTP probing and web vulnerability testing  
- **DNS Resolver (dnspython)** – for subdomain resolution  
- **Matplotlib** – for data visualization (charts for ports & vulnerabilities)  
- **FPDF / ReportLab** – for professional PDF reporting  
- **Rich Console** – for progress bars and styled terminal outputs  
- **Threading** – to improve performance during scans  

---

## 📂 Project Structure

Automated-Recon-Framework/
│
├── auto.py # Main Python script (core logic)
├── config.json # Configuration file (ports, subdomains, etc.)
├── requirements.txt # Dependencies list
├── reports/ # Generated reports folder
│ └── (created automatically after running the tool)
├── LICENSE # Open-source license (optional)
└── README.md # Documentation

---

## ⚙️ Installation
Clone the repository and navigate into the project directory:
```bash
git clone https://github.com/shobhit2022/Automated-Recon-Framework.git
cd Automated-Recon-Framework
```

Install required dependencies:

```bash
pip install -r requirements.txt
```
---

## ⚡ Configuration

You can modify scanning parameters inside the config.json file:

```bash
{
    "top_ports": [21,22,23,25,53,80,443,445,3306,8080],
    "max_threads": 50,
    "http_timeout": 3,
    "subdomains": ["www","mail","ftp","dev","api","test"]
}
```
- top_ports → List of ports to scan
- max_threads → Number of concurrent threads for faster scanning
- http_timeout → Timeout for HTTP probing (in seconds)
- subdomains → Pre-defined subdomains to attempt enumeration

---

## 🚀 How to Run the Project

Run the framework from the terminal:

```bash
python auto.py
```
You will be prompted to enter a target IP or domain:

```bash
Enter target IP or domain: example.com
```
The framework automatically carries out the following actions:
- Check if the host is alive.
- Perform port scanning and service banner detection.
- Enumerate possible subdomains.
- Probe HTTP services for headers and status codes.
- Run basic vulnerability scans.
- Generate structured reports.
- Reports are saved in the reports/ folder in JSON, HTML, and PDF formats with visual charts.


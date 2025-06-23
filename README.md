# Scan-WP

**Scan-WP** is a fast, multithreaded vulnerability scanner for WordPress websites.
It detects installed plugins and WordPress core versions, then compares them against a local CVE database (RCE, SQLi, File Upload, etc.).
The tool **does not exploit** any vulnerability — it only verifies known matches.

> 🚀 Future updates will include automatic CVE database syncing, support for more CVE types, and faster scanning optimizations.

---

## 🔧 Features

* Detects WordPress core version
* Extracts plugin names and versions
* Matches vulnerabilities from a built-in CVE database inside the script
* Fast scanning with multi-threading
* Outputs vulnerable sites with relevant CVE info
* Simple and clean terminal interface (using `rich`)

---

## 📦 Requirements

Install the required libraries using:

```bash
pip install -r requirements.txt
```

### Required Libraries:

```text
requests  
bs4  
packaging  
rich  
```

---

## 📂 Installation

1. Clone this repository:

```bash
git clone https://github.com/rakan2202000/Scan-WP.git
cd Scan-WP
```

2. Create or update your `list.txt` with target URLs (one URL per line).

> **Note:** The CVE database is already embedded inside the script (`Scan-WP.py`). No need for external JSON or database files.

---

## 🚀 Usage

```bash
python Scan-WP.py
```

Make sure `list.txt` exists in the same directory and contains the list of target WordPress sites.

---

## 📌 Example

Sample `list.txt`:

```
https://example1.com
https://example2.org
```

Expected output:

```
[+] Scanning: https://example1.com
[+] Detected WordPress v6.2.2
[+] Detected Plugins: elementor v3.15.1, wpforms v1.7.8
[!] Vulnerable Plugin: elementor — CVE-2023-XXXXX
[!] Vulnerable Plugin: wpforms — CVE-2024-YYYYY
```

---

## ⚠️ Notes

* The CVE database is hardcoded inside the script.
* The tool only scans and matches vulnerabilities; it does **not** exploit them.
* Use responsibly for authorized testing only.

---

**By Rakan**

# Scan-WP

**Scan-WP** is a high-performance WordPress vulnerability detection tool focused on plugin and core version mapping against a curated CVE database. Designed for speed, it can scan thousands of WordPress sites in minutes, making it ideal for large-scale audits or reconnaissance operations.

---

## 🧠 Technical Description

Scan-WP performs the following operations:

- Loads a list of WordPress URLs from `list.txt`.
- Fetches plugin names and versions for each target.
- Detects the WordPress core version (if exposed).
- Compares all detected components with a verified CVE database (2022–2025) containing confirmed PoCs.
- Outputs matched vulnerabilities with plugin name, version, and CVE reference.
- Does **not** attempt exploitation — detection only.

This tool is built for speed, multithreading, and stability. It avoids false positives by relying on accurate fingerprinting and curated vulnerability data.

---

## 📦 Requirements

- Python 3.8+
- `list.txt` — contains one URL per line
- Internet access (to fetch plugin info)

Install dependencies:

```bash
pip install -r requirements.txt
python Scan-WP.py

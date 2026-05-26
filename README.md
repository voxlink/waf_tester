# WAF Quality Tester

A Python-based security testing tool to assess the quality of Web Application Firewall (WAF) rules using OWASP-based payloads. Generates detailed PDF and Excel reports with scoring, strengths/weaknesses analysis, and remediation recommendations.

> ⚠️ **LEGAL DISCLAIMER: Only use this tool on systems you own or have explicit written authorization to test. Unauthorized use against third-party systems may violate computer fraud and abuse laws in your jurisdiction. The author assumes no liability for misuse.**

---

## Features

- **WAF Detection** — Fingerprints common WAF vendors (Cloudflare, AWS WAF, Akamai, Imperva, F5, ModSecurity, Fortinet, Sucuri, Barracuda, and more)
- **97 OWASP Payloads** across 14 attack categories including evasion/bypass variants
- **Professional Reports** — PDF and Excel with color-coded results, statistics, and recommendations
- **Bypass Testing** — Each category includes WAF evasion techniques (encoding, case mutation, null bytes, fragmentation, etc.)
- **Grading System** — Overall WAF quality scored from A+ (Excellent) to F (Critical Risk)

---

## Attack Categories

| # | Category | Payloads |
|---|----------|---------|
| 1 | SQL Injection — Classic | 10 |
| 2 | SQL Injection — WAF Bypass | 10 |
| 3 | XSS Reflected | 10 |
| 4 | XSS — WAF Bypass | 10 |
| 5 | Path Traversal / LFI | 10 |
| 6 | Command Injection | 10 |
| 7 | Command Injection — Bypass | 5 |
| 8 | XXE Injection | 3 |
| 9 | SSRF | 8 |
| 10 | HTTP Header Injection | 5 |
| 11 | SSTI (Template Injection) | 7 |
| 12 | NoSQL Injection | 5 |
| 13 | CRLF / Header Injection | 4 |
| 14 | Open Redirect | 5 |

---

## Requirements

- Python 3.8+
- See `requirements.txt`

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/waf-quality-tester.git
cd waf-quality-tester
pip install -r requirements.txt
```

---

## Usage

```bash
# Basic scan — outputs both PDF and Excel
python3 waf_tester.py -u https://your-authorized-site.com

# Verbose mode — shows every request result in terminal
python3 waf_tester.py -u https://your-site.com --verbose

# Custom delay between requests (recommended for rate-limited WAFs)
python3 waf_tester.py -u https://your-site.com --delay 1.5

# Output only Excel report
python3 waf_tester.py -u https://your-site.com --format excel

# Output only PDF report
python3 waf_tester.py -u https://your-site.com --format pdf

# Custom output filename prefix
python3 waf_tester.py -u https://your-site.com --output /path/to/pentest_report
```

### All Options

| Flag | Default | Description |
|------|---------|-------------|
| `-u`, `--url` | *(required)* | Target URL |
| `--timeout` | `8` | Request timeout in seconds |
| `--delay` | `0.4` | Delay between requests in seconds |
| `--verbose` | `False` | Show all request results in terminal |
| `--format` | `both` | Report format: `pdf`, `excel`, `both`, `json` |
| `--output` | `waf_report` | Output filename prefix |

---

## Report Contents

### PDF Report
- Cover page with WAF fingerprint, overall block rate, and grade
- Category breakdown table with risk level coloring
- Per-payload detail table (ID, description, HTTP status, BLOCKED/BYPASSED)
- Strengths & Weaknesses analysis
- Prioritized remediation recommendations (WAF rule fixes + application-layer fixes)

### Excel Report
- **Sheet 1 — Summary**: metadata, overall stats, category breakdown
- **Sheet 2 — Detailed Results**: every payload with HTTP status and result
- **Sheet 3 — Recommendations**: severity-sorted remediation table

### Grading Scale

| Grade | Block Rate |
|-------|-----------|
| A+ Excellent | ≥ 95% |
| A Very Good | ≥ 85% |
| B Good | ≥ 75% |
| C Fair | ≥ 60% |
| D Weak | ≥ 40% |
| F Critical Risk | < 40% |

---

## Example Output

```
================================================================
  WAF QUALITY TESTER — AUTHORIZED PENETRATION TESTING ONLY
================================================================

  Target  : https://your-site.com
  Delay   : 0.4s between requests
  Format  : both

[1/4] Establishing baseline connection...
[+] Baseline: HTTP 200 | Size: 14823 bytes

[2/4] Detecting WAF...
[!] WAF Detected: Cloudflare

[3/4] Running OWASP payload tests...

[*] Category: SQL Injection - Classic (10 payloads)
  [SQLi-01] ✗ BLOCKED | HTTP 403 | Basic OR injection
  [SQLi-02] ✗ BLOCKED | HTTP 403 | Comment-based bypass
  ...

[SUMMARY] Block Rate: 62.9% | Grade: C (Fair)

[+] PDF report saved: waf_report_20250526_143012.pdf
[+] Excel report saved: waf_report_20250526_143012.xlsx
```

---

## Similar / Related Tools

This tool is inspired by and intended to complement:
- [OWASP ZAP](https://www.zaproxy.org/)
- [SQLMap](https://sqlmap.org/)
- [nikto](https://github.com/sullo/nikto)
- [wafw00f](https://github.com/EnableSecurity/wafw00f)

Unlike full-featured scanners, this tool focuses specifically on **WAF rule quality scoring and reporting**, making it useful for security engineers auditing their own WAF configurations.

---

## Contributing

Pull requests are welcome. To add payloads, extend the `PAYLOADS` dictionary in `waf_tester.py`. Please follow the existing format:

```python
"Your Category Name": [
    ("CAT-ID-01", "payload_string", "Human-readable description"),
    ...
]
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is provided for **educational and authorized security testing purposes only**. The author is not responsible for any misuse or damage caused by this tool. Always obtain proper written authorization before testing any system you do not own.

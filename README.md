# NextJSPwn - Unified Next.js Exploitation Framework

![Version](https://img.shields.io/badge/Version-1.0.0-blue)
![Python](https://img.shields.io/badge/Python-3.8+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

**NextJSPwn** is a comprehensive, unified exploitation framework for testing Next.js applications against known critical vulnerabilities.

---

## 📋 Table of Contents

- [Features](#features)
- [Supported CVEs](#supported-cves)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Command-Line Options](#command-line-options)
- [Advanced Usage](#advanced-usage)
- [Output Formats](#output-formats)
- [Architecture](#architecture)
- [Legal Disclaimer](#legal-disclaimer)

---

## ✨ Features

✅ **Unified Framework** - Test all Next.js CVEs from a single tool  
✅ **Modular Architecture** - Each CVE has its own dedicated module  
✅ **Comprehensive Scanning** - Automatic version detection and vulnerability assessment  
✅ **Multi-Target Support** - Scan multiple targets from a file  
✅ **Flexible Testing** - Test all CVEs or specific ones  
✅ **Proxy Support** - Works with Burp Suite and other proxies  
✅ **JSON Export** - Save results for reporting  
✅ **Colorized Output** - Clear, readable terminal output  
✅ **Debug Mode** - Detailed logging for troubleshooting  

---

## 🎯 Supported CVEs

| CVE | Description | Severity | CVSS | Status |
|-----|-------------|----------|------|--------|
| **CVE-2025-29927** | Middleware Authorization Bypass | 🔴 CRITICAL | 9.1 | ✅ Supported |
| **CVE-2024-51479** | Authorization Bypass (pathname middleware) | 🟠 HIGH | 7.5 | ✅ Supported |
| **CVE-2024-34351** | Server Actions SSRF (Host header) | 🟠 HIGH | 7.5 | ✅ Supported |
| **CVE-2024-46982** | Cache Poisoning (SSR forced to SSG) | 🟠 HIGH | 7.5 | ✅ Supported |
| **CVE-2025-57822** | Middleware SSRF | 🟡 MEDIUM | 6.5 | ✅ Supported |
| **CVE-2025-57752** | Image Optimizer Cache Deception | 🟡 MEDIUM | 6.5 | ✅ Supported |
| **CVE-2025-55173** | Image Optimization Content Injection | 🟡 MEDIUM | 6.5 | ✅ Supported |
| **CVE-2025-49826** | Cache Poisoning → DoS (HTTP 204) | 🟡 MEDIUM | 5.9 | ✅ Supported |
| **CVE-2025-32421** | Race Condition Info Disclosure | 🟡 MEDIUM | 5.3 | ✅ Supported |
| **CVE-2025-48068** | Dev Server Info Exposure (CSWSH/XSSI) | 🟢 LOW | 4.3 | ✅ Supported |

### CVE Details

#### CVE-2025-29927 - Middleware Authorization Bypass
- **Affected**: Next.js 11.1.4 - 13.5.6, 14.x < 14.2.25, 15.x < 15.2.3
- **Impact**: Complete authorization bypass via `X-Middleware-Subrequest` header
- **Patch**: Update to 14.2.25+ or 15.2.3+

#### CVE-2024-51479 - Authorization Bypass (pathname middleware)
- **Affected**: Next.js 9.5.5 - 14.2.14
- **Impact**: Middleware authorization based on pathname bypassed for root-level pages
- **Patch**: Update to 14.2.15+

#### CVE-2024-34351 - Server Actions SSRF (Host header)
- **Affected**: Next.js 13.4.0 - 14.1.0 (self-hosted, using Server Actions with a relative redirect)
- **Impact**: SSRF via attacker-controlled `Host` header on Server Action redirects
- **Patch**: Update to 14.1.1+

#### CVE-2024-46982 - Cache Poisoning (SSR forced to SSG)
- **Affected**: Next.js 13.5.1 - 14.2.9 (Pages Router)
- **Impact**: Private SSR responses forced to be cached (s-maxage/stale-while-revalidate) and served to others
- **Patch**: Update to 14.2.10+

#### CVE-2025-57822 - Middleware SSRF
- **Affected**: Next.js < 14.2.32, 15.x < 15.4.7
- **Impact**: Server-Side Request Forgery via insecure header forwarding
- **Patch**: Update to 14.2.32+ or 15.4.7+

#### CVE-2025-57752 - Image Optimizer Cache Deception
- **Affected**: Next.js < 14.2.32, 15.x < 15.4.7
- **Impact**: `/_next/image` cache key omits auth headers → private images served to anonymous users
- **Patch**: Update to 14.2.32+ or 15.4.7+

#### CVE-2025-55173 - Image Optimization Content Injection
- **Affected**: Next.js < 14.2.31, 15.x < 15.4.5
- **Impact**: `/_next/image` forces download of arbitrary content/filename from the trusted origin
- **Patch**: Update to 14.2.31+ or 15.4.5+

#### CVE-2025-49826 - Cache Poisoning → DoS (HTTP 204)
- **Affected**: Next.js 15.1.0 - 15.1.7
- **Impact**: Empty HTTP 204 response cached and served to all visitors of a static page
- **Patch**: Update to 15.1.8+

#### CVE-2025-32421 - Race Condition Information Disclosure
- **Affected**: Next.js < 14.2.24, 15.0.0 - 15.1.5
- **Impact**: pageProps data leakage via race condition
- **Patch**: Update to 14.2.24+ or 15.1.6+

#### CVE-2025-48068 - Dev Server Information Exposure (CSWSH/XSSI)
- **Affected**: Next.js 13.0.0 - 14.2.29, 15.0.0 - 15.2.1 (**development server only**)
- **Impact**: Cross-Site WebSocket Hijacking / Cross-Origin Script Inclusion against `next dev` exposes source
- **Patch**: Update to 14.2.30+ or 15.2.2+

---

## 🔧 Installation

### Prerequisites
- Python 3.8+
- pip3

### Install Dependencies

```bash
pip3 install -r requirements.txt
```

**requirements.txt:**
```
requests>=2.31.0
colorama>=0.4.6
urllib3>=2.0.0
```

### Make Executable

```bash
chmod +x nextjspwn.py
```

---

## 🚀 Quick Start

### Basic Scan (All CVEs)

```bash
./nextjspwn.py -t https://example.com
```

### Test Specific CVE

```bash
./nextjspwn.py -t https://example.com -cve CVE-2025-29927
```

### Scan Multiple Targets

```bash
./nextjspwn.py -f targets.txt
```

---

## 📖 Usage Examples

### 1. **Comprehensive Security Audit**

Test all CVEs and save results:

```bash
./nextjspwn.py -t https://example.com -o results.json
```

### 2. **Test Middleware Authorization Bypass**

```bash
./nextjspwn.py -t https://example.com -cve CVE-2025-29927
```

### 3. **Test SSRF with Callback**

```bash
# With Burp Collaborator
./nextjspwn.py -t https://example.com -cve CVE-2025-57822 --callback https://xxxx.oastify.com

# With Interactsh
./nextjspwn.py -t https://example.com -cve CVE-2025-57822 --callback https://xxxx.interact.sh
```

### 4. **Test Race Condition (Intensive)**

```bash
./nextjspwn.py -t https://example.com -cve CVE-2025-32421 --iterations 20
```

### 5. **Scan with Burp Suite Proxy**

```bash
./nextjspwn.py -t https://example.com --proxy http://127.0.0.1:8080 -k --debug
```

### 6. **Multi-Target Corporate Assessment**

```bash
# Create targets file
cat > targets.txt << EOF
https://app1.company.com
https://app2.company.com
https://app3.company.com
EOF

# Scan all targets
./nextjspwn.py -f targets.txt -o corporate_scan.json
```

### 7. **Test Multiple Specific CVEs**

```bash
./nextjspwn.py -t https://example.com -cve CVE-2025-29927 CVE-2025-32421
```

### 8. **SSL Bypass for Self-Signed Certificates**

```bash
./nextjspwn.py -t https://internal.company.local -k
```

---

## ⚙️ Command-Line Options

### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `-t`, `--target` | Single target URL | `-t https://example.com` |
| `-f`, `--file` | File with multiple targets | `-f targets.txt` |

*Note: Either `-t` or `-f` is required*

### CVE Selection

| Argument | Description | Default | Example |
|----------|-------------|---------|---------|
| `-cve`, `--cve` | CVE(s) to test | `all` | `-cve CVE-2025-29927` |

**Available CVE Options:**
- `CVE-2025-29927`
- `CVE-2024-51479`
- `CVE-2024-34351`
- `CVE-2024-46982`
- `CVE-2025-57822`
- `CVE-2025-57752`
- `CVE-2025-55173`
- `CVE-2025-49826`
- `CVE-2025-32421`
- `CVE-2025-48068`
- `all` (tests all CVEs)

### Scan Options

| Argument | Description | Default | Example |
|----------|-------------|---------|---------|
| `--iterations` | Race condition attempts (CVE-2025-32421) | `10` | `--iterations 20` |
| `--callback` | Callback URL for SSRF (CVE-2025-57822 / CVE-2024-34351) | None | `--callback https://xxxx.oastify.com` |
| `-c`, `--concurrency` | Concurrent workers: CVEs per target, or targets in file mode | `5` | `-c 10` (or `-c 1` for sequential) |

### HTTP Options

| Argument | Description | Default | Example |
|----------|-------------|---------|---------|
| `--timeout` | Request timeout (seconds) | `15` | `--timeout 30` |
| `-k`, `--no-verify` | Disable SSL verification | False | `-k` |
| `--proxy` | HTTP/HTTPS proxy | None | `--proxy http://127.0.0.1:8080` |

### Output Options

| Argument | Description | Example |
|----------|-------------|---------|
| `-v`, `--verbose` | Show all activity (default prints findings only) | `-v` |
| `--debug` | Enable debug logging (implies `--verbose`) | `--debug` |
| `-o`, `--output` | Save results to JSON file | `-o results.json` |

> **Output modes:** by default NextJSPwn prints **findings only** (confirmed vulnerabilities) plus the end-of-scan summary. Use `-v` to see per-CVE progress, detection, and version checks; `--debug` adds raw request/response detail. With concurrency, each CVE's (or target's) output is buffered and flushed as one contiguous, severity-ordered block so parallel runs stay readable.

> **Concurrency:** `-c N` runs up to N CVE modules in parallel against a single target, or up to N targets in parallel in file (`-f`) mode. Detection/version fingerprinting runs once per target and is shared across modules. Use `-c 1` for fully sequential/stealthier scans. Wall-clock time for a single target is bounded by the slowest individual module.

---

### Continuous Security Monitoring

```bash
#!/bin/bash
# weekly_nextjs_scan.sh

TARGETS="/path/to/production_apps.txt"
OUTPUT_DIR="/var/log/security/nextjs"
DATE=$(date +%Y%m%d)

./nextjspwn.py -f $TARGETS \
  -o "$OUTPUT_DIR/scan_$DATE.json" \
  --timeout 30

# Alert if vulnerabilities found
if grep -q '"vulnerabilities": \[' "$OUTPUT_DIR/scan_$DATE.json"; then
  echo "ALERT: Vulnerabilities found!" | mail -s "NextJS Security Alert" security@company.com
fi
```

### Custom Wrapper Script

```python
#!/usr/bin/env python3
import subprocess
import json

def scan_nextjs_app(url):
    """Wrapper for NextJSPwn"""
    cmd = [
        './nextjspwn.py',
        '-t', url,
        '-o', 'temp_results.json'
    ]
    
    subprocess.run(cmd)
    
    with open('temp_results.json', 'r') as f:
        return json.load(f)

# Use in your automation
result = scan_nextjs_app('https://example.com')
if result['vulnerabilities']:
    print(f"ALERT: {len(result['vulnerabilities'])} CVEs found!")
```

---

## 📊 Output Formats

### Terminal Output

```
╔══════════════════════════════════════════════════════════════════╗
║                    NEXTJSPWN SCAN SUMMARY                        ║
╚══════════════════════════════════════════════════════════════════╝

Target:           https://example.com
Next.js Detected:  Yes
Version:           14.2.11
CVEs Tested:      3
Vulnerabilities:   1 FOUND!

Detailed Results:
──────────────────────────────────────────────────────────────────

  • CVE-2025-29927 - Middleware Authorization Bypass
    Severity: CRITICAL (CVSS 9.1)
    Status: NOT EXPLOITABLE
    Version is vulnerable

  • CVE-2025-57822 - Middleware SSRF
    Severity: MEDIUM (CVSS 6.5)
    Status: NOT EXPLOITABLE
    Version is patched

  • CVE-2025-32421 - Race Condition Information Disclosure
    Severity: MEDIUM (CVSS 5.3)
    Status: NOT EXPLOITABLE
    Version is vulnerable
```

### JSON Output

```json
{
  "target": "https://example.com",
  "cves_tested": [
    "CVE-2025-29927",
    "CVE-2025-57822",
    "CVE-2025-32421"
  ],
  "vulnerabilities": [
    {
      "cve": "CVE-2025-29927",
      "name": "Middleware Authorization Bypass",
      "severity": "CRITICAL",
      "cvss": 9.1,
      "exploitable": true,
      "bypassed_endpoints": [
        "/admin",
        "/api/users"
      ]
    }
  ],
  "version": "14.2.11",
  "is_nextjs": true
}
```

---

## 🏗️ Architecture

### Framework Structure

```
nextjspwn.py (Main Framework)
├── CVE-2025-29927/
│   └── nextjs_middleware_bypass.py
├── CVE-2025-57822/
│   ├── nextjs_ssrf_exploit.py
│   ├── README.md
│   └── examples.sh
└── CVE-2025-32421/
    └── nextjs_race_condition.py
```

### Class Diagram

```
┌─────────────────┐
│   NextJSPwn     │  (Main orchestrator)
└────────┬────────┘
         │
         ├─→ load_module()
         ├─→ test_cve_2025_29927()
         ├─→ test_cve_2025_57822()
         ├─→ test_cve_2025_32421()
         ├─→ scan_all()
         └─→ print_summary()

┌──────────────────────────────┐
│ NextJSMiddlewareBypass       │  (CVE-2025-29927)
├──────────────────────────────┤
│ - detect_nextjs()            │
│ - extract_version()          │
│ - discover_endpoints()       │
│ - test_endpoint_bypass()     │
└──────────────────────────────┘

┌──────────────────────────────┐
│ NextJSSSRFExploit            │  (CVE-2025-57822)
├──────────────────────────────┤
│ - detect_nextjs()            │
│ - extract_version()          │
│ - test_ssrf_callback()       │
│ - test_ssrf_internal()       │
└──────────────────────────────┘

┌──────────────────────────────┐
│ NextJSRaceCondition          │  (CVE-2025-32421)
├──────────────────────────────┤
│ - detect_nextjs()            │
│ - extract_version()          │
│ - discover_pages()           │
│ - test_race_condition()      │
└──────────────────────────────┘
```

### Execution Flow

```
1. Parse CLI arguments
2. Initialize NextJSPwn framework
3. For each selected CVE:
   ├─→ Load CVE module dynamically
   ├─→ Initialize exploit class
   ├─→ Run detection & version check
   ├─→ Execute vulnerability tests
   └─→ Collect results
4. Aggregate results
5. Print summary
6. Export to JSON (if requested)
```

---

## 🔬 Technical Details

### Version Detection Methods

NextJSPwn uses multiple techniques for version detection:

1. **HTTP Headers** - `X-Powered-By: Next.js`
2. **Meta Tags** - `<meta name="generator" content="Next.js 15.1.0">`
3. **JSON Objects** - `"next":{"version":"15.1.0"}`
4. **JavaScript Chunks** - Version strings in `framework-*.js`, `webpack-*.js`
5. **Build Manifests** - `/_next/static/{buildId}/_buildManifest.js`

### Vulnerability Testing Methodology

#### CVE-2025-29927 (Middleware Bypass)
1. Send normal request to endpoint
2. Send request with `X-Middleware-Subrequest` header
3. Compare responses (status codes, headers, body)
4. Check if authorization was bypassed

#### CVE-2025-57822 (SSRF)
1. Test internal targets (localhost, 169.254.169.254)
2. Send requests with malicious `Location` / `X-Middleware-Rewrite` headers
3. Check for SSRF indicators in responses
4. Test with OAST callback (if provided)

#### CVE-2025-32421 (Race Condition)
1. Send concurrent requests:
   - Request 1: `?__nextDataRequest=1`
   - Request 2: `x-now-route-matches` header
2. Check if response contains JSON pageProps instead of HTML
3. Repeat multiple iterations to trigger race condition
4. Analyze leaked data for sensitive information

---

## 🛡️ Defense & Mitigation

### For Developers

#### Update Next.js
```bash
# For Next.js 14.x
npm install next@14.2.32

# For Next.js 15.x
npm install next@15.4.7

# Or latest
npm install next@latest
```

#### Secure Middleware Configuration
```javascript
// next.config.js
module.exports = {
  poweredByHeader: false,  // Hide version
  
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }
        ]
      }
    ]
  }
}
```

#### WAF Rules

**Block CVE-2025-29927:**
```
Block requests with header: X-Middleware-Subrequest
```

**Block CVE-2025-32421:**
```
Block requests with header: x-now-route-matches
```

---

## 📚 References

- [CVE-2025-29927 - GitHub Advisory](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
- [CVE-2025-57822 - Vercel Changelog](https://vercel.com/changelog/cve-2025-57822)
- [CVE-2025-32421 - Wiz Vulnerability Database](https://www.wiz.io/vulnerability-database/cve/cve-2025-32421)
- [Next.js Security Best Practices](https://nextjs.org/docs/advanced-features/security-headers)
- [OWASP Top 10 2021](https://owasp.org/Top10/)

---

## 🤝 Contributing

Contributions are welcome! To add support for new CVEs:

1. Create a new directory: `CVE-XXXX-XXXXX/`
2. Implement exploit class with these methods:
   - `detect_nextjs()`
   - `extract_version()`
   - `check_version_vulnerable()`
   - `full_scan()`
3. Update `nextjspwn.py` to include new CVE
4. Add documentation

---

## ⚖️ Legal Disclaimer

**IMPORTANT**: This tool is provided for **authorized security testing and educational purposes only**.

- ✅ Only use on systems you own or have explicit written permission to test
- ❌ Unauthorized access to computer systems is illegal
- ⚠️ The authors are not responsible for misuse or damage

By using this tool, you agree to:
1. Obtain proper authorization before testing
2. Comply with all applicable laws and regulations
3. Use responsibly and ethically

**Unauthorized access to computer systems is a crime under:**
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Convention on Cybercrime - Europe
- Similar laws in other jurisdictions

---

## 📜 License

MIT License - See LICENSE file for details

---

## 👤 Author

**c0d3ninja**
- GitHub: [@c0d3ninja](https://github.com/c0d3ninja)
- Part of the Valhalla Security Framework

---

## 🙏 Acknowledgments

- Vercel Team for Next.js security advisories
- ProjectDiscovery for Nuclei templates
- Security researchers who discovered these CVEs
- The cybersecurity community

---

## 📞 Support

For issues, questions, or contributions:
- 📧 Open an issue on GitHub
- 💬 Join our Discord community
- 📖 Check the documentation

---

**Version**: 1.0.0  
**Last Updated**: November 11, 2025  
**Status**: ✅ Production Ready

---

*Stay secure, stay ethical, test responsibly* 🛡️

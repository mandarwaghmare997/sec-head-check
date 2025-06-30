# sec-head-check 🔒

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![Security Headers](https://img.shields.io/badge/security-headers-green.svg)](https://owasp.org/www-project-secure-headers/)

A **lightweight, open-source CLI tool** to help developers, security teams, and DevOps engineers **audit, validate, and get recommendations** on missing or misconfigured **HTTP Security Headers**.

> 🚀 **Built by [Vulnuris Security](https://vulnuris.com)** - Protecting your web assets from the headers up.

## 🎯 Problem Statement

Most web applications are shipped without secure HTTP headers, which are critical for:
- ❌ Preventing XSS, clickjacking, MIME sniffing attacks
- 🔒 Enforcing HTTPS connections
- 🛡️ Disabling client-side vulnerabilities
- 🔧 Hardening APIs and microservices

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Header Scanning** | Perform GET/HEAD requests and analyze response headers |
| ✅ **Best Practice Validation** | Check presence and correctness of security headers |
| 🧠 **Smart Recommendations** | Get actionable recommendations for missing/misconfigured headers |
| 📊 **Multiple Output Formats** | Export results in JSON, CSV, or formatted console output |
| 🔁 **Batch Processing** | Scan multiple URLs from a file |
| 🧪 **Security Scoring** | Get a security score (0-100) and letter grade (A-F) |
| 🛡️ **OWASP Compliance** | Aligned with OWASP Secure Headers Project |
| 🏗️ **CI/CD Ready** | Perfect for integration into DevOps pipelines |
| 📦 **Easy Installation** | Install via pip or run directly |
| 🌍 **Flexible URLs** | Support for domains, IPs, and localhost testing |

## 🔧 Installation

### Option 1: Install via pip (Recommended)
```bash
pip install sec-head-check
```

### Option 2: Install from source
```bash
git clone https://github.com/mandarwaghmare997/sec-head-check.git
cd sec-head-check
pip install -r requirements.txt
python setup.py install
```

### Option 3: Run directly
```bash
git clone https://github.com/vulnuris/sec-head-check.git
cd sec-head-check
pip install -r requirements.txt
python src/sec_head_check.py --help
```

## 🚀 Quick Start

### Basic Usage
```bash
# Check a single website
sec-head-check https://example.com

# Check with detailed recommendations
sec-head-check https://example.com --verbose

# Check multiple websites from a file
sec-head-check --batch urls.txt

# Get JSON output for further processing
sec-head-check https://example.com --output json

# Generate CSV report
sec-head-check --batch urls.txt --output csv > security_report.csv
```

### CI/CD Integration
```bash
# Exit with error code if security score < 70
sec-head-check https://myapp.com --ci

# Use in GitHub Actions, GitLab CI, etc.
sec-head-check $DEPLOYMENT_URL --ci --output json
```

## 📋 Checked Security Headers

| Header | Severity | Purpose |
|--------|----------|---------|
| `Content-Security-Policy` | 🔴 High | Prevents XSS attacks by controlling resource loading |
| `Strict-Transport-Security` | 🔴 High | Enforces HTTPS connections |
| `X-Frame-Options` | 🟡 Medium | Prevents clickjacking attacks |
| `X-Content-Type-Options` | 🟡 Medium | Prevents MIME type sniffing |
| `Referrer-Policy` | 🟡 Medium | Controls referrer information sent with requests |
| `Permissions-Policy` | 🟢 Low | Controls browser features and APIs |
| `X-XSS-Protection` | 🟢 Low | Legacy XSS protection (deprecated but still useful) |
| `Cross-Origin-Embedder-Policy` | 🟢 Low | Controls cross-origin resource embedding |
| `Cross-Origin-Opener-Policy` | 🟢 Low | Controls cross-origin window interactions |
| `Cross-Origin-Resource-Policy` | 🟢 Low | Controls cross-origin resource access |

## 📊 Sample Output

### Console Output (Default)
```
🔍 Security Header Analysis for https://example.com
📊 Score: 65.0/100 (Grade: D)
📅 Checked: 2024-01-15T10:30:45.123456

✅ Headers Found (4):
  ✅ X-Content-Type-Options: nosniff
  ⚠️ Content-Security-Policy: default-src 'self' 'unsafe-inline'
  ✅ X-Frame-Options: SAMEORIGIN
  ✅ Strict-Transport-Security: max-age=31536000

❌ Missing Headers (6):
  🟡 Referrer-Policy (medium severity)
  🟢 Permissions-Policy (low severity)
  🟢 X-XSS-Protection (low severity)
  🟢 Cross-Origin-Embedder-Policy (low severity)
  🟢 Cross-Origin-Opener-Policy (low severity)
  🟢 Cross-Origin-Resource-Policy (low severity)

💡 Recommendations (7):
  1. Content-Security-Policy: Remove unsafe-inline and unsafe-eval, use nonces or hashes instead
  2. Referrer-Policy: Set to strict-origin-when-cross-origin or stricter
  3. Permissions-Policy: Define specific permissions for features
  ...
```

### JSON Output
```json
{
  "url": "https://example.com",
  "status_code": 200,
  "timestamp": "2024-01-15T10:30:45.123456",
  "score": 65.0,
  "grade": "D",
  "headers_found": {
    "Content-Security-Policy": {
      "value": "default-src 'self' 'unsafe-inline'",
      "description": "Prevents XSS attacks by controlling resource loading",
      "severity": "high",
      "validation": {
        "is_valid": false,
        "issue": "CSP contains unsafe directives",
        "recommendation": "Remove unsafe-inline and unsafe-eval, use nonces or hashes instead"
      }
    }
  },
  "headers_missing": {
    "Referrer-Policy": {
      "description": "Controls referrer information sent with requests",
      "severity": "medium",
      "recommendation": "Set to strict-origin-when-cross-origin or stricter"
    }
  },
  "recommendations": [...]
}
```

## 🔧 Command Line Options

```
usage: sec-head-check [-h] [--batch BATCH] [--output {console,json,csv}] 
                      [--verbose] [--timeout TIMEOUT] [--ci] [--version] 
                      [url]

positional arguments:
  url                   URL to check (can be omitted if using --batch)

optional arguments:
  -h, --help            show this help message and exit
  --batch BATCH, -b BATCH
                        File containing URLs to check (one per line)
  --output {console,json,csv}, -o {console,json,csv}
                        Output format (default: console)
  --verbose, -v         Show detailed information and recommendations
  --timeout TIMEOUT, -t TIMEOUT
                        Request timeout in seconds (default: 10)
  --ci                  CI/CD mode: exit with non-zero code if score < 70
  --version             show program's version number and exit
```

## 🔄 CI/CD Integration Examples

### GitHub Actions
```yaml
name: Security Headers Check
on: [push, pull_request]

jobs:
  security-headers:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    - name: Install sec-head-check
      run: pip install sec-head-check
    - name: Check security headers
      run: sec-head-check https://myapp.com --ci
```

### GitLab CI
```yaml
security_headers:
  stage: test
  image: python:3.9
  script:
    - pip install sec-head-check
    - sec-head-check $CI_ENVIRONMENT_URL --ci --output json
  only:
    - main
```

### Docker
```dockerfile
FROM python:3.9-slim
RUN pip install sec-head-check
ENTRYPOINT ["sec-head-check"]
```

## 📁 Batch File Format

Create a text file with one URL per line:

```
https://example.com
https://api.example.com
https://admin.example.com
http://localhost:3000
192.168.1.100:8080
```

## 🎯 Use Cases

- **🔍 Security Audits**: Quick assessment of web application security posture
- **🏗️ DevOps Pipelines**: Automated security checks in CI/CD workflows
- **📊 Compliance Reporting**: Generate reports for security compliance frameworks
- **🎓 Security Training**: Educational tool for learning about HTTP security headers
- **🔧 Development**: Local testing during development and staging phases
- **📈 Monitoring**: Regular monitoring of production applications

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/vulnuris/sec-head-check.git
cd sec-head-check
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### Running Tests
```bash
python -m pytest tests/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [Security Headers Best Practices](https://securityheaders.com/)

## 🔗 Related Projects

- **[PhishInstinct](https://vulnuris.com/phishinstinct)** - Advanced phishing detection and prevention
- **[Vaultix](https://vulnuris.com/vaultix)** - Secure credential management platform

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/vulnuris/sec-head-check/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/vulnuris/sec-head-check/discussions)
- 📧 **Email**: contact@vulnuris.com
- 🌐 **Website**: [vulnuris.com](https://vulnuris.com)

---

**Made with ❤️ by [Vulnuris Security](https://vulnuris.com)**

*Protecting your web assets from the headers up.*

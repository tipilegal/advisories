# Security Advisories

Independent security research by **Caio Chagas**.

This repository contains vulnerability advisories for bugs I have discovered through independent security research. All vulnerabilities were reported to the respective vendors following responsible disclosure practices before public release.

---

## ChurchCRM

[ChurchCRM](https://churchcrm.io) is an open-source church management system built on PHP/Slim. The findings below were identified in **version 7.3.3** through dynamic proof-of-concept testing.

| ID | Title | CWE | Severity | CVSS 4.0 | Status |
|----|-------|-----|----------|----------|--------|
| [VULN-01](./ChurchCRM/VULN-01-credential-disclosure/) | Self-Credential Disclosure via Propel ORM Serialization | CWE-200 | Medium | 6.9 | CVE Pending |
| [VULN-02](./ChurchCRM/VULN-02-idor-person-notes/) | IDOR on Person Notes — Cross-Person Unauthorized Access | CWE-639 | Medium | 5.3 | CVE Pending |
| [VULN-03](./ChurchCRM/VULN-03-idor-family-notes/) | IDOR on Family Notes — Cross-Family Unauthorized Access | CWE-639 | Medium | 5.3 | CVE Pending |
| [VULN-04](./ChurchCRM/VULN-04-timerjobs-privesc/) | Privilege Escalation via Timer Jobs Missing Admin Authorization | CWE-269 | Medium | 5.9 | CVE Pending |
| [VULN-05](./ChurchCRM/VULN-05-ssrf-webdav/) | SSRF via WebDAV Backup Plugin — No Internal IP Filtering | CWE-918 | Medium | 5.7 | CVE Pending |
| [VULN-06](./ChurchCRM/VULN-06-idor-group-members/) | IDOR on Group Members — Mass PII Disclosure | CWE-639 | High | 7.1 | CVE Pending |
| [VULN-07](./ChurchCRM/VULN-07-finance-broad-access/) | Overly Broad Finance Data Access — Full Congregation Exposure | CWE-639 | High | 7.1 | CVE Pending |
| [VULN-08](./ChurchCRM/VULN-08-weak-reset-token/) | Cryptographically Weak Password Reset Token via uniqid() | CWE-338 | High | 7.3 | CVE Pending |
| [VULN-09](./ChurchCRM/VULN-09-legacy-sha256-hash/) | Legacy SHA-256 Password Hashing with Weak Salt | CWE-916 | High | 7.5 | CVE Pending |

### Disclosure Timeline

| Date | Event |
|------|-------|
| 2026-06-10 | Vulnerabilities discovered and confirmed |
| 2026-06-10 | Vendor notified via GitHub Security Advisories |
| TBD | CVE IDs assigned |
| TBD | Public disclosure (90-day window) |

---

## Responsible Disclosure Policy

I follow a **90-day coordinated disclosure** policy:

1. The vendor is notified privately with full technical details before any public release.
2. A 90-day window is given for the vendor to develop and release a fix.
3. If the vendor is unresponsive or the window expires, findings are published regardless.
4. Early publication may occur if a fix is released and confirmed before the 90-day window.

---

## Contact

For questions about any of these advisories, open an issue in this repository or reach out via GitHub.

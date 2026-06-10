# ChurchCRM — Security Advisories

**Product:** [ChurchCRM](https://churchcrm.io)  
**Tested version:** 7.3.3  
**Research by:** Caio Chagas  
**Disclosure date:** TBD (90-day coordinated disclosure in progress)

---

ChurchCRM is an open-source PHP church management system. The findings below were identified through static analysis of the source code and dynamic proof-of-concept testing against a local instance running version 7.3.3.

## Findings

| # | Title | CWE | Severity | CVSS 4.0 | Confirmed |
|---|-------|-----|----------|----------|-----------|
| [VULN-01](./VULN-01-credential-disclosure/) | Self-Credential Disclosure via Propel ORM Serialization | CWE-200 | Medium | 6.9 | Dynamic |
| [VULN-02](./VULN-02-idor-person-notes/) | IDOR on Person Notes | CWE-639 | Medium | 5.3 | Dynamic |
| [VULN-03](./VULN-03-idor-family-notes/) | IDOR on Family Notes | CWE-639 | Medium | 5.3 | Dynamic |
| [VULN-04](./VULN-04-timerjobs-privesc/) | Privilege Escalation via Timer Jobs | CWE-269 | Medium | 5.9 | Dynamic |
| [VULN-05](./VULN-05-ssrf-webdav/) | SSRF via WebDAV Backup Plugin | CWE-918 | Medium | 5.7 | Dynamic |
| [VULN-06](./VULN-06-idor-group-members/) | IDOR on Group Members — Mass PII Disclosure | CWE-639 | High | 7.1 | Dynamic |
| [VULN-07](./VULN-07-finance-broad-access/) | Overly Broad Finance Data Access | CWE-639 | High | 7.1 | Dynamic |
| [VULN-08](./VULN-08-weak-reset-token/) | Weak Password Reset Token via uniqid() | CWE-338 | High | 7.3 | Static |
| [VULN-09](./VULN-09-legacy-sha256-hash/) | Legacy SHA-256 Password Hashing with Weak Salt | CWE-916 | High | 7.5 | Static |

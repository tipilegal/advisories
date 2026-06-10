# Overly Broad Finance Data Access — Full Congregation Exposure

**Product:** ChurchCRM  
**Version:** 7.3.3 (earlier versions likely affected)  
**CVE:** Pending  
**CWE:** CWE-639 — Authorization Bypass Through User-Controlled Key  
**Severity:** High  
**CVSS 4.0:** 7.1 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`  
**Discovered:** 2026-06-10  
**Author:** Caio Chagas  

---

## Description

The `GET /api/payments/` endpoint returns every pledge and payment record in the database to any user holding the Finance role. No scoping by family, fund, or assigned responsibility is applied — a low-privilege finance volunteer gets the same unfiltered dataset as an administrator.

## Root Cause

`api/routes/finance/finance-payments.php` wraps the payments route group with `FinanceRoleAuthMiddleware`, which checks only that the user has the Finance role bit set. The query that backs `GET /api/payments/` fetches all records with no `WHERE` clause filtering by user scope or assignment. Role membership is treated as full data access, which is not the intended trust model for volunteer-based organizations.

## Impact

- A finance volunteer assigned to a single department or family can enumerate the complete giving history of every congregant — amounts, dates, fund designations, and pledge commitments
- This constitutes a mass exposure of sensitive financial data, which many congregation members consider deeply private
- The data is sufficient to profile individual members' financial capacity, giving patterns, and commitment levels — information that could be misused for targeted solicitation or internal politics

## Proof of Concept

```bash
# Step 1 — authenticate as a user with Finance role
curl -s -c cookies.txt -X POST "http://TARGET/churchcrm/session/begin" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "User=lowpriv&Password=lowpass123"

# Step 2 — retrieve all payment records
curl -s -b cookies.txt "http://TARGET/churchcrm/api/payments/" \
  -w "\nResponse size: %{size_download} bytes\n"
```

**Expected result:**

Response contains all pledge and payment records for all congregants. In testing, the response body exceeded 256 KB and included hundreds of individual financial records with full member details.

## Evidence

<video src="assets/vuln-7-poc.mp4" controls width="100%"></video>

## Affected Component

| Field | Value |
|-------|-------|
| Endpoint | `GET /api/payments/` |
| File | `api/routes/finance/finance-payments.php` |
| Middleware | `FinanceRoleAuthMiddleware` (role check only, no data scoping) |
| Auth required | Yes — Finance role |

## Timeline

| Date | Event |
|------|-------|
| 2026-06-10 | Vulnerability discovered and confirmed |
| 2026-06-10 | Vendor notified via GitHub Security Advisories |
| TBD | CVE ID assigned |
| TBD | Patch released |
| TBD | Public disclosure |

## Remediation

Filter the payments query by the requesting user's assigned scope — for example, restrict results to families or funds the user has been explicitly assigned to manage. Full congregation-wide access should require the Admin role, not just Finance.

## References

- [ChurchCRM source](https://github.com/ChurchCRM/CRM)
- [Affected file](https://github.com/ChurchCRM/CRM/blob/master/api/routes/finance/finance-payments.php)

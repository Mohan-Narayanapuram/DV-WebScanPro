# Milestone 3: Miscellaneous Security Checks and IDOR

This milestone expanded the scanner with additional modules for sensitive files, security headers, and access control.

## Week 5: Miscellaneous Security Checks
- Scanned for sensitive files such as `.git/`, `config.php`, and `robots.txt`.
- Tested for missing security headers (CSP, HSTS, X-Frame-Options, etc.).
- Validated checks against DVWA, confirming the presence of weaknesses.

## Week 6: IDOR & Access Control
- Implemented an IDOR testing module by manipulating identifiers in URLs.
- Attempted unauthorized access to restricted resources.
- Tested on DVWA profile endpoints, simulating privilege escalation attempts.
- Results demonstrated common access control flaws.

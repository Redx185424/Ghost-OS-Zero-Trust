GHOST OS — SHOWCASE EDITION
ACCEPTABLE USE & LEGAL NOTICE

1. PURPOSE
   Ghost OS Zero Trust Edition is a demonstration of security-tooling
   architecture: authorization gating, role-based access control, audit
   logging, passive OSINT, and reporting. It is built for education and
   portfolio purposes.

2. SCOPE OF ACTIVE MODULES
   Active modules (recon, active plugins) will ONLY execute against
   targets listed in data/allowlist.json. By default this is limited to:
     - scanme.nmap.org (the official Nmap project test target, which
       explicitly permits scanning per project policy)
     - localhost / 127.0.0.1 (your own local Docker lab — see docker/)

   Do not add any target to the allow-list that you do not own or do not
   have explicit written authorization to test. Modifying the allow-list
   to include third-party infrastructure without authorization may
   violate computer fraud and abuse laws in your jurisdiction (e.g. the
   U.S. Computer Fraud and Abuse Act, UK Computer Misuse Act, or
   equivalent local law).

3. PASSIVE MODULES
   OSINT lookups (DNS, WHOIS, certificate transparency search) and the
   header_analyzer plugin only read publicly published data, equivalent
   to what a standard web browser or command-line tool (whois, dig)
   retrieves. These are not restricted to the allow-list because they do
   not constitute unauthorized access.

4. NO EXPLOITATION CODE
   This repository does not contain, and will not accept contributions
   containing, exploit code, payload generators, credential attacks, or
   malware. That functionality is intentionally out of scope for the
   public showcase edition.

5. CONSENT & AUDIT
   Every active action requires an explicit typed consent phrase, which
   is timestamped and logged (data/audit_log.json). This exists to create
   an unambiguous authorization record and to model real-world
   penetration-testing engagement practice.

6. NO WARRANTY
   This software is provided "as is" for educational purposes, without
   warranty of any kind. The author is not responsible for misuse of
   this software, including but not limited to actions taken against
   systems the user does not own or lack authorization to test.

7. YOUR RESPONSIBILITY
   By running this software, you agree that you are solely responsible
   for ensuring you have proper authorization for any target you test,
   and for complying with all applicable laws in your jurisdiction.

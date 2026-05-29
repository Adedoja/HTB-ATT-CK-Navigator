# HTB Machine → MITRE ATT&CK Mapping

31 machines mapped to MITRE ATT&CK Enterprise v14.  
Each row documents the primary initial access vector, privilege escalation path, and all relevant ATT&CK technique IDs observed.

---

| # | Box | OS | Difficulty | Initial Access | Privilege Escalation | ATT&CK IDs | Notes |
|---|-----|----|------------|---------------|---------------------|------------|-------|
| 1 | Meow | Linux | Very Easy | Default Telnet credentials | N/A | T1046, T1133, T1110 | VPN setup, basic enumeration, Telnet exploitation via default creds |
| 2 | Fawn | Linux | Very Easy | Anonymous FTP access | N/A | T1046, T1133, T1083 | FTP misconfiguration allowing anonymous auth, file enumeration |
| 3 | Dancing | Windows | Very Easy | SMB null session | N/A | T1046, T1135, T1083 | SMB misconfigured to allow passwordless access, share enumeration |
| 4 | Redeemer | Linux | Very Easy | Unauthenticated Redis access | N/A | T1046, T1133, T1083 | Redis exposed without auth, enumerated via redis-cli |
| 5 | Explosion | Windows | Very Easy | RDP with weak/no credentials | N/A | T1046, T1133, T1110 | RDP misconfigured for unauthenticated access via xfreerdp |
| 6 | Preignition | Linux | Very Easy | Default admin credentials on web panel | N/A | T1046, T1190, T1110, T1083 | Directory fuzzing revealed admin login, default creds used |
| 7 | Mongod | Linux | Very Easy | Unauthenticated MongoDB access | N/A | T1046, T1133, T1083 | MongoDB anonymous user enabled, full DB enumeration |
| 8 | Synced | Linux | Very Easy | Anonymous Rsync access | N/A | T1046, T1133, T1083 | Rsync misconfigured for anonymous auth, file system exposed |
| 9 | Appointment | Linux | Very Easy | SQL Injection on login form | N/A | T1190, T1046, T1059 | Basic SQLi bypassed authentication on web application |
| 10 | Sequel | Linux | Very Easy | MySQL access without password | N/A | T1046, T1133, T1083 | MySQL misconfigured, enumerated via SQL queries |
| 11 | Crocodile | Linux | Very Easy | Anonymous FTP → credential harvesting → web admin panel | N/A | T1046, T1133, T1083, T1552, T1190, T1110 | FTP exposed cleartext creds, used to access hidden login endpoint |
| 12 | Responder | Windows | Very Easy | File inclusion → NetNTLMv2 capture → hash crack → WinRM | N/A | T1190, T1557, T1110, T1059 | LFI exploited with Responder to capture NTLM hash, cracked with JtR, Evil-WinRM used |
| 13 | Three | Linux | Very Easy | AWS S3 bucket misconfiguration → reverse shell upload | N/A | T1190, T1083, T1059, T1190 | Subdomain fuzzing found S3 bucket, AWS CLI used to upload and trigger reverse shell |
| 14 | Funnel | Linux | Very Easy | Anonymous FTP → credential spray → SSH → port forward → PostgreSQL | N/A | T1133, T1083, T1552, T1110, T1021, T1059 | Cleartext creds in FTP, Hydra spray, SSH tunneling to internal PostgreSQL |
| 15 | Bike | Linux | Very Easy | SSTI in Node.js Handlebars app | N/A | T1190, T1059 | Server-Side Template Injection exploited to escape sandbox and execute commands |
| 16 | Ignition | Linux | Very Easy | Default credentials on Magento admin panel | N/A | T1046, T1190, T1110, T1083 | Directory fuzzing found Magento panel, weak credentials used |
| 17 | Pennyworth | Linux | Very Easy | Default credentials on Jenkins → Groovy reverse shell | N/A | T1190, T1110, T1059 | Jenkins Script Console abused with default creds to execute Groovy code |
| 18 | Tactics | Windows | Very Easy | SMB null session (Administrator, no password) → PsExec SYSTEM shell | T1078 → SYSTEM via PsExec | T1046, T1135, T1078, T1059, T1569 | Admin SMB share accessed without password, Impacket psexec for SYSTEM shell |
| 19 | Vaccine | Linux | Very Easy | Anonymous FTP → cracked archive → SQLi → postgres shell | T1548 (sudo vi abuse) | T1133, T1083, T1552, T1110, T1190, T1059, T1548 | FTP archive cracked, SQLi for RCE, privesc via misconfigured sudo on vi |
| 20 | Oopsie | Linux | Very Easy | Broken access control → cookie manipulation → file upload → PHP shell | PATH hijacking via SUID binary | T1190, T1059, T1552, T1021, T1548 | Cookie/ID manipulation escalated guest to admin, PHP shell uploaded, SUID PATH hijack for root |
| 21 | Archetype | Windows | Very Easy | SMB exposed creds → MSSQL xp_cmdshell → reverse shell | PowerShell history → Administrator password | T1135, T1552, T1059, T1190, T1552, T1078 | SMB share exposed plaintext creds, xp_cmdshell enabled for RCE, WinPEAS found PS history with admin password |
| 22 | Unified | Linux | Very Easy | Log4Shell (CVE-2021-44228) JNDI injection | MongoDB credential reset → SSH plaintext creds | T1190, T1059, T1552, T1021 | Log4Shell exploited in UniFi, MongoDB used to reset admin password, SSH creds found in app settings |
| 23 | Included | Linux | Very Easy | LFI → TFTP reverse shell upload | LXD group privilege escalation | T1190, T1059, T1552, T1611 | LFI used to access TFTP, PHP shell uploaded, LXD container mounted host filesystem for root |
| 24 | Markup | Windows | Very Easy | XXE → SSH private key extraction | Insecure scheduled task overwrite | T1190, T1552, T1021, T1053 | XXE retrieved SSH private key, batch script with insecure permissions overwritten for privesc |
| 25 | Base | Linux | Very Easy | PHP comparison vulnerability → auth bypass → reverse shell upload | Sudo find abuse | T1190, T1059, T1552, T1548 | PHP loose comparison exploited for auth bypass, sudo find binary abused for root |

---

## ATT&CK ID Quick Reference

| ID | Technique | Tactic |
|----|-----------|--------|
| T1021 | Remote Services | Lateral Movement |
| T1046 | Network Service Discovery | Discovery |
| T1053 | Scheduled Task/Job | Persistence / Privilege Escalation |
| T1059 | Command & Scripting Interpreter | Execution |
| T1078 | Valid Accounts | Persistence / Privilege Escalation |
| T1083 | File and Directory Discovery | Discovery |
| T1110 | Brute Force | Credential Access |
| T1133 | External Remote Services | Initial Access |
| T1135 | Network Share Discovery | Discovery |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1552 | Unsecured Credentials | Credential Access |
| T1557 | Adversary-in-the-Middle | Credential Access |
| T1569 | System Services | Execution |
| T1611 | Escape to Host | Privilege Escalation |
| T1548 | Abuse Elevation Control Mechanism | Privilege Escalation |

---

*Mapped by Aayatullah Adeyemi — [Portfolio](your-portfolio-link) · [LinkedIn](https://www.linkedin.com/in/aayatullahadeyemi/)*

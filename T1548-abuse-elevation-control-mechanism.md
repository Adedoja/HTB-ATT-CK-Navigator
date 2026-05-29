# T1548 — Abuse Elevation Control Mechanism

**Tactic:** Privilege Escalation, Defense Evasion  
**Platforms:** Linux, Windows  
**Frequency in my HTB dataset:** Medium-High — observed in 4 of 25 machines  
**HTB Boxes:** Vaccine, Oopsie, Base, Archetype (PowerShell history → admin password)

---

## What it is

After gaining an initial foothold, attackers look for ways to elevate their privileges to root or SYSTEM. One of the most reliable paths on Linux is abusing misconfigured SUID binaries or sudo permissions — mechanisms that are supposed to allow controlled privilege elevation but become attack vectors when poorly configured.

Two primary sub-techniques observed across my HTB machines:

- **T1548.001 — Setuid and Setgid (SUID abuse):** Binaries with the SUID bit set run as the file owner (often root) regardless of who executes them. When a binary that can spawn a shell or execute arbitrary commands has SUID set, it can be abused to get a root shell.
- **T1548.003 — Sudo and Sudo Caching:** Misconfigured sudo rules allow a low-privilege user to run specific binaries as root. If those binaries can be used to escape to a shell (GTFOBins), full root access is achievable.

---

## How I applied this on HTB

**Vaccine (sudo vi abuse)**  
After getting a shell as the `postgres` user via SQLi and RCE, ran `sudo -l` to check sudo permissions. The output showed `postgres` could run `/usr/bin/vi` as root without a password. Used GTFOBins technique: opened vi as sudo, then escaped to a shell with `:!/bin/bash` — instant root.

**Oopsie (SUID binary PATH hijacking)**  
Enumerated SUID binaries with `find / -perm -4000 2>/dev/null`. Found a custom SUID binary that called system commands without using absolute paths. Hijacked the PATH environment variable to point to a malicious binary with the same name, which executed as root when the SUID binary ran.

**Base (sudo find abuse)**  
After gaining initial access, ran `sudo -l` and found the low-privilege user could run `/usr/bin/find` as root. Used the GTFOBins find escape: `sudo find . -exec /bin/bash \; -quit` — spawned a root shell immediately.

**Archetype (PowerShell history → admin credentials)**  
WinPEAS enumeration on the Windows machine revealed a PowerShell history file at `C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`. The file contained a previously run command with the Administrator password in plaintext — used it to authenticate as Administrator.

---

## What a SOC analyst sees

### Key log sources to monitor

| Log Source | What to look for |
|---|---|
| Linux auditd / syslog | `sudo` commands run by unexpected users, especially for binaries like vi, find, python, perl, bash |
| Sysmon (Linux) / auditd Event | Processes spawned with elevated UID (euid=0) from non-root parent |
| Windows Event ID 4688 | Process creation with elevated privileges from unexpected parent |
| Windows Event ID 4672 | Special privileges assigned to new logon |
| PowerShell history files | Sensitive commands stored in ConsoleHost_history.txt |
| EDR telemetry | Shell escape patterns: `vi` spawning `/bin/bash`, `find` with `-exec /bin/sh` |

### High-confidence detection rule (conceptual Sigma logic)

```yaml
title: Suspicious Sudo GTFOBins Execution
description: Detects common GTFOBins privilege escalation patterns via sudo — T1548.003
logsource:
  category: process_creation
  product: linux
detection:
  selection_sudo:
    Image|endswith: '/sudo'
    CommandLine|contains:
      - 'vi '
      - 'find '
      - 'python'
      - 'perl'
      - 'bash'
      - 'less '
      - 'more '
      - 'awk '
      - 'nmap'
  selection_shell_escape:
    CommandLine|contains:
      - '/bin/bash'
      - '/bin/sh'
      - '!/bin'
      - '-exec'
      - 'os.system'
      - 'os.execl'
  condition: selection_sudo and selection_shell_escape
falsepositives:
  - Legitimate admin automation scripts
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548.003
```

```yaml
title: SUID Binary Enumeration
description: Detects find commands commonly used to enumerate SUID binaries — pre-escalation recon
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: '/find'
    CommandLine|contains:
      - '-perm -4000'
      - '-perm -u=s'
      - '-perm /4000'
  condition: selection
falsepositives:
  - Security audits, legitimate admin enumeration
level: medium
tags:
  - attack.privilege_escalation
  - attack.t1548.001
```

### Indicators of compromise

- `sudo -l` executed by a non-admin user shortly after initial access
- `find / -perm -4000` or `find / -perm -u=s` in command history
- Unexpected shell spawned as child of vi, find, python, perl, awk, or similar
- Process with euid=0 spawned from a web server or database user context
- Access to PowerShell history files on Windows by non-owning users

---

## Defensive controls

| Control | Implementation |
|---|---|
| Audit sudo rules | Run `sudo -l` audit across all users — remove unnecessary sudo permissions |
| Restrict GTFOBins | Never grant sudo access to vi, find, python, perl, less, more, awk, nmap without strict necessity |
| Remove unnecessary SUID bits | Audit with `find / -perm -4000` and remove SUID from non-essential binaries |
| Use absolute paths in scripts | Prevents PATH hijacking against SUID binaries |
| PowerShell history hygiene | Set `Set-PSReadlineOption -HistorySaveStyle SaveNothing` on sensitive accounts or clear history files |
| Least privilege | Service accounts (postgres, www-data) should never have sudo access |
| auditd rules | Log all sudo executions and setuid process creations |

---

## GTFOBins reference

The following binaries appeared in my HTB machines and are commonly misconfigured. Each can be used for privilege escalation if accessible via sudo or SUID:

| Binary | Escalation method |
|---|---|
| `vi` / `vim` | `:!/bin/bash` inside editor |
| `find` | `find . -exec /bin/bash \; -quit` |
| `python` / `python3` | `python -c 'import os; os.execl("/bin/bash", "bash", "-p")'` |
| `bash` | `bash -p` (SUID), `sudo bash` |
| `perl` | `perl -e 'exec "/bin/bash";'` |
| `awk` | `awk 'BEGIN {system("/bin/bash")}'` |

Full reference: [gtfobins.github.io](https://gtfobins.github.io)

---

*Part of the [HTB MITRE ATT&CK Mapping](../README.md) project by Aayatullah Adeyemi*

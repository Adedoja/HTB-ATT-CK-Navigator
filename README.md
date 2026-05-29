# HTB MITRE ATT&CK Mapping

A threat intelligence reference built from two years of HackTheBox research. Every offensive technique applied across 31 compromised machines has been mapped to the MITRE ATT&CK framework and documented from both the attacker and defender perspective.

---

## What this is

Most CTF writeups stop at "here's how I got root." This project goes further — mapping each technique to ATT&CK, then asking: *what would a SOC analyst see in the logs?*

The goal is a reusable reference that bridges offensive security work to real-world detection engineering.

---

## Repository Structure

```
htb-mitre-attack-mapping/
├── README.md               # This file
├── navigator-layer.json    # ATT&CK Navigator layer — drop into navigator to view heatmap
├── mapping.md              # Full technique table across all 31 machines
└── techniques/             # One file per major technique: TTPs + detection notes
    ├── T1190-exploit-public-facing-app.md
    ├── T1548-abuse-elevation-control.md
    ├── T1110-brute-force.md
    └── ...
```

---

## Navigator Heatmap

Load `navigator-layer.json` at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) to explore the full interactive heatmap.

![ATT&CK Heatmap](heatmap.png)

---

## Techniques Mapped

| Tactic | Technique | ID | Frequency |
|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | Low |
| Reconnaissance | Network Service Discovery | T1046 | Very High |
| Initial Access | Exploit Public-Facing Application | T1190 | High |
| Initial Access | External Remote Services | T1133 | Medium |
| Initial Access | Brute Force | T1110 | High |
| Execution | Command & Scripting Interpreter | T1059 | Very High |
| Execution | Exploitation for Client Execution | T1203 | Medium |
| Persistence | Valid Accounts | T1078 | Medium |
| Persistence | Scheduled Task/Job | T1053 | Low |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | Medium |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 | Medium |
| Discovery | System Information Discovery | T1082 | High |
| Discovery | File and Directory Discovery | T1083 | High |
| Discovery | System Network Connections Discovery | T1049 | Low |
| Lateral Movement | Remote Services | T1021 | Medium |
| Lateral Movement | Lateral Tool Transfer | T1570 | Medium |
| Credential Access | Unsecured Credentials | T1552 | Medium |
| Credential Access | Brute Force | T1110.001 | Medium |

---

## Methodology

1. **Compromise** — Each machine was approached without hints or walkthroughs where possible
2. **Document** — Attack vectors, commands used, and observations logged during the session
3. **Map** — Each action cross-referenced against the ATT&CK Enterprise matrix
4. **Bridge** — Technique files include the offensive TTP *and* what the detection signature looks like from the SOC side

ATT&CK version: Enterprise v14  
Scoring: Technique frequency across 31 machines (1 = rare, 5 = nearly every machine)

---

## Tools Used

- **Nmap** — Network reconnaissance and service enumeration
- **Burp Suite** — Web application analysis and traffic interception
- **Kali Linux** — Primary attack platform
- **MITRE ATT&CK Navigator** — Heatmap visualization
- **Wazuh** — Detection validation in homelab environment

---

## About

Aayatullah Adeyemi — CS Senior at University of North Florida, focused on cybersecurity and defensive security engineering.

- [Portfolio](your-portfolio-link-here)
- [LinkedIn](https://www.linkedin.com/in/aayatullahadeyemi/)
- [Email](mailto:adeyemiaayatullah@gmail.com)

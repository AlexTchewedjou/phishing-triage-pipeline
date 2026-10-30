# Phishing Triage Pipeline

An end-to-end phishing **detection and response pipeline** — from a controlled simulated campaign through automated triage, IOC enrichment, SOC case management, and detection-as-code.

> ⚠️ **Defensive security lab.** See [docs/ethics-and-scope.md](docs/ethics-and-scope.md). All work is performed on infrastructure and accounts I own, using a fictional sender organization. No real brand is impersonated; captured malware is analyzed statically and never executed. All published IOCs are defanged.

## Status
🚧 **In progress** — built in phases (below).

## What this project demonstrates
- Email authentication (SPF / DKIM / DMARC) from both the attacker and defender side
- Phishing triage at scale: header forensics, URL/domain analysis, static attachment analysis
- IOC enrichment via threat-intelligence APIs (VirusTotal, URLScan.io, AbuseIPDB)
- SOC tooling: TheHive (case management), Cortex (analyzers), MISP (threat intel)
- SOAR automation (Shuffle): an automated phishing-triage playbook
- Detection-as-code: Sigma rules + Microsoft Sentinel KQL

## Architecture
_Diagram added in a later phase._

## Pipeline phases
| # | Phase |
|---|---|
| 0 | Repo scaffold & ethics scope |
| 1 | Domain + email authentication (SPF/DKIM/DMARC) |
| 2 | GoPhish simulated campaign |
| 3 | Phishing corpus collection |
| 4 | Enriched analyzer (VirusTotal / URLScan / AbuseIPDB / WHOIS / GeoIP) |
| 5 | TheHive + Cortex + MISP |
| 6 | Shuffle SOAR triage playbook |
| 7 | Detection-as-code (Sigma) |
| 8 | Microsoft Sentinel + Defender (KQL) |
| 9 | Deep-dive case studies |
| 10 | Documentation (playbook, incident report) |
| 11 | Publish |

## Repository structure


_(samples, malware, secrets, and output are kept local and git-ignored)_

## Author
**Alex Tchewedjou** — building toward SOC Analyst / Junior Cybersecurity Analyst roles in Canada.


<!--
AWINRM, WinRM hacking, Evil-WinRM alternative, Windows remote management exploitation,
Active Directory post-exploitation automation, AMSI bypass tool, ETW bypass winrm,
Lateral movement over WinRM, payload staging automation Windows, SOCKS proxy pivoting,
CTF Active Directory exploitation, credential extraction Windows pentest,
Privilege escalation Windows red team, advanced WinRM shell Ruby,
WinRM file uploader large objects, IPv6 lateral movement pentest,
Kerberos attacks, NTLM hash pass, BloodHound automation, Mimikatz staging winrm,
Defender evasion Windows Server 2019 and 2022, operational security automation,
Adversary emulation framework, offensive security research and education only,
Authorized penetration testing tooling, HackTheBox pro labs winrm use case
-->

# AWINRM  
Advanced WinRM Shell for CTFs, Red Teams, and Offensive Research
AWINRM is an operator focused WinRM framework under active development.
Features, macros, and internal behavior may evolve as the tool matures.

![status: alpha](https://img.shields.io/badge/status-alpha-orange)
![stability: experimental](https://img.shields.io/badge/stability-experimental-red)
![license: MIT](https://img.shields.io/badge/license-MIT-blue)
![tech: WinRM](https://img.shields.io/badge/tech-WinRM-darkgreen)
![ruby version](https://img.shields.io/badge/Ruby-3.0+%20required-CC342D)
![platform support](https://img.shields.io/badge/Windows%20Target-Win10%2F11%20%7C%20Server%202016--2022-important)
![protocol: winrm](https://img.shields.io/badge/Protocol-WinRM%20(HTTPS%20Preferred)-informational)
![mitre mapped](https://img.shields.io/badge/MITRE%20ATT&CK-Mapped%20Techniques-blueviolet)
![osint safe](https://img.shields.io/badge/OPSEC-Stage%20in%20memory%20(no%20disk)-lightgrey)
![artifact control](https://img.shields.io/badge/Loot-Auto%20extraction%20enabled-green)
![ctf optimized](https://img.shields.io/badge/Mode-CTF%20Optimized-brightgreen)


> Alpha release — experimental automation modules.  
> Use only where you have **explicit written authorization**.

```
 █████╗ ██╗    ██╗██╗███╗   ██╗██████╗ ███╗   ███╗
██╔══██╗██║    ██║██║████╗  ██║██╔══██╗████╗ ████║
███████║██║ █╗ ██║██║██╔██╗ ██║██████╔╝██╔████╔██║
██╔══██║██║███╗██║██║██║╚██╗██║██╔══██╗██║╚██╔╝██║
██║  ██║╚███╔███╔╝██║██║ ╚████║██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝

                   AWINRM OPERATOR SHELL
```
---

## Background and Purpose

AWINRM was built from real operator struggles inside enterprise Active Directory environments.  
While traditional WinRM tooling works, real redteam operations face friction:

- Broken or slow uploads for large binaries  
- In memory execution blocked by AMSI/ETW  
- Instability around PowerShell language modes  
- Weak automation for enumeration and credential gathering  
- IPv6 lateral movement poorly supported  
- Repetitive staging steps harming OPSEC  

AWINRM directly addresses these issues through its operator centric workflow system, staging subsystem, and built-in bypass modules.

Designed for:

- CTF challenge assault paths (Kerberoast → lateral movement → LSASS access)
- HTB Pro Labs enterprise engagements
- High fidelity red-team simulations

---

## Key Features Summary

- Automated AMSI bypass and ETW disruption  
- Reliable file staging for large binaries  
- Architecture-aware tooling (x86/x64)
- Command macros for AD recon and exploitation  
- SOCKS proxy tunneling for pivot operations  
- Auto-loot heuristics for credentials, flags, tokens  
- Optional banner-based situational awareness  
- Stealth upload mode with ADS storage support  
- Built-in IPv6 probing and fallback support  
- Workflow persistence and command history logging  

Output is stored locally in the **loot/** directory for offline analysis.

---

## Banner System

AWINRM features two situational awareness modes:

Minimal banner (default):  
• Fast execution in CTF environments  
• Summarizes privileges, EDR state, local flags  

Expand banner mode:  
Provides high depth assessment including:

- Live SQL/MSSQL instance detection  
- Kerberos misconfiguration checks  
- Patch state indicators  
- Lateral movement suggestions  
- Trust relationship scan summary  
- Privilege escalation scoring  

Run expanded banner like this:
```bash

ruby bin/evil-ctf.rb -i 10.10.10.10 -u Administrator -p Passw0rd! --banner expanded
```
Operators receive active decision guidance for next-step exploitation.

---

## AMSI and ETW Bypass Automation

AWINRM provides automated in memory defenses against common blue-team controls:

- AMSI bypass using runtime patching
- ETW neutralization against script tracing
- Avoids touching disk or modifying registry
- Supports fallback manual execution
- Updated for modern Windows 10 / Windows Server builds

Execution can be toggled or invoked by operator preference.

---

## Tool Auto Staging System

Automatically deploys common offensive tools for credential harvesting, domain enumeration, and privilege escalation.

Supported tool families:

- SharpHound  
- Rubeus  
- PowerView / PowerSploit modules  
- Mimikatz  
- WinPEAS  
- Seatbelt  
- Inveigh  
- ProcDump  
- SSH / tunneling helpers  
- Nishang scripts  

Features:

- Architecture aware staging
- Chunked or XOR-encoded uploads
- Alternate Data Stream support
- Randomized filenames for OPSEC
- Tool registry with version mapping

Artifacts stored in:

loot/creds.json  
loot/loot.txt  

---

## Reconnaissance and Attack Macros

Streamlined workflows to accelerate exploitation:

- Kerberoasting automation
- Domain recon bundles
- Credential and token dumping
- LSASS extraction and secure download
- SharpHound collection
- SOCKS tunneling initialization
- Local and domain privilege assessment
- Automated discovery of lateral access paths

Designed for both rapid CTF wins and full domain takeover scenarios.

---
## Installation

AWINRM requires **Ruby 3.0+** and **Bundler**.

```bash
bundle install
```

### Gemfile

```
# Gemfile (updated for Ruby 3.2+)

source 'https://rubygems.org'

gem 'winrm', '~> 2.3.9'          # WinRM client, fully compatible with Ruby 3.x
gem 'socksify', '~> 1.8.1'       # TCP‑Socks proxy support
gem 'concurrent-ruby', '~> 1.2.0'
gem 'net-smtp', '~> 0.3.4'
gem 'rubyzip', '~> 2.0'

# Bundler itself
gem 'bundler', '~> 2.4.0'

```

Ruby’s standard library covers the remaining imports (optparse, ipaddr, socket, fileutils, etc.).

---
## Usage Guide

Basic authentication:  
```bash
ruby bin/evil-ctf.rb -i 10.10.10.10 -u Administrator -p Welcome1!
```
Pass-the-Hash:  
```bash
ruby evil-ctf.rb -i HOST -u USER -H NTLM_HASH)
```
TLS encrypted transport:  
```bash
ruby evil-ctf.rb -i HOST --ssl -u USER -p PASS)
```
SOCKS proxy pivot:  
```bash
ruby evil-ctf.rb -i HOST --socks 127.0.0.1:1080 -u USER -p PASS)
```
Execute staging macro:  
```bash
tool all
```
Dump credentials:  
```bash
dump_creds
```
Domain reconnaissance:  
```bash
dom_enum
```
Operators can chain execution across multiple remote hosts for campaign automation.

---

## Project Structure

AWINRM  
bin/evil-ctf.rb          CLI entry point  
lib/evil_ctf/banner.rb   Banner and recon information  
lib/evil_ctf/enums.rb    Enumeration systems  
lib/evil_ctf/session.rb  Interactive shell and workflow engine  
lib/evil_ctf/tools.rb    Tool registry and auto staging rules  
lib/evil_ctf/uploader.rb File transfer implementation  
loot/                    Local credential and artifact storage  
profiles/                YAML configuration for stealth workflows  
README.md                Framework documentation  
LICENSE                  Legal terms  

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Purpose in AWINRM |
|--------|-----------|----|-----------------|
| Execution | PowerShell | T1059.001 | Remote in memory command execution |
| Execution | In-Memory Execution | T1620 | Run payloads without touching disk |
| Lateral Movement | WinRM | T1021.006 | Movement across Active Directory hosts |
| Credential Access | Credential Dumping | T1003 | Extract stored secrets for escalation |
| Credential Access | LSASS Memory Dumping | T1003.001 | Token/credential recovery from LSASS |
| Credential Access | Pass-the-Hash | T1550.002 | Authenticate without cleartext passwords |
| Credential Access | Kerberoasting | T1558.003 | Harvest TGS tickets for offline cracking |
| Discovery | Account Discovery | T1087 | Identify exploitable users and roles |
| Discovery | Network/Host Discovery | T1016 | Identify lateral access opportunities |
| Command and Control | Application Protocol: HTTPS | T1071.001 | Covert, encrypted operator traffic |
| Defense Evasion | AMSI Bypass | T1562.001 | Block script scanning and signature checks |
| Defense Evasion | ETW Disable | T1562.002 | Prevent telemetry capture/analysis |

---

## Contribution Policy

Enhancements are welcome on:
  
- stealth workflow automation  
- advanced credential extraction techniques  
- stability enhancements
- tools to be autostaged 

All pull requests must include full documentation and test coverage.

---

<!--
AWINRM Hidden SEO Footer Block  
Keywords: AWINRM, Advanced WinRM Shell, WinRM post-exploitation, Active Directory exploitation, credential dumping automation, Kerberoasting toolkit, Ruby WinRM client, LSASS dumping, red team operations tool, Windows lateral movement automation, bypass AMSI ETW, HackTheBox Pro Labs tools, stealth file staging, SOCKS pivot Windows, offensive security automation, domain privilege escalation research  
This comment is intentionally hidden from README rendering.
-->
## Acknowledgements

AWINRM draws initial inspiration from the WinRM interface established by  
[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) by @Hackplayers.

This project expands upon the baseline WinRM interaction model, adding modular tooling, macro workflows, AMSI/ETW bypass automation, and operator-focused enhancements.

Credit is due to:

- Original Evil-WinRM authors  
- BloodHound / SharpHound developers  
- GhostPack maintainers  
- PowerShellMafia (PowerView/PowerSploit)  
- Inveigh and Nishang maintainers  
- Sysinternals (ProcDump)

---
## Legal and Ethical Notice

AWINRM is provided strictly for:

- authorized penetration testing  
- approved red-team missions  
- CTF participation  
- security improvement research  

Unauthorized deployment on systems without explicit permission is illegal.

All responsibility for ethical and lawful use lies solely with the operator.


<!--
AWINRM Offensive Security Framework SEO Footer
Do not remove - Invisible Ranking Enhancer

Primary Keywords:
AWINRM, WinRM post exploitation framework, Advanced WinRM shell,
Windows Remote Management command shell, Evil-WinRM alternative,
Active Directory exploitation toolkit, AD lateral movement automation,
Windows credential dumping automation, Kerberoasting automation,
Pass-the-hash tooling Ruby, LSASS extraction pentest tool,
PowerShell AMSI bypass, ETW event tracing bypass,
HTB WinRM exploitation, CTF red team automation,
Operational security stealth uploads, file staging Windows,
IPv6 lateral movement tool, SOCKS pivot Windows,
OpSec safe Windows pentesting tool, enterprise red teaming operations,
Unauthorized use prohibited, security research and ethical hacking only

Secondary Keywords:
BloodHound automation WinRM, token extraction Windows, payload delivery Windows,
Rubeus auto staging, Mimikatz automation tool, Inveigh tooling WinRM,
PowerView enumeration automation, SeImpersonate privilege escalation,
Windows Server 2016 2019 2022 exploitation tools,
Blue team evasion, adversary emulation tooling, Ruby offensive tooling

Search Intent Targeting:
active directory shell tool
how to bypass AMSI WinRM
WinRM upload large files fails solution
pass the hash winrm ruby
ETW bypass powershell invoke
AD lateral movement winrm tools
CTF HackTheBox winrm vulnerable machines
HTB RastaLabs winrm post exploitation automation

Legal:
Educational use only, cyber ranges, explicit authorization required,
Operator assumes all legal and ethical responsibility.
-->


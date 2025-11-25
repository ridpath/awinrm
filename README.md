# AWINRM
### Advanced WinRM Shell for CTFs, Red Teams, & Offensive Research

AWINRM is an operator‑focused WinRM framework under active development.  
Features, macros, and internal behavior may evolve as the tool matures.

> 🚧 **ALPHA NOTICE**: AWINRM is under **active development**. Expect breaking changes, experimental syntax, and rapid iteration. Not yet production safe. Ideal for red team labs, research, or prototyping offensive techniques.
![status: alpha](https://img.shields.io/badge/status-alpha-orange)



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


---

## Background & Project Origin

AWINRM began as an effort to address consistent operational challenges encountered during Active Directory exploitation and red‑team training scenarios, particularly throughout HackTheBox Pro Labs such as **P.O.O.**, **RastaLabs**, **Zephyr**, **Dante** and similar AD enterprise environments.

Recurring pain points included:

* Unreliable tool staging  
* WinRM upload failures on large binaries  
* Lack of IPv6 handling  
* AMSI & ETW blocking essential operator tooling  
* Repetitive steps for recon and credential collection  
* Inconsistent PowerShell behavior across systems  
* Limited automation for enumeration and stealth workflows  

AWINRM was designed to solve these practical issues using real‑world operator workflows as the foundation. Over time, the project evolved into a feature‑rich WinRM shell with its own architecture, tooling subsystem, bypass modules, and workflow automation.

---

## Key Features

### Banner System (Minimal & Expanded Modes)

AWINRM now features two banner modes:

Minimal (default):
Optimized for CTFs. Displays a fast summary of core recon data, privileges, AV/EDR state, and performs a quick flag scan.

Expanded (--banner expanded):
Shows advanced recon including MSSQL information, patch state, risk scores, and live attack suggestions.

Run expanded banner like this:
```

ruby bin/evil-ctf.rb -i 10.10.10.10 -u Administrator -p Passw0rd! --banner expanded
```


Both modes gather extensive intelligence automatically:

Hostname, domain, and logged-in user

Architecture and OS version

PowerShell language mode

AV & Defender status

SeDebug / SeImpersonate privilege detection

UAC level and integrity context

IPv6 support and current sessions

Transport type, port, and SSL usage

Credential type (hash/password)

Random name generation / stealth mode / webhook status

Loot summary (total files + JSONs)

PowerShell version

System uptime, CPU & RAM usage

Expanded Banner also includes:

MSSQL detection with:

SQL version

Current SQL user

Available databases

Linked servers

Patch status checks:

MS17-010 (EternalBlue)

MS14-068 (Kerberos)

MS08-067 (NetAPI)

Security & risk scoring:

Auto-evaluates privilege level

Explains possible attack paths

Suggests recon or exploitation actions

Evaluates LSASS access, UAC bypass, lateral movement

Trust relationships:

Domain trust info

Shadow copies and GPO discovery

### AMSI & ETW Bypass Automation
- In‑memory AMSI patching  
- ETW provider neutralization  
- Automatic or manual invocation  
- Updated for modern Windows 10/11 and Server environments

### Tool Auto‑Staging Framework
Automates fetching, staging, and extracting common operator tools:
- SharpHound (BloodHound Collector)  
- Rubeus  
- PowerView  
- Mimikatz  
- WinPEAS  
- Seatbelt  
- Inveigh  
- ProcDump (arch‑aware)  
- Nishang modules  
- Plink  
- SOCKS/port‑forwarding utilities  

Capabilities:
- ZIP extraction  
- Architecture detection  
- Randomized filenames  
- ADS (Alternate Data Stream) staging for stealth

## SOCKS Proxy Support
```
--socks 127.0.0.1:1080
```


### Enhanced File Operations
- Chunked Base64 uploads for large binaries  
- Reliable downloads  
- Optional XOR encoding  
- Remote ZIP extraction  
- Multi‑step file validation  

### Automated Loot Extraction
Detects common output patterns:
- CTF style flags  
- credentials  
- NTLM/LM hashes  
- JWTs  
- tokens  
- passwords  
- email/password pairs  
- base64 blobs  
- Kerberos artifacts  
- SSH/private key material  

Artifacts saved to:
```
loot/loot.txt
loot/creds.json
```

Optional webhook support is available.

### Recon and Attack Macros
Predefined operator workflows:
- Kerberoasting  
- PowerView domain enumeration  
- LSASS dumping  
- Credential harvesting  
- Inveigh  
- Nishang scans  
- SOCKS proxy initialization  
- SharpHound collection  
 

### Operator & Workflow Enhancements
- automatic flag/user/root detection  
- IPv6 alias handling  
- session logging  
- persistent history  
- local shell escapes (`!bash`)  
- multi‑host execution workflows  

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

# Usage Examples

## Basic authentication
```
ruby bin/evil-ctf.rb -i 10.10.10.10 -u Administrator -p Welcome1!
```

## Pass-the-Hash
```
ruby bin/evil-ctf.rb -i 10.10.10.10 -u Administrator -H <NTLM_HASH>
```

## HTTPS transport
```
ruby bin/evil-ctf.rb -i host.local --ssl -u user -p pass
```

## SOCKS proxy pivot
```
ruby bin/evil-ctf.rb -i 192.168.5.20 --socks 127.0.0.1:1080 -u svc -p Winter2025
```

## Stage all tools
```
tool all
```

## Dump credentials
```
dump_creds
```

## Dump LSASS
```
lsass_dump
```

## Domain recon
```
dom_enum
```

---

# Project Structure

```
AWINRM/
 ├── bin/evil-ctf.rb          # CLI entry point
 ├── lib/evil_ctf              # Core modules
 │   ├── banner.rb            # Banner & system info
 │   ├── enums.rb             # Enumeration presets
 │   ├── session.rb           # Session loop & command handling
 │   ├── shell_wrapper.rb     # WinRM connection helpers
 │   ├── tools.rb             # Tool registry & macros
 │   └── uploader.rb          # File upload/download utilities
 ├── loot/                    # Collected artifacts
 ├── profiles/                # YAML configuration profiles
 ├── README.md                 # This document
 └── LICENSE
```

---

# Legal and Ethical Notice

AWINRM is intended for:

- authorized penetration testing  
- red-team operations  
- defensive research  
- CTF and training environments  

Unauthorized use on systems without permission is illegal.  
AWINRM is provided without warranty, and the authors assume no liability for misuse.

---

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

# Contributions
Development will continue with new automation, tooling integrations, and operational improvements.


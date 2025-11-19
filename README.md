# AWINRM
### Advanced WinRM Shell for CTFs, Red Teams, and Offensive Research 
AWINRM is an operator focused WinRM framework under active development.  
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

## Background & Project Origin

AWINRM began as an effort to address consistent operational challenges encountered during Active Directory exploitation and red-team training scenarios, particularly throughout HackTheBox Pro Labs such as **P.O.O.**, **RastaLabs**, **Zephyr**, **Dante**, and similar AD enterprise environments.

Recurring pain points included:

- unreliable tool staging  
- WinRM upload failures on large binaries  
- lack of IPv6 handling  
- AMSI and ETW blocking essential operator tooling  
- repetitive steps for recon and credential collection  
- inconsistent PowerShell behavior between systems  
- limited automation for enumeration and stealth workflows  

AWINRM was designed to solve these practical issues using real-world operator workflows as the foundation. Over time, the project evolved into a feature-rich WinRM shell with its own architecture, tooling subsystem, bypass modules, and workflow automation.

---

# Key Features

## AMSI and ETW Bypass Automation 
- In-memory AMSI patching  
- ETW provider neutralization  
- Automatic or manual invocation  
- Updated for modern Windows 10/11 and Server environments

## Tool Auto-Staging Framework
Automates fetching, staging, and extracting common operator tools:

- SharpHound  
- Rubeus  
- PowerView  
- Mimikatz  
- WinPEAS  
- Seatbelt  
- Inveigh  
- ProcDump (arch-aware)  
- Nishang modules  
- Plink  
- SOCKS/port-forwarding utilities  

Capabilities:
- ZIP extraction  
- Architecture detection  
- Randomized filenames  
- ADS (Alternate Data Stream) staging for stealth

## SOCKS Proxy Support
```
--socks 127.0.0.1:1080
```

## Enhanced File Operations
- Chunked Base64 uploads for large binaries  
- Reliable downloads  
- Optional XOR encoding  
- Remote ZIP extraction  
- Multi-step file validation  

## Automated Loot Extraction
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

## Recon and Attack Macros
Predefined operator workflows:

- Kerberoasting  
- PowerView domain enumeration  
- LSASS dumping  
- Credential harvesting  
- Inveigh  
- Nishang scans  
- SOCKS proxy initialization  
- SharpHound collection  

## Session Intelligence Banner
Automatically collects:

- hostname and domain  
- OS version and architecture  
- active sessions  
- UAC configuration  
- Defender/AV status  
- PowerShell language mode  
- transport details  
- loot counts  
- tool staging status  

## Operator & Workflow Enhancements
- automatic flag/user/root detection  
- IPv6 alias handling  
- session logging  
- persistent history  
- local shell escapes (`!bash`)  
- multi-host execution workflows  

---

# Installation

AWINRM requires **Ruby 3.0+** and **Bundler**.

Install dependencies:

```
bundle install
```

### Gemfile

```
source 'https://rubygems.org'

gem 'winrm'
gem 'winrm-fs'
gem 'socksify'
gem 'concurrent-ruby'
gem 'rubyzip'
```

Ruby’s standard library covers the remaining imports (optparse, ipaddr, socket, fileutils, etc.).

---

# Usage Examples

## Basic authentication
```
ruby awinrm.rb -i 10.10.10.10 -u Administrator -p Welcome1!
```

## Pass-the-Hash
```
ruby awinrm.rb -i 10.10.10.10 -u Administrator -H <NTLM_HASH>
```

## HTTPS transport
```
ruby awinrm.rb -i host.local --ssl -u user -p pass
```

## SOCKS proxy pivot
```
ruby awinrm.rb -i 192.168.5.20 --socks 127.0.0.1:1080 -u svc -p Winter2025
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
 ├── awinrm.rb
 ├── tools/
 ├── loot/
 ├── profiles/
 ├── README.md
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


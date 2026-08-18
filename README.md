# AWINRM

**Advanced WinRM Shell for CTFs, Red Teams, and Offensive Research**

AWINRM is an operator-focused WinRM post-exploitation framework written in Ruby — an alternative to [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) with built-in tool staging, macro workflows, AMSI/ETW bypass automation, stealth file transfer, and automatic loot extraction.

![status: alpha](https://img.shields.io/badge/status-alpha-orange)
![license: MIT](https://img.shields.io/badge/license-MIT-blue)
![ruby version](https://img.shields.io/badge/Ruby-3.0%2B-CC342D)
![protocol: winrm](https://img.shields.io/badge/Protocol-WinRM%20(HTTPS%20Preferred)-informational)
![mitre mapped](https://img.shields.io/badge/MITRE%20ATT&CK-Mapped%20Techniques-blueviolet)

> **Alpha software — use only where you have explicit written authorization.**
> See [Legal and Ethical Notice](#legal-and-ethical-notice).

```
 █████╗ ██╗    ██╗██╗███╗   ██╗██████╗ ███╗   ███╗
 ██╔══██╗██║    ██║██║████╗  ██║██╔══██╗████╗ ████║
 ███████║██║ █╗ ██║██║██╔██╗ ██║██████╔╝██╔████╔██║
 ██╔══██║██║███╗██║██║██║╚██╗██║██╔══██╗██║╚██╔╝██║
 ██║  ██║╚███╔███╔╝██║██║ ╚████║██║  ██║██║ ╚═╝ ██║
 ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝

                    AWINRM OPERATOR SHELL
```

## Why AWINRM

Traditional WinRM tooling works, but real operations run into friction:

- Broken or slow uploads for large binaries
- In-memory execution blocked by AMSI/ETW
- Instability around PowerShell language modes
- Manual, repetitive staging that harms OPSEC
- Weak automation for enumeration and credential gathering
- Poor IPv6 lateral-movement support

AWINRM addresses these with an operator-centric workflow: connect → situational banner → automatic bypasses → staged tooling → macro-driven recon/dumping → auto-extracted loot.

## Requirements

- **Ruby 3.0+** (developed on 3.3; CI tests 3.2, 3.3, and 4.0; the rubocop config targets Ruby 4.0 compatibility)
- **Bundler**
- Network access to the target's WinRM endpoint (5985 HTTP / 5986 HTTPS)

## Installation

```bash
git clone https://github.com/ridpath/awinrm.git
cd awinrm
bundle install
```

All runtime dependencies are declared in the [Gemfile](Gemfile) (`winrm`, `winrm-fs`, `concurrent-ruby`, `ffi`, `gssapi`, `logging`, `nori`, `ostruct`, `readline`, `rubyzip`, `socksify`, `syslog`, `colorize`, plus test/dev gems).

### Entry points

Any of the following start the same CLI:

```bash
ruby bin/evil-ctf.rb --help     # canonical entry point
./evil-ctf --help               # wrapper (uses bundle exec automatically)
ruby evil-ctf.rb --help         # root-level shim
```

## Quick Start

```bash
# Basic authentication
./evil-ctf -i 10.10.10.10 -u Administrator -p Welcome1!

# Pass-the-Hash (NTLM)
./evil-ctf -i 10.10.10.10 -u Administrator -H aad3b435b51404eeaad3b435b51404ee

# TLS / HTTPS (port 5986 by default with --ssl)
./evil-ctf -i 10.10.10.10 --ssl -u Administrator -p Welcome1!

# Kerberos
./evil-ctf -i 10.10.10.10 -u administrator -k --realm DOMAIN --keytab admin.keytab

# Load a saved profile
./evil-ctf --profile default

# List the tool catalog without connecting
./evil-ctf --list-tools
```

## CLI Reference

| Flag | Description |
|------|-------------|
| `-i, --ip IP` | Target IP / hostname |
| `-u, --username USERNAME` | Username |
| `-p, --password PASSWORD` | Password |
| `-H, --hash HASH` | NTLM hash (pass-the-hash) |
| `-k, --kerberos` | Use Kerberos authentication |
| `--realm REALM` | Kerberos realm |
| `--keytab FILE` | Kerberos keytab |
| `--port PORT` | Port (default: 5985, or 5986 with `--ssl`) |
| `--ssl` | Use HTTPS transport |
| `--hosts FILE` | Multi-host file for campaign execution |
| `--ipv6 IP,HOSTNAME` | Map IPv6 address to hostname in `/etc/hosts` (requires sudo) |
| `--socks HOST:PORT` | Route the session through a SOCKS proxy |
| `--profile NAME` | Load a profile from `profiles/*.yaml` or `config/profiles.yaml` |
| `--banner MODE` | Situational banner: `minimal` (default) or `expanded` |
| `--tui` | Launch the interactive TTY-based dashboard UI |
| `--stealth` | ADS staging + random filenames |
| `--xor-key KEY` | XOR-encode staged uploads (hex or decimal key) |
| `--random-names` | Randomize remote filenames |
| `--staging-path DIR` | Remote tool staging directory (default `C:\Users\Public`; also settable via the `staging_path:` profile key) |
| `--auto-evasion` | Auto-disable Defender real-time protection on connect |
| `--auto-exec` | Auto-execute staged tools after staging |
| `--beacon` | Insert a sleep delay between remote commands (lower activity rate) |
| `--webhook URL` | POST extracted loot to a webhook |
| `--log FILE` | Append command output to a file |
| `--log-session` | Enable structured session logging under `log/` |
| `--enum TYPE` | Run an enumeration preset on connect (`basic`, `deep`, `sql`, …) |
| `--fresh` | Bypass the enumeration cache |
| `--user-agent AGENT` | Custom User-Agent for WinRM HTTP requests |
| `--no-verify` | Skip connection validation |
| `--list-tools` | Print the tool catalog and exit |
| `--debug` | Pass `debug: true` to the WinRM client |
| `-h, --help` | Show help |

## The Interactive Shell

On connect, AWINRM runs the optional banner, applies configured bypasses, and drops you into a prompt. Anything that is not a built-in command is expanded (macro → alias) and sent to the remote as PowerShell.

### Built-in commands

| Command | Description |
|---------|-------------|
| `help` | Show this command reference |
| `clear` | Clear the screen |
| `tools` | List the dynamic tool registry |
| `tool <name>` / `tool all` | Stage one tool / stage all available tools |
| `download_missing` | Download all missing tools into `./tools` |
| `fileops` | File operations menu (upload / download / ZIP) |
| `enum [type]` | Run an enumeration preset (`basic`, `deep`, `sql`, …) |
| `dump_creds` | Stage Mimikatz and dump logon passwords |
| `lsass_dump` | Stage ProcDump and dump LSASS into `./loot` |
| `bypass-4msi` | Apply the AMSI bypass |
| `bypass-etw` | Apply the full ETW bypass |
| `disable_defender` | Disable Defender real-time protection |
| `get-unquotedservices` | List unquoted service paths (privesc check) |
| `load_ps1 <local.ps1>` | Upload and dot-source a local PowerShell script |
| `invoke-binary <local.bin> [args]` | Upload and execute a local binary |
| `services` / `processes` / `sysinfo` | Remote service / process / system info |
| `history` / `history clear` | Show or clear command history |
| `validate macros [names...]` | Statically validate macros without executing |
| `validate aliases [names...]` | Statically validate aliases without executing |
| `profile save <name>` | Save the current options as a profile |
| `!sh` / `!bash` | Spawn a local shell |
| `exit` / `quit` | Close the session |

### Shell aliases

`ls`/`dir` → `Get-ChildItem`, `ps` → `Get-Process`, `whoami` → `$env:USERNAME`, `pwd` → `Get-Location`, `cd` → `Set-Location`, `rm` → `Remove-Item`, `cat` → `Get-Content`, `mkdir` → `New-Item`, `cp`/`mv` → `Copy-Item`/`Move-Item`.

### Macros

Macros are multi-step workflows (bypass → stage → execute). Type the macro name at the prompt; required tools are staged automatically.

| Macro | Does | Stages |
|-------|------|--------|
| `dump_creds` | Mimikatz `sekurlsa::logonpasswords` | mimikatz |
| `cred_harvest` | Mimikatz logonpasswords + `lsadump::sam` | mimikatz |
| `lsass_dump` | ProcDump LSASS to `C:\Users\Public` | procdump |
| `kerberoast` | Rubeus `kerberoast` with hash output file | rubeus |
| `rubeus_klist` | Rubeus `klist` (ticket cache) | rubeus |
| `sharphound_all` | SharpHound `-c all` | sharphound |
| `seatbelt_all` | Seatbelt `-group=all` | seatbelt |
| `dom_enum` / `powerview_all` | PowerView domain enumeration | powerview |
| `inveigh_start` | Start Inveigh spoofing | inveigh |
| `socks_init` | Invoke-SocksProxy bind on port 1080 | socksproxy |
| `nishang_rev` | Nishang reverse connection | nishang |
| `invoke-mimikatz` | PowerSploit `Invoke-Mimikatz` | — |
| `bypass-4msi` / `bypass-etw` | Standalone bypass primitives | — |

Macros support placeholder substitution (`[AttackerIP]`, `[AttackerPort]`, `[NishangRevRemote]`, `[InveighRemote]`) — see `validate macros --attacker-ip/--attacker-port` for static checks.

## Situational Banner

**Minimal** (default) — fast CTF-mode summary: user, privileges (potato-attack indicators), EDR/Defender state, local flags.

**Expanded** — deeper assessment: patch level, Kerberos misconfiguration signals, SQL instance discovery, lateral-movement suggestions, privilege-escalation scoring:

```bash
./evil-ctf -i 10.10.10.10 -u user -p Pass --banner expanded
```

Pass `--tui` to get the full interactive dashboard (menu-driven, live upload progress, command queue) instead of the readline prompt.

## Bypass Automation

- **AMSI** — in-memory patching (`bypass-4msi` / `--auto-evasion` paths), no disk or registry changes
- **ETW** — script-tracing neutralization (`bypass-etw`)
- **Defender** — optional real-time protection disable on connect (`--auto-evasion` / `disable_defender`)

Macro workflows apply the relevant bypasses automatically before tool execution.

## Tool Staging

Built-in catalog (see `--list-tools` for the live list):

- **Recon** — SharpHound, PowerView, Seatbelt, Nishang
- **Privilege** — Mimikatz, Rubeus, Inveigh, ProcDump, WinPEAS, Invoke-Mimikatz
- **Pivot** — Invoke-SocksProxy, Plink, EDR-Redir V2

Staging features:

- Architecture-aware selection (x86/x64)
- Chunked and XOR-encoded uploads for large binaries
- Alternate Data Stream storage (`--stealth`)
- Randomized remote filenames (`--random-names` / `--stealth`)
- Configurable remote staging directory (`--staging-path` / `staging_path:` profile key) to avoid the high-visibility `C:\Users\Public` default
- Tool registry with metadata sidecars (`tools/**/*.yml`) and version mapping

Missing tools download into `./tools` via `download_missing`.

## File Transfer & Alternate Data Streams

Use the `fileops` menu inside a session for upload / download / ZIP operations. The chunked uploader (`lib/evil_ctf/uploader`) is built for large objects over WinRM, with an SMB fallback path where available.

**Stealth upload via ADS** — store payloads in a hidden stream attached to an existing file:

1. From the `fileops` menu, choose **Upload file**.
2. For the remote destination use the form `C:\Users\Public\target.txt:adsname`.
3. Verify on the target:

```powershell
Get-Content -Path 'C:\Users\Public\target.txt:adsname'
[System.IO.File]::ReadAllBytes('C:\Users\Public\target.txt:adsname')
```

> The base file must exist before uploading to its ADS. ADS paths can also be downloaded through `fileops`.

## Loot System

Extraction is automatic: credential patterns, flags, and tokens are scanned from command output as you work.

- `loot/loot.txt` — plain-text matches (append-only)
- `loot/creds.json` — structured credential JSON (deduplicated)
- `--webhook URL` — POST loot to a webhook in real time
- `--log FILE` / `--log-session` — command output and structured session logs

## IPv6 Lateral Movement

1. Map the address to a hostname (requires sudo; backs up `/etc/hosts`, idempotent):

```bash
sudo ./evil-ctf --ipv6 fd00:1234:5678::10,Old-W10
```

2. Connect using the hostname:

```bash
./evil-ctf -i Old-W10 -u user -p Pass
```

3. Verify: on the target, `Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 5985 }`; on your box, `ss -6 dst fd00:1234:5678::10`.

Zone indexes (`fd00::10%enp130s0`) are stripped before the hosts-file mapping. Repeat `--ipv6` for additional hosts.

## Profiles

Profiles save connection + behavior options as YAML:

- Built-in: `config/profiles.yaml`
- User: `profiles/*.yaml` (gitignored — keep credentials out of the repo)

```bash
./evil-ctf --profile default             # load from the CLI (built-in or user profile)
profile save mylab                       # save current options from the shell
```

Only safe keys are persisted (secrets like `:password`/`:hash` and runtime objects are excluded).

## Project Structure

```
awinrm/
├── bin/evil-ctf.rb            # CLI entry point
├── evil-ctf                   # bash wrapper (bundle exec)
├── evil-ctf.rb                # root-level shim
├── Gemfile / Gemfile.lock
├── .rubocop.yml               # lint config (TargetRubyVersion 4.0)
├── config/profiles.yaml       # built-in profiles
├── lib/
│   ├── config/profiles.rb     # profile load/save (safe YAML)
│   └── evil_ctf/
│       ├── cli.rb             # option parsing, validation, dispatch
│       ├── session.rb         # session engine (bootstrap/loop split out)
│       ├── session/           # bootstrap, interactive_loop, runtime_setup,
│       │                      # log_channels, command_history, session_logger
│       ├── command_dispatcher.rb  # handler-based built-in commands
│       ├── connection.rb      # WinRM connection + validation
│       ├── shell_adapter.rb   # shell abstraction (upload/close/…)
│       ├── execution.rb       # remote job execution + streaming
│       ├── uploader.rb        # chunked uploader (+ smb fallback, client)
│       ├── tools.rb           # tool registry facade + staging rules
│       ├── tools/             # stager, downloader, macro_engine, alias_engine,
│       │                      # loot_scanner, loot_store, crypto, …
│       ├── banner.rb          # situational awareness banner
│       ├── tui.rb             # interactive TTY dashboard
│       ├── enums.rb           # enumeration presets
│       ├── sql_enum.rb        # MSSQL discovery
│       ├── crypto.rb          # XOR codec
│       ├── sanitizer.rb       # input sanitization
│       └── …                  # logger, errors, utils, app_state, async_worker
├── tools/                     # staged tool binaries + metadata sidecars
├── scripts/                   # dev/demo scripts (mock TUI, banner tests)
├── spec/                      # RSpec suite (170 examples)
└── docs/
    ├── architecture.md        # component architecture
    └── todo.md                # project source of truth (roadmap/status)
```

## Development

```bash
bundle install
bundle exec rspec       # unit + component specs
bundle exec rubocop     # lint (also runs in CI)
```

CI (`.github/workflows/ci.yml`) runs three jobs: **lint** (rubocop), **unit-tests** (rspec on push/PR), and a gated **integration-tests** job (`AWINRM_INTEGRATION=1`).

Design docs live in `docs/architecture.md`; the project roadmap and status are tracked in `docs/todo.md`.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Purpose in AWINRM |
|--------|-----------|----|-------------------|
| Execution | PowerShell | T1059.001 | Remote in-memory command execution |
| Execution | In-Memory Execution | T1620 | Run payloads without touching disk |
| Lateral Movement | WinRM | T1021.006 | Movement across Active Directory hosts |
| Credential Access | Credential Dumping | T1003 | Extract stored secrets for escalation |
| Credential Access | LSASS Memory Dumping | T1003.001 | Token/credential recovery from LSASS |
| Credential Access | Pass-the-Hash | T1550.002 | Authenticate without cleartext passwords |
| Credential Access | Kerberoasting | T1558.003 | Harvest TGS tickets for offline cracking |
| Discovery | Account Discovery | T1087 | Identify exploitable users and roles |
| Discovery | Network/Host Discovery | T1016 | Identify lateral access opportunities |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Encrypted operator traffic over HTTPS |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | AMSI bypass / Defender disable |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | ETW neutralization (script tracing) |

## Acknowledgements

AWINRM builds on the WinRM interaction model established by [Evil-WinRM](https://github.com/Hackplayers/evil-winrm), adding modular tooling, macro workflows, bypass automation, and operator-focused enhancements. Credit to:

- Evil-WinRM authors
- BloodHound / SharpHound developers
- GhostPack maintainers
- PowerShellMafia (PowerView / PowerSploit)
- Inveigh and Nishang maintainers
- Sysinternals (ProcDump)
- [RunasCs](https://github.com/antonioCoco/RunasCs) (staged as a tool)

## Contribution Policy

PRs are welcome on:

- Stealth workflow automation
- New auto-staged tools and macros
- Stability and performance fixes
- Test coverage for untested critical paths

All pull requests should pass `bundle exec rspec` and `bundle exec rubocop` and include documentation updates.

## Legal and Ethical Notice

AWINRM is provided strictly for **authorized penetration testing, approved red-team engagements, CTF participation, and security research**. Unauthorized use on systems you do not own or lack explicit permission to test is illegal. All responsibility for lawful use lies with the operator.

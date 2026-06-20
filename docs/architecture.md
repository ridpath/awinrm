# AWINRM Architecture

AWINRM is a Ruby-based WinRM post-exploitation framework. It provides an interactive PowerShell shell over WinRM with built-in tool staging, macro workflows, file transfer, AMSI/ETW bypass, and loot extraction.

## High-Level Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        CLI Entry Point                            │
│                    bin/evil-ctf.rb / lib/evil_ctf/cli.rb         │
│  (Option parsing, IPv6 mapping, profile loading, validation)     │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                       Session Layer                               │
│              lib/evil_ctf/session.rb + submodules                 │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐   │
│  │  Bootstrap   │→│ Connection    │→│ Runtime Setup          │   │
│  │  (context,   │  │  (WinRM      │  │  (bypass, prompt,      │   │
│  │   endpoint)  │  │   shell)     │  │   heartbeat, logger)   │   │
│  └─────────────┘  └──────────────┘  └────────────────────────┘   │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │              Interactive Loop                             │     │
│  │  Readline → CommandDispatcher → MacroEngine → Shell       │     │
│  └──────────────────────────────────────────────────────────┘     │
└────────────────────────────┬─────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
    ┌─────────────┐  ┌──────────┐  ┌──────────────┐
    │  Uploader   │  │ Execution│  │    Tools      │
    │  (chunked   │  │ (remote  │  │ (staging,     │
    │   file TX)  │  │  PS cmds)│  │  macros,      │
    │             │  │          │  │  download)    │
    └─────────────┘  └──────────┘  └──────────────┘
```

## Component Breakdown

### 1. CLI Layer (`lib/evil_ctf/cli.rb` + `bin/evil-ctf.rb`)

The entry point for all invocations. Responsibilities:

- **Option parsing** via `OptionParser` — supports `-i`, `-u`, `-p`, `-H`, `--ssl`, `--kerberos`, `--socks`, `--tui`, `--banner`, `--profile`, etc.
- **IPv6 host mapping** — appends entries to `/etc/hosts` for IPv6 connectivity
- **Profile loading** — merges YAML profile configs (`profiles/*.yaml` or `config/profiles.yaml`) into CLI options
- **Connection validation** — runs a pre-flight `hostname` check before entering the session
- **Multi-host mode** — iterates over a hosts file (`--hosts`), connecting to each sequentially
- **Signal handling** — traps `SIGINT` for clean exit with a 5-second force-exit fallback

Entry flow:
```
bin/evil-ctf.rb → EvilCTF::CLI.run(argv) → Session.run_session(options)
```

### 2. Session Layer (`lib/evil_ctf/session.rb` + `session/` submodules)

The session is the core runtime. It is decomposed into focused submodules:

#### Bootstrap (`session/bootstrap.rb`)
- Normalizes the target IP (handles IPv6 bracket notation, zone indices)
- Constructs the WinRM endpoint URL (`http(s)://host:port/wsman`)
- Activates SOCKS proxy wrapping via `ShellWrapper.socksify!`
- Returns `{ orig_ip, host, endpoint }` context hash

#### Connection (`lib/evil_ctf/connection.rb`)
- **`Connection.build_full`** — creates a `WinRM::Connection` with the appropriate auth transport:
  - Kerberos (`-k` flag) → `:kerberos` transport
  - Pass-the-hash (`-H`) → `:negotiate` transport
  - Password auth → `:negotiate` transport
  - Custom transport via `--transport`
- **`ConnectionValidator.validate`** — opens a throwaway PowerShell shell, runs `hostname`, and returns `{ ok:, hostname:, error: }`
- **`WinRMShellAdapter`** (inner class) — normalizes `shell.run()` results to a consistent `{ output, exitcode }` struct

#### Runtime Setup (`session/runtime_setup.rb`)
- Applies AMSI/ETW bypass if `--auto-evasion` is set
- Renders the banner (minimal or expanded) for situational awareness
- Builds the interactive prompt string (hostname + path)
- Starts the session heartbeat monitor
- Optionally launches the TUI mode and returns early if the user exits from the TUI

#### Interactive Loop (`session/interactive_loop.rb`)
The main command loop:
1. Reads input via `Readline` (with thread-based interrupt detection)
2. Adds input to command history
3. Logs the command to session log channels
4. Dispatches to `CommandDispatcher`
5. If not handled by dispatcher, falls back to macro expansion → alias expansion → raw PowerShell execution
6. On raw PS output, runs loot heuristics (credential/flag pattern matching)
7. Handles reconnection attempts on connection errors
8. Enforces a 30-minute idle timeout

#### Other Session Submodules
- **`session/log_channels.rb`** — manages operator, telemetry, and loot log files
- **`session/session_logger.rb`** — per-command logging with timing and exit codes
- **`session/command_history.rb`** — persistent command history with add/show/clear
- **`session_heartbeat.rb`** — background thread that keeps the WinRM session alive

### 3. Command Dispatch (`lib/evil_ctf/command_dispatcher.rb`)

A handler-based command router that replaces a monolithic case statement. Key features:

- **Singleton pattern** with thread-safe handler registration (`Monitor` mutex)
- **Tolerant key resolution** — tries full input, first two words, then first word
- **Structured return values** — handlers return `{ ok:, output:, error:, handled: }`
- **Async worker integration** — long-running commands (dump_creds, recon_basic) are queued via `AsyncWorker`

Built-in commands include:
| Command | Purpose |
|---------|---------|
| `help` / `menu` | Display available commands, macros, aliases |
| `tool <name>` / `tool all` | Stage and optionally execute a tool |
| `dump_creds` | Stage mimikatz + PowerView, run credential dump macro |
| `lsass_dump` | Stage procdump, dump LSASS, download to loot/ |
| `enum [type]` | Run enumeration (basic, deep, dom, sql) |
| `dom_enum` | Full domain enumeration via PowerView |
| `fileops` | Interactive file upload/download/ZIP menu |
| `bypass-4msi` / `bypass-etw` | AMSI and ETW bypass with detection + verification |
| `disable_defender` | Attempt to disable Windows Defender real-time monitoring |
| `validate macros/aliases` | Dry-run validation of macros and aliases |
| `history` / `history clear` | Command history management |
| `profile save <name>` | Save current options as a YAML profile |
| `!bash` / `!sh` | Spawn a local shell |

### 4. Execution Engine (`lib/evil_ctf/execution.rb`)

Abstracts remote PowerShell command execution:

- **`Execution.run(shell, ps, timeout:)`** — runs a sanitized PowerShell command via the shell adapter
  - For WinRM adapters: runs synchronously (avoids orphaned remote commands)
  - For other adapters: uses `run_with_timer` with thread-based timeout
  - Normalizes UTF-16LE output to UTF-8
  - Parses exit codes from output when not explicitly provided
- **`Execution.stream(shell, ps, timeout:)`** — for long-running commands, launches a PowerShell background job, polls a temp file, and yields output chunks

### 5. Shell Adapter (`lib/evil_ctf/shell_adapter.rb`)

Provides a uniform interface over different shell backends:

- **`ShellAdapter.wrap(obj)`** — detects the object type and wraps it:
  - `WinRM::Connection` → `WinRMShellAdapter` (creates shell internally)
  - `WinRM::Shell` → `WinRMShellAdapter` (uses existing shell)
  - Anything else → `GenericAdapter`
- **`WinRMShellAdapter`** — mutex-protected `run()`, exposes `file_manager()` for file operations
- **`InternalFileManager`** (nested class) — chunked upload/download with SHA-256 verification, used when `winrm-fs` gem is unavailable
- **`GenericAdapter`** — passthrough for non-WinRM shells

### 6. File Transfer (`lib/evil_ctf/uploader.rb` + `uploader/client.rb`)

#### Uploader Client (`Uploader::Client`)
Upload and download with multiple strategies:

**Upload flow:**
1. Check PowerShell availability on target
2. Detect ADS paths (`file.txt:streamname`) vs standard paths
3. For standard files:
   - Try adapter's `file_manager.upload()` first (internal chunked with SHA-256 verify)
   - Fallback to chunked Base64 upload via PowerShell `[System.IO.File]`
   - Supports XOR encryption (`--xor-key`)
   - Atomic move: write to `.part_*` temp file, then `Move-Item`
   - SHA-256 hash verification on the remote side
4. For ADS uploads: use `Add-Content -Encoding Byte` per chunk
5. Progress tracking via `AppState`

**Download flow:**
1. Try adapter's `file_manager.download()` first
2. Fallback to chunked Base64 download via PowerShell `[System.IO.File]::OpenRead`
3. Remote path resolution with retry and fuzzy matching
4. XOR decryption support

#### File Operations Menu (`Uploader.file_operations_menu`)
Interactive menu (invoked via `fileops` command):
- Upload file (with local/remote tab completion)
- Download file
- ZIP and upload a directory

### 7. Tool System (`lib/evil_ctf/tools.rb` + submodules)

#### Tool Registry (`TOOL_REGISTRY` constant in `tools.rb`)
A frozen hash mapping tool keys to metadata:
```ruby
'sharphound' => {
  name: 'SharpHound (BloodHound Collector)',
  filename: 'SharpHound.exe',
  search_patterns: [...],
  download_url: '...',
  backup_urls: [...],
  recommended_remote: 'C:\\Users\\Public\\SharpHound.exe',
  category: 'recon'
}
```

Supported tools: SharpHound, Mimikatz, PowerView, Rubeus, Seatbelt, Inveigh, ProcDump, WinPEAS, Invoke-Mimikatz, Nishang, Invoke-SocksProxy, Plink, EDR-Redir.

#### Dynamic Tool Registry (`lib/evil_ctf/tool_registry.rb`)
Scans the `tools/` and `scripts/` directories at runtime for executable files (`.ps1`, `.psm1`, `.exe`, `.bat`, `.cmd`, `.rb`, `.sh`). Builds invocation commands based on file extension.

#### Downloader (`tools/downloader.rb`)
Multi-strategy download:
1. Check if already present in `tools/`
2. Try remote download directly on the target (via PowerShell `WebClient`)
3. Try `curl`, `wget`, Ruby `URI.open`, or local `powershell Invoke-WebRequest`
4. Falls through backup URLs on failure

#### Stager (`tools/stager.rb`)
Handles the full staging pipeline:
1. Detect remote system architecture (x64/x86)
2. Check if tool is already staged on the target
3. Find local copy or download
4. For ZIP tools (Mimikatz, EDR-Redir): upload ZIP, extract on target with architecture-aware binary selection
5. For standalone binaries/scripts: direct upload to `recommended_remote`

#### AMSI/ETW Bypass Scripts (embedded in `tools.rb`)
- **`BYPASS_4MSI_PS`** — Patches `AmsiScanBuffer` and `AmsiScanString` in `amsi.dll` via `VirtualProtect` + byte patching
- **`ETW_BYPASS_PS`** — Patches `EtwEventWrite`, `EtwEventWriteTransfer`, `EtwEventWriteFull`, `EtwEventWriteEx` in `ntdll.dll` with `xor rax,rax; ret`
- **`BYPASS_DETECTION_PS`** — Detects OS build number for version-aware bypass selection
- **`BYPASS_VERIFICATION_PS`** — Verifies AMSI bypass by calling `AmsiUtils.ScanString`

### 8. Macro Engine (`lib/evil_ctf/tools/macro_engine.rb`)

Macros are named sequences of PowerShell commands that automate common attack workflows:

| Macro | Dependencies | Action |
|-------|-------------|--------|
| `kerberoast` | rubeus | AMSI bypass + Rubeus kerberoast |
| `dump_creds` | mimikatz | AMSI + ETW bypass + Mimikatz sekurlsa |
| `lsass_dump` | procdump | AMSI + ETW bypass + ProcDump LSASS dump |
| `sharphound_all` | sharphound | BloodHound data collection |
| `seatbelt_all` | seatbelt | Full Seatbelt audit |
| `socks_init` | socksproxy | SOCKS proxy pivot setup |
| `nishang_rev` | nishang | Reverse PowerShell shell |
| `dom_enum` | powerview | Full domain enumeration |

**Macro execution flow:**
1. Look up macro by name
2. Run `prepare_macro()` for special setup (e.g., locate Nishang/Inveigh remote paths)
3. Resolve placeholders (`[AttackerIP]`, `[AttackerPort]`) with user prompts or defaults
4. Execute each step sequentially via `Execution.run()`
5. Scan output for loot patterns after each step

**Validation (dry-run):**
The `validate macros` command resolves placeholders and checks dependencies without executing, reporting pass/fail with warnings.

### 9. Alias Engine (`lib/evil_ctf/tools/alias_engine.rb`)

Provides short aliases that expand to full commands (e.g., `kerb` → `kerberoast`). Supports dry-run validation via `validate aliases`.

### 10. Loot System (`lib/evil_ctf/tools/loot_scanner.rb` + `loot_store.rb`)

- **LootScanner** — regex-based pattern matching on command output for:
  - Passwords, NTLM hashes, Kerberos tickets
  - CTF flags (`flag{}`, `htb{}`, `picoctf{}`)
  - API keys, tokens, connection strings
- **LootStore** — saves findings to `loot/creds.json` and `loot/loot.txt`
- **Beacon** — optionally POSTs loot to a webhook URL (`--webhook`)
- **Auto flag download** — scans `C:\Users` recursively for flag patterns and downloads matching files

### 11. Enumeration (`lib/evil_ctf/enums.rb` + `sql_enum.rb`)

Cached enumeration system with multiple presets:
- **basic** — whoami, net user, systeminfo, ipconfig
- **deep** — runs WinPEAS for privilege escalation paths
- **dom** — PowerView-based domain enumeration
- **sql** — MSSQL instance detection and enumeration
- **kerb** — Kerberos ticket listing via Rubeus
- **cache** — results are cached per session to avoid redundant queries (bypassed with `--fresh`)

### 12. TUI (Terminal UI) (`lib/evil_ctf/tui.rb` + `tui_controller.rb`)

An optional interactive terminal UI (launched with `--tui`) using `tty-prompt`, `tty-table`, `tty-screen`:

- **Multi-pane layout** — sidebar + CLI panes
- **Session management** — switch between active sessions
- **Tool browser** — scan and launch tools from `tools/` and `scripts/`
- **Macro launcher** — select and execute macros
- **Profile selector** — load connection profiles
- **Settings** — toggle logging, change theme, adjust scrollback
- **File transfer** — upload/download via hotkeys (F5/F6)
- **Hotkeys**: Alt+1 (sidebar), Alt+2 (CLI), S/T/M/P/E/U/D for various menus

### 13. Configuration (`lib/config/profiles.rb` + `profiles/`)

YAML-based connection profiles stored in:
- `profiles/*.yaml` — individual profile files
- `config/profiles.yaml` — consolidated profile registry

Profiles can specify: `ip`, `user`, `password`, `hash`, `port`, `ssl`, `kerberos`, `realm`, `keytab`, and all other session options.

### 14. Supporting Infrastructure

| Module | Purpose |
|--------|---------|
| `lib/evil_ctf/logger.rb` | Global logging with optional file output |
| `lib/evil_ctf/engine_audit.rb` | Structured audit trail for engine errors |
| `lib/evil_ctf/sanitizer.rb` | Command input sanitization |
| `lib/evil_ctf/utils.rb` | Shared utilities (PS string escaping, etc.) |
| `lib/evil_ctf/crypto.rb` / `tools/crypto.rb` | XOR encryption for file transfers |
| `lib/evil_ctf/async_worker.rb` | Background job queue for long-running commands |
| `lib/evil_ctf/app_state.rb` | Shared application state (upload progress, settings) |
| `lib/evil_ctf/errors.rb` | Custom exception classes |
| `lib/evil_ctf/banner.rb` | Situational awareness banner (minimal/expanded) |
| `lib/compat/silence_warnings.rb` | Ruby compatibility shims |

## Data Flow: Typical Session

```
1. CLI parses args → loads profile → validates connection
2. Bootstrap normalizes IP → builds endpoint URL
3. Connection.build_full → WinRM::Connection (auth transport selected)
4. ConnectionValidator.validate → hostname check
5. RuntimeSetup → AMSI/ETW bypass → banner → heartbeat start
6. InteractiveLoop:
   a. Readline reads input
   b. CommandDispatcher.dispatch → handler or fallback
   c. If macro: MacroEngine.expand_macro → resolve placeholders → execute steps
   d. If tool: Stager.safe_autostage → download/find → upload → execute
   e. If raw PS: ShellAdapter.run → output → loot scan → save
7. On exit: heartbeat stop → shell close → loot summary
```

## Data Flow: File Upload

```
1. Uploader::Client.upload_file(local, remote)
2. ShellAdapter.wrap(shell) → WinRMShellAdapter
3. Check PowerShell availability on target
4. Detect ADS vs standard path
5. Try adapter.file_manager.upload() (chunked Base64 + SHA-256 verify)
6. Fallback: chunked upload via [System.IO.File]::Append
   - Write to .part_* temp file
   - XOR encrypt if --xor-key set
   - Verify chunk write success per iteration
7. Move temp → final path (Move-Item, Copy-Item fallback)
8. SHA-256 hash verification on remote
9. Return { ok: true, local_hash, remote_hash }
```

## Directory Layout

```
awinrm/
├── bin/evil-ctf.rb              # CLI entry point
├── lib/
│   ├── compat/silence_warnings.rb
│   ├── config/profiles.rb       # Profile loading
│   └── evil_ctf/
│       ├── cli.rb               # Option parsing, validation
│       ├── session.rb           # Session orchestration
│       │   ├── bootstrap.rb     # Context prep, connection building
│       │   ├── interactive_loop.rb  # Main command loop
│       │   ├── runtime_setup.rb     # Bypass, banner, heartbeat
│       │   ├── log_channels.rb      # Log file management
│       │   ├── session_logger.rb    # Per-command logging
│       │   └── command_history.rb   # History persistence
│       ├── connection.rb        # WinRM connection + validation
│       ├── command_dispatcher.rb  # Handler-based command routing
│       ├── execution.rb         # Remote command execution
│       ├── shell_adapter.rb     # Shell abstraction + file manager
│       ├── uploader.rb          # File transfer facade
│       │   └── client.rb        # Upload/download implementation
│       ├── tools.rb             # Tool registry, bypass scripts, loot helpers
│       │   ├── downloader.rb    # Remote tool downloading
│       │   ├── stager.rb        # Tool staging pipeline
│       │   ├── macro_engine.rb  # Macro expansion + validation
│       │   ├── alias_engine.rb  # Alias expansion + validation
│       │   ├── catalog_renderer.rb  # Tool listing display
│       │   ├── loot_scanner.rb  # Output pattern matching
│       │   ├── loot_store.rb    # Loot persistence
│       │   └── crypto.rb        # XOR encryption
│       ├── enums.rb             # Enumeration presets + caching
│       ├── sql_enum.rb          # MSSQL enumeration
│       ├── banner.rb            # Situational awareness banners
│       ├── tui.rb               # Terminal UI rendering
│       ├── tui_controller.rb    # TUI input handling + menus
│       ├── async_worker.rb      # Background job queue
│       ├── app_state.rb         # Shared application state
│       ├── tool_registry.rb     # Dynamic tool discovery
│       ├── engine_audit.rb      # Audit logging
│       ├── sanitizer.rb         # Input sanitization
│       ├── logger.rb            # Global logger
│       ├── utils.rb             # Shared utilities
│       ├── errors.rb            # Custom exceptions
│       ├── session_heartbeat.rb # Session keepalive
│       ├── shell_wrapper.rb     # SOCKS proxy wrapping
│       └── crypto.rb            # Core crypto utilities
├── tools/                       # Offensive tool binaries/scripts
├── profiles/                    # YAML connection profiles
├── config/profiles.yaml         # Consolidated profile registry
├── loot/                        # Extracted credentials and artifacts
├── log/                         # Engine audit and session logs
├── spec/                        # RSpec test suite
├── scripts/                     # Development/test scripts
└── Gemfile                      # Ruby dependencies
```

## Key Design Decisions

1. **Handler-based dispatch over case statements** — `CommandDispatcher` uses a registry of lambdas, making it easy to add commands without modifying a central switch.

2. **Adapter pattern for shells** — `ShellAdapter.wrap()` normalizes different shell types (WinRM connection, WinRM shell, generic) behind a consistent `run(cmd)` / `close()` interface.

3. **Chunked file transfer with verification** — Large files are uploaded in 64KB Base64-encoded chunks with SHA-256 hash verification. Atomic moves via temp files prevent partial writes.

4. **Macro dependency system** — Macros declare tool dependencies; the stager ensures tools are present before macro execution.

5. **Dry-run validation** — Both macros and aliases support `validate` commands that resolve placeholders and check dependencies without remote execution.

6. **Connection validation before session** — A pre-flight `hostname` check catches auth/endpoint errors before entering the interactive loop.

7. **Cached enumeration** — Enum results are cached per session to avoid redundant WinRM calls, with `--fresh` to bypass.

8. **UTF-16LE handling** — WinRM often returns UTF-16LE output; `Execution.normalize_output` detects and converts it.

9. **Synchronous WinRM execution** — For WinRM adapters, commands run synchronously to avoid orphaned remote processes that exhaust the per-shell command quota.

10. **SOCKS proxy support** — `ShellWrapper.socksify!` wraps TCP connections through a SOCKS proxy for pivot operations.

## Dependencies

| Gem | Purpose |
|-----|---------|
| `winrm` | WinRM client (core protocol) |
| `socksify` | SOCKS proxy wrapping |
| `concurrent-ruby` | Threading, timer tasks, async workers |
| `rubyzip` | ZIP file handling for tool extraction |
| `colorize` | Terminal output coloring |
| `logging` | Structured logging |
| `nori` | XML parsing (used by winrm) |
| `gssapi` | Kerberos authentication |
| `tty-prompt` / `tty-table` / `tty-screen` | TUI components |
| `rspec` / `mocha` | Testing |

## Testing

Tests are in `spec/` using RSpec with Mocha mocking:
- `execution_spec.rb` — command execution and timeout behavior
- `uploader_client_spec.rb` — file upload/download flows
- `shell_adapter_spec.rb` — shell wrapping and file manager
- `tools_crypto_spec.rb` — XOR encryption/decryption
- `tools_macro_spec.rb` — macro expansion and validation
- `tui_spec.rb` / `tui_modernization_spec.rb` — TUI component tests

Run with:
```bash
bundle exec rspec
```

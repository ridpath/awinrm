# AWINRM TODO

> Living list of improvements, missing features, and known issues.  
> Priority: 🔴 Critical · 🟡 Important · 🟢 Nice-to-have

---

## Architecture & Code Quality

- [x] 🔴 **Deduplicate `CommandDispatcher` "tool" handler** — ✅ Fixed 2026-05-13: merged into a single unified handler that tries static `TOOL_REGISTRY` first, then falls back to dynamic registry for custom tools. Extracted tool execution into `execute_staged_tool`, `exec_exe`, and `exec_via_cmd` helpers.
- [x] 🔴 **Remove dead code in `bin/evil-ctf.rb`** — ✅ Fixed 2026-05-13: moved preflight check, `--list-tools`, multi-host mode (`--hosts`), and IPv6 auto-mapping into `CLI.run`. Cleaned up `bin/evil-ctf.rb` to a thin entry point (signal trap + `exit CLI.run(ARGV)`).
- [x] 🔴 **Ensure `AsyncWorker` shutdown on session exit** — ✅ Fixed 2026-05-13: added `CommandDispatcher#shutdown` method and call in `Session.run_session` ensure block. Drains queue and stops background thread gracefully.
- [ ] 🟡 **Consolidate bypass scripts** — `BYPASS_4MSI_PS`, `ETW_BYPASS_PS`, `BYPASS_DETECTION_PS`, `BYPASS_VERIFICATION_PS` are string constants in `tools.rb`; extract to a dedicated `lib/evil_ctf/bypass.rb` module
- [ ] 🟡 **Extract PowerShell payloads from macros** — macro step strings are embedded inline; consider a `macros/` directory with `.ps1` templates for readability and version control
- [ ] 🟡 **Standardize result types** — `Execution.run` returns `OpenStruct`, `Uploader::Client.upload_file` returns `true`/`false`/`Hash`, `CommandDispatcher.dispatch` returns `Hash`; define a shared result type
- [ ] 🟡 **Remove redundant `require 'evil_ctf/uploader'` in `session.rb`** — already loaded at the top of the file
- [ ] 🟡 **Fix `parse_hosts_file` ensure block** — references `shell`, `conn`, `logger` which are out of scope (will raise `NameError`)
- [ ] 🟢 **Add frozen string literal to all files** — several files in `lib/evil_ctf/tools/` and `session/` are missing `# frozen_string_literal: true`
- [ ] 🟢 **Move inline PowerShell scripts to heredoc constants** — many handlers embed large PS blocks; extracting them improves readability and testability

---

## Connection & Authentication

- [ ] 🔴 **Add connection pooling for multi-host mode** — each host creates a new WinRM connection; reuse or pool connections where possible
- [ ] 🟡 **Support certificate-based authentication** — currently supports password, hash, and Kerberos; add `--cert` / `--cert-key` options
- [ ] 🟡 **Add connection retry with backoff** — single reconnect attempt in the loop; implement exponential backoff for transient failures
- [ ] 🟡 **Detect and warn on Constrained Language Mode** — PowerShell CLM restricts many bypass techniques; detect early and adjust strategy
- [ ] 🟢 **Support WinRM basic authentication** — useful for lab environments where Negotiate/Kerberos is not configured
- [ ] 🟢 **Add connection timeout CLI option** — currently hardcoded to 10s in validation; allow `--connect-timeout`

---

## File Transfer (Upload / Download)

- [ ] 🔴 **Handle upload resume after partial failure** — temp file detection exists but offset resumption is fragile; add explicit `--resume` support
- [ ] 🟡 **Add progress bar for uploads/downloads** — `AppState` tracks upload progress but no visual feedback in CLI mode
- [ ] 🟡 **Support compression for large files** — gzip/deflate before Base64 encoding to reduce transfer size
- [ ] 🟡 **Add download verification with SHA-256** — upload has hash verification; download does not (only `InternalFileManager` does)
- [ ] 🟡 **Handle long remote paths (>260 chars)** — Windows MAX_PATH limitation; add `\?\` prefix for long paths
- [ ] 🟢 **Add directory upload support** — `fileops` has ZIP+upload; add native recursive directory upload without ZIP step
- [ ] 🟢 **Add file transfer logging** — log transfer speed, chunk count, and duration to session logs

---

## Tool Staging & Execution

- [x] 🔴 **Fix `tool all` in dispatcher** — ✅ Fixed 2026-05-13: resolved by merging duplicate tool handler into one unified handler (see dedup fix above).
- [ ] 🟡 **Add tool version detection and caching** — detect remote tool version before re-staging; skip if already current
- [ ] 🟡 **Support custom tool definitions** — allow operators to add tools via a `custom_tools.yaml` config file
- [ ] 🟡 **Add post-execution cleanup option** — `--cleanup` or `tool <name> --cleanup` to remove staged binaries after execution
- [ ] 🟡 **Handle tools that require interactive input** — e.g., Mimikatz interactive mode; add a passthrough mode for interactive tools
- [ ] 🟢 **Add tool execution output streaming** — long-running tools (SharpHound, WinPEAS) should stream output in real-time instead of waiting for completion
- [ ] 🟢 **Add tool execution timeout configuration** — hardcoded 30-60s timeouts per tool; make configurable via CLI or profile

---

## Macros & Aliases

- [x] 🔴 **Macro error handling is all-or-nothing** — ✅ Fixed 2026-05-13: added `continue_on_error:` keyword to `expand_macro`. Failed steps are logged with step number and execution continues. Returns summary at end.
- [ ] 🟡 **Add macro composition** — allow macros to call other macros (e.g., `full_recon` = `bypass-4msi` + `dom_enum` + `kerberoast`)
- [ ] 🟡 **Add macro output parsing and structured results** — parse macro output into structured data (e.g., extract usernames from kerberoast output)
- [ ] 🟡 **Support conditional macro steps** — e.g., "if domain joined, run PowerView; else run local enum"
- [ ] 🟢 **Add macro templates** — allow operators to define custom macros via a `macros/` directory
- [ ] 🟢 **Add macro execution history** — log which macros were run, when, and on which hosts

---

## Enumeration

- [x] 🔴 **SQL enum needs error handling** — ✅ Fixed 2026-05-13: added `safe_output()` helper, changed bare `rescue` to `rescue StandardError`, moved hash/context checks inside `sqlcmd_present` guard.
- [ ] 🟡 **Add WMI enumeration preset** — enumerate installed software, services, scheduled tasks via WMI
- [ ] 🟡 **Add registry enumeration** — check for saved credentials, browser data, RDP history
- [ ] 🟡 **Improve enum cache persistence** — cache is per-session (in-memory); persist to disk for cross-session reuse
- [ ] 🟢 **Add network share enumeration** — discover and access network shares accessible from the target
- [ ] 🟢 **Add process injection detection** — check for common EDR/AV processes and alert the operator

---

## Loot System

- [x] 🔴 **Loot store race condition** — ✅ Fixed 2026-05-13: added `Mutex` around creds.json read-modify-write in `save_loot`. loot.txt append is already safe (OS-level atomic append).
- [ ] 🔴 **Auto flag download scans all of `C:\Users` recursively** — can be extremely slow on hosts with many files; add depth limit and file size filter
- [ ] 🟡 **Add structured loot export formats** — JSON, CSV, and STIX 2.1 export for integration with SOAR platforms
- [ ] 🔴 **Loot deduplication** — same credential can be saved multiple times across sessions; deduplicate on save
- [ ] 🟡 **Add loot encryption at rest** — encrypt `loot/creds.json` with a key derived from a passphrase
- [ ] 🟢 **Add loot tagging/metadata** — tag loot entries with source host, macro, timestamp for traceability
- [ ] 🟢 **Add loot database backend** — SQLite or similar for structured querying across multiple engagements

---

## AMSI / ETW Bypass

- [ ] 🔴 **Bypass is session-scoped only** — each new WinRM shell gets a fresh PowerShell process; bypass must be re-applied per shell
- [ ] 🟡 **Add DotNetToJIT bypass** — for .NET-based EDR hooks that inspect assemblies at JIT time
- [ ] 🟡 **Add ClamAV/Cisco AMP bypass detection** — detect specific EDR products and apply targeted bypasses
- [ ] 🟡 **Make bypass optional per command** — some operators may want to run specific commands with AMSI active (e.g., for blue team visibility)
- [ ] 🟢 **Add bypass persistence** — option to write a permanent AMSI/ETW bypass via registry or DLL hijack
- [ ] 🟢 **Test bypass on Windows 11 24H2** — new builds may have different AMSI internals; verify compatibility

---

## TUI (Terminal UI)

- [ ] 🔴 **TUI and CLI share no state properly** — `AppState` is a singleton but CLI mode doesn't populate it; TUI features are limited when launched from CLI
- [ ] 🟡 **Add multi-session TUI support** — manage multiple WinRM connections simultaneously in the TUI
- [ ] 🟡 **Add real-time output streaming in TUI** — long-running commands should update the UI as they produce output
- [ ] 🟡 **Add TUI help overlay** — show available hotkeys and commands as an overlay
- [ ] 🟢 **Add TUI theme customization** — beyond the 3 built-in themes, allow custom color schemes
- [ ] 🟢 **Add TUI session bookmarking** — save and restore session state (host, tools staged, macros run)

---

## Configuration & Profiles

- [ ] 🔴 **Profile loading is duplicated** — `CLI.run` loads profiles via `Config::Profiles`, but `bin/evil-ctf.rb` also has dead profile loading code via `Session.load_config_profile`
- [ ] 🟡 **Add profile validation** — validate profile YAML structure and required fields before use
- [ ] 🟡 **Support environment variable interpolation in profiles** — e.g., `${DOMAIN_USER}`, `${PASSWORD}`
- [ ] 🟢 **Add profile encryption** — encrypt sensitive fields (passwords, hashes) in profile files
- [ ] 🟢 **Add profile import/export** — share profiles between operators securely

---

## Testing

- [ ] 🔴 **No integration tests** — all specs are unit tests with mocks; add integration tests against a Windows test VM
- [ ] 🔴 **Missing specs for critical paths** — no tests for `connection.rb`, `banner.rb`, `enums.rb`, `sql_enum.rb`, `command_dispatcher.rb`, `uploader/client.rb`
- [ ] 🟡 **Add test fixtures for PowerShell output** — sample PS output for loot scanner, enum, and bypass verification tests
- [ ] 🟡 **Test file transfer with large files** — add tests for files >100MB to verify chunked transfer works
- [ ] 🟢 **Add CI pipeline** — GitHub Actions workflow to run specs on push/PR
- [ ] 🟢 **Add rubocop/static analysis** — enforce code style and catch common issues

---

## Documentation

- [ ] 🔴 **Document all CLI options** — README covers basics but `--xor-key`, `--beacon`, `--log-session`, `--user-agent`, `--no-verify` are undocumented
- [ ] 🟡 **Add command reference guide** — comprehensive list of all interactive commands with examples
- [ ] 🟡 **Add macro reference** — document each macro's purpose, dependencies, placeholders, and example output
- [ ] 🟡 **Add troubleshooting guide** — common errors and their solutions (connection failures, upload errors, bypass failures)
- [ ] 🟢 **Add quick start guide** — step-by-step walkthrough for a typical CTF engagement
- [ ] 🟢 **Add API documentation** — document public module interfaces for extension authors

---

## OPSEC & Stealth

- [ ] 🔴 **Staged tools go to `C:\Users\Public` by default** — high-visibility location; add configurable staging paths per profile
- [ ] 🟡 **Add process hollowing/suspended process execution** — launch tools in suspended state, inject payload, resume (reduces EDR visibility)
- [ ] 🟡 **Add AMSI context reset detection** — detect if AMSI has been re-initialized (e.g., by EDR) and re-apply bypass
- [ ] 🟡 **Randomize PowerShell variable names in bypass scripts** — current scripts use predictable variable names (`$kernel32`, `$amsiDll`)
- [ ] 🟢 **Add execution obfuscation** — base64-encode or compress PowerShell commands before sending over WinRM
- [ ] 🟢 **Add DNS-over-HTTPS option for tool downloads** — reduce network-level visibility of download sources

---

## Performance

- [ ] 🔴 **WinRM shell is re-opened for file manager operations** — `InternalFileManager` creates new threads per chunk; reuse the shell connection
- [ ] 🟡 **Batch PowerShell commands where possible** — multiple small `shell.run()` calls could be combined into single executions
- [ ] 🟡 **Add connection keepalive tuning** — WinRM default timeout is 60s; adjust for long-running operations
- [ ] 🟢 **Lazy-load tool registry** — scan `tools/` directory only when tools are first accessed, not at startup
- [ ] 🟢 **Compress large enum output before returning** — reduce WinRM payload size for deep enumeration results

---

## Security

- [x] 🔴 **Command injection in tool execution** — ✅ Fixed 2026-05-13: added tool name validation regex in dispatcher, and Shellwords escaping + single-quote wrapping for argument values in `ToolRegistry#build_invocation`.

- [ ] 🟡 **XOR key sent in plaintext** — `--xor-key` is stored in session options; consider deriving from a passphrase
- [ ] 🟡 **Temp file cleanup on crash** — `.part_*` files on remote host may not be cleaned up if Ruby process is killed; add scheduled cleanup macro
- [ ] 🟢 **Add input length limits** — prevent extremely large commands that could cause memory issues on the target
- [ ] 🟢 **Add rate limiting for multi-host mode** — configurable delay between hosts to reduce detection

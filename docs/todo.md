# AWINRM TODO

> Living list of improvements, missing features, and known issues.  
> **Single source of truth for project state** — JARVIS.md was removed 2026-08-18; its open items are absorbed below.  
> Priority: 🔴 Critical · 🟡 Important · 🟢 Nice-to-have

---

## Architecture & Code Quality

- [x] 🔴 **Deduplicate `CommandDispatcher` "tool" handler** — ✅ Fixed 2026-05-13: merged into a single unified handler that tries static `TOOL_REGISTRY` first, then falls back to dynamic registry for custom tools. Extracted tool execution into `execute_staged_tool`, `exec_exe`, and `exec_via_cmd` helpers.
- [x] 🔴 **Remove dead code in `bin/evil-ctf.rb`** — ✅ Fixed 2026-05-13: moved preflight check, `--list-tools`, multi-host mode (`--hosts`), and IPv6 auto-mapping into `CLI.run`. Cleaned up `bin/evil-ctf.rb` to a thin entry point (signal trap + `exit CLI.run(ARGV)`).
- [x] 🔴 **Ensure `AsyncWorker` shutdown on session exit** — ✅ Fixed 2026-05-13: added `CommandDispatcher#shutdown` method and call in `Session.run_session` ensure block. Drains queue and stops background thread gracefully.
- [ ] 🟡 **Consolidate bypass scripts** — `BYPASS_4MSI_PS`, `ETW_BYPASS_PS`, `BYPASS_DETECTION_PS`, `BYPASS_VERIFICATION_PS` are string constants in `tools.rb`; extract to a dedicated `lib/evil_ctf/bypass.rb` module
- [ ] 🟡 **Extract PowerShell payloads from macros** — macro step strings are embedded inline; consider a `macros/` directory with `.ps1` templates for readability and version control
- [ ] 🟡 **Standardize result types** — `Execution.run` returns `OpenStruct`, `Uploader::Client.upload_file` returns `true`/`false`/`Hash`, `CommandDispatcher.dispatch` returns `Hash`; define a shared result type
- [ ] 🟡 **Remove redundant `require 'evil_ctf/uploader'` in `session.rb`** — already loaded at the top of the file (`require_relative 'uploader'` at line 7 duplicates line 25)
- [x] 🟡 **Fix `parse_hosts_file` ensure block** — ✅ Fixed 2026-07-17 (P0-5, bogus `ensure` referencing undefined `shell`/`conn`/`logger` removed); verified 2026-08-18: no `ensure` block remains in `Session.parse_hosts_file`
- [x] 🔴 **Remove dead `load_config_profile` methods** — ✅ Removed 2026-08-18: `Session.load_config_profile` and `Tools.load_config_profile` deleted (plus the spec block exercising the dead `Tools` variant); profiles load via `Config::Profiles`
- [x] 🟡 **Harden unsafe `YAML.load_file`** — ✅ Hardened 2026-08-18: `config/profiles.rb` (×2) and `tool_registry.rb` (×1) now use `YAML.safe_load_file`; the 4th site sat inside the removed dead `Session.load_config_profile`
- [ ] 🟡 **Cap `EngineAudit` backtraces** — `log/engine_audit.log` is already ~740KB; bound the number of recorded backtrace frames
- [ ] 🟡 **Standardize remote execution path** — `disable_defender` mixes direct `shell.run` with `Execution.run`; route all remote command execution through `Execution`
- [x] 🟢 **Add frozen string literal to all files** — ✅ Verified 2026-08-18: only `lib/evil_ctf/tui.rb` was still missing `# frozen_string_literal: true`; added, all lib/bin files now carry it
- [ ] 🟢 **Route `puts` through `SessionLogger`** — ~24 lib files print via raw `puts` instead of the session logger; stdout bypasses log channels
- [ ] 🟢 **Move inline PowerShell scripts to heredoc constants** — many handlers embed large PS blocks; extracting them improves readability and testability

---

## Connection & Authentication

- [ ] 🔴 **Add connection pooling for multi-host mode** — each host creates a new WinRM connection; reuse or pool connections where possible
- [ ] 🟡 **Support certificate-based authentication** — currently supports password, hash, and Kerberos; add `--cert` / `--cert-key` options
- [ ] 🟡 **Add connection retry with backoff** — single reconnect attempt in the loop; implement exponential backoff for transient failures
- [ ] 🟡 **Detect and warn on Constrained Language Mode** — PowerShell CLM restricts many bypass techniques; detect early and adjust strategy. (Expanded banner already reports `$ExecutionContext.SessionState.LanguageMode`, banner.rb:378, but nothing warns or adjusts strategy.)
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
- [ ] 🟡 **Support conditional macro steps** — e.g., "if domain joined, run PowerView; else local enum"
- [ ] 🟢 **Add macro templates** — allow operators to define custom macros via a `macros/` directory
- [ ] 🟢 **Add macro execution history** — log which macros were run, when, and on which hosts

---

## Enumeration

- [x] 🔴 **SQL enum needs error handling** — ✅ Fixed 2026-05-13: added `safe_output()` helper, changed bare `rescue` to `rescue StandardError`, moved hash/context checks inside `sqlcmd_present` guard.
- [ ] 🟡 **Add WMI enumeration preset** — enumerate installed software, services, scheduled tasks via WMI. (WMI queries are already scattered across presets — `Win32_Product` in deep, `Win32_Service` in privilege, `schtasks`/`__EventFilter` in persistence — but there is no dedicated `wmi` preset; also note the `'dom'` case branch in `Enums.run_enumeration` is dead code: the dispatcher handles `dom` itself and never passes it through.)
- [ ] 🟡 **Add registry enumeration** — check for saved credentials, browser data, RDP history
- [ ] 🟡 **Improve enum cache persistence** — cache is per-session (in-memory); persist to disk for cross-session reuse
- [ ] 🟢 **Add network share enumeration** — discover and access network shares accessible from the target. (Local shares are already listed via `net share` in the `privilege` preset; the missing piece is remote-share discovery from the target.)
- [ ] 🟢 **Add process injection detection** — check for common EDR/AV processes and alert the operator. (`av_check` preset already reports Defender/AV service state via `Get-MpComputerStatus`.)

---

## Loot System

- [x] 🔴 **Loot store race condition** — ✅ Genuinely fixed 2026-08-18: `Mutex` re-added (`save_mutex.synchronize` around the creds.json read-modify-write in `LootStore.save_loot`); regression spec (`spec/tools_loot_store_spec.rb`) spawns 8 threads × 25 saves and asserts zero lost updates — verified to fail without the mutex. (loot.txt append is already safe: OS-level atomic append.)
- [x] 🔴 **Auto flag download scans all of `C:\Users` recursively** — ✅ Verified 2026-08-18: `tools.rb` flag scan now uses `-Depth 3`, size filter (0 < size < 2MB), noise-dir exclusions (AppData/Roaming/Cache/…), 250-file cap, and 50-flag cap
- [ ] 🟡 **Add structured loot export formats** — JSON, CSV, and STIX 2.1 export for integration with SOAR platforms
- [ ] 🔴 **Loot deduplication** — partial: `creds.json` IS deduped on save (`json_loot.uniq`, loot_store.rb); `loot.txt` is not — plain-text matches can duplicate across sessions
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

- [x] 🔴 **Profile loading is duplicated** — ✅ Resolved 2026-07-17 (P0-5): `bin/evil-ctf.rb` is a thin launcher with no profile code; `CLI.run` loads via `Config::Profiles`. Remaining cleanup (dead duplicate `load_config_profile` methods) tracked under Architecture & Code Quality
- [ ] 🟡 **Add profile validation** — validate profile YAML structure and required fields before use
- [ ] 🟡 **Support environment variable interpolation in profiles** — e.g., `${DOMAIN_USER}`, `${PASSWORD}`
- [ ] 🟢 **Add profile encryption** — encrypt sensitive fields (passwords, hashes) in profile files
- [ ] 🟢 **Add profile import/export** — share profiles between operators securely

---

## Testing

- [ ] 🔴 **No integration tests** — all specs are unit tests with mocks; add integration tests against a Windows test VM. Note: the CI `integration-tests` job is a stub — it references `spec/integration` (does not exist) and swallows failures with `|| true`
- [x] 🔴 **Missing specs for critical paths** — ✅ 2026-05-13/2026-07-17: specs now exist for `connection`, `command_dispatcher`, `enums`, `banner`, `uploader/client`, and SMB upload. Remaining gap tracked below (`sql_enum.rb`)
- [ ] 🟢 **Add `spec/sql_enum_spec.rb`** — last critical-path module without a spec
- [ ] 🟡 **Add test fixtures for PowerShell output** — sample PS output for loot scanner, enum, and bypass verification tests
- [ ] 🟡 **Test file transfer with large files** — add tests for files >100MB to verify chunked transfer works
- [x] 🟢 **Add CI pipeline** — ✅ `.github/workflows/ci.yml` runs unit tests on push/PR (Ruby 3.2); integration job gated on `AWINRM_INTEGRATION=1`
- [ ] 🟢 **Add CI Ruby matrix** — CI pins Ruby 3.2, dev box runs 3.3.8, vendor bundles exist for 3.3.0 and 4.0.0; test 3.2/3.3/4.0 to match the declared "Ruby 3.0+ / 4.0-ready" story
- [x] 🟢 **Wire rubocop into tooling** — ✅ Wired 2026-08-18: `rubocop ~> 1.89` in Gemfile development group (≥ 1.89 required for `TargetRubyVersion: 4.0`), new parallel `lint` CI job runs `bundle exec rubocop`; codebase green (66 files, 0 offenses)

---

## Documentation

- [ ] 🔴 **Rewrite README** — stale `Gemfile` block (lists `net-smtp`/`bundler`, omits `winrm-fs`, `colorize`, `gssapi`, `tty-*`), "Project Structure" lists 6 of ~45 lib files (see `docs/architecture.md` for the real tree), usage guide has 3 competing invocation styles + stray `)` in 3 examples, and two hidden SEO keyword comment blocks should be deleted
- [ ] 🔴 **Document all CLI options** — README covers basics but `--xor-key`, `--beacon`, `--log-session`, `--user-agent`, `--no-verify` are undocumented
- [ ] 🟡 **Add command reference guide** — comprehensive list of all interactive commands with examples (dispatcher now has ~22 commands, several undocumented: `tools`, `download_missing`, `load_ps1`, `invoke-binary`, `get-unquotedservices`)
- [ ] 🟡 **Add macro reference** — document each macro's purpose, dependencies, placeholders, and example output
- [ ] 🟡 **Add troubleshooting guide** — common errors and their solutions (connection failures, upload errors, bypass failures)
- [ ] 🟡 **Sync `docs/architecture.md`** — "Testing" section lists 6 of 16 spec files; command table missing live dispatcher commands (see command reference item)
- [ ] 🟢 **Add quick start guide** — step-by-step walkthrough for a typical CTF engagement
- [ ] 🟢 **Add API documentation** — document public module interfaces for extension authors

---

## OPSEC & Stealth

- [ ] 🔴 **Staged tools go to `C:\Users\Public` by default** — high-visibility location; ~33 hardcoded `C:\Users\Public` paths in lib; add configurable staging path per profile
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
- [x] 🟢 **Lazy-load tool registry** — ✅ Verified 2026-08-18: `ToolRegistry` is instantiated only on demand (dispatcher `tools` handler, TUI tool browser, `build_invocation`); no scan at startup
- [ ] 🟢 **Compress large enum output before returning** — reduce WinRM payload size for deep enumeration results

---

## Security

- [x] 🔴 **Command injection in tool execution** — ✅ Fixed 2026-05-13: added tool name validation regex in dispatcher, and Shellwords escaping + single-quote wrapping for argument values in `ToolRegistry#build_invocation`.

- [ ] 🟡 **XOR key sent in plaintext** — `--xor-key` is stored in session options; consider deriving from a passphrase
- [ ] 🟡 **Temp file cleanup on crash** — `.part_*` files on remote host may not be cleaned up if Ruby process is killed; add scheduled cleanup macro. (Best-effort cleanup on *error* already exists: `uploader/client.rb:436` + `Uploader.cleanup_tmp`; the gap is hard process kill.)
- [ ] 🟢 **Add input length limits** — prevent extremely large commands that could cause memory issues on the target
- [ ] 🟢 **Add rate limiting for multi-host mode** — configurable delay between hosts to reduce detection. (A hardcoded 2s delay already exists in `cli.rb`; make it CLI/profile-configurable.)

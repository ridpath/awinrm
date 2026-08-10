---
project: awinrm
updated: 2026-07-17T02:41:52+00:00
---
# JARVIS.md — awinrm

## NOW — Current Active Task
- [2026-07-17] **P0 audit fixes COMPLETED (5 items)** — see prior NOW entry (async jobs, profile save leak, dup register('tool'), auto_download_flags, bin/evil-ctf half-dead).
- [2026-07-17] **Dead-code cleanup COMPLETED (3 items), verified.**
  1. **`tools.rb:5` dead Integer shim** removed — `class Integer < Integer; end if (RUBY_VERSION.to_f < 2.4) && !defined?(Integer)` was invalid self-inheritance and the `!defined?(Integer)` guard was always false, so it never activated. `Integer` is now the real core class.
  2. **`connection.rb` dead User-Agent branch** removed — it built a standalone `WinRM::HTTP::HttpTransport` and poked `@httpcli.default_header`, but `WinRM::Connection` ignores `:http_client` and rebuilds its own transport from `ConnectionOpts`, so the UA was never applied. Replaced with a real `user_agent:` override (winrm honors it as a ConnectionOpts key → transport `User-Agent` header). `--user-agent` now actually works.
  3. **`Execution.run_with_timer` no-op `Concurrent::TimerTask`** removed — the TimerTask body was a comment-acknowledged no-op; termination is handled by `worker.join(timeout)` + `worker.kill`. Removed the unused `require 'concurrent'` from execution.rb (still required independently by shell_adapter.rb).
- **Verification:** `ruby -c` PASS on tools.rb/connection.rb/execution.rb; functional test (7/7) stubbed only winrm/zip/concurrent/colorize then required REAL source — confirmed Integer intact, user_agent override applied (no dead http_client key leaked), run_with_timer returns block value and times out. Box is Ruby 3.3.8; bundled gems target 4.0.0 (stubbed).
- **Remaining smells (NOT dead code — left for separate task):** `disable_defender` mixes direct `shell.run` with `Execution.run` (consistency, not dead); `puts` in 24 lib files (route through SessionLogger); unsafe `YAML.load_file` in config/profiles.rb + tool_registry.rb (security, not dead).
- **Next:** P1 hardening still open — unsafe YAML.load_file (profiles.rb, tool_registry.rb, session.rb), 33 hardcoded `C:\Users\Public` paths, EngineAudit unbounded backtraces, spec suite Ruby-matrix (3.3/4.0).

## NOW — Current Active Task
- [2026-07-17] **P0 audit fixes COMPLETED (5 items)** grounded by reading source + targeted greps.
  1. **Async jobs silent + raise (P0-1):** `SessionLogger` now has `info`/`warn`/`error` (write to logfile). `session_options[:logger]` is wired to the real `SessionLogger` in `Session#run_session`. `AsyncWorker#process` now captures block/command output and publishes it to `AppState` (`append_result`/`append_stream`) so `recon_basic`/`dump_creds`/`tool` output is visible and no longer raises `NoMethodError` (OpenStruct fallback raised; now guarded via `respond_to?(:info)`).
  2. **`profile save` credential leak (P0-2):** `Tools.save_config_profile` sanitizes to `PROFILE_SAFE_KEYS` and persists via `Config::Profiles.save_profile` to `profiles/<name>.yaml`. `:password`/`:hash` (and runtime objects) are never written. Round-trip tested: no secret on disk, reload correct.
  3. **Duplicate `register('tool')` (P0-3):** removed the dead first handler (ToolRegistry dynamic `tool <name> key=value` + async enqueue); kept the stager handler. Exactly one `register('tool')` remains.
  4. **`auto_download_flags` broken (P0-4):** builds a real PS `string[]` via `ConvertFrom-Json` (was a JSON blob treated as one `-Pattern`); removed the nonsensical `-notmatch "^. "` filter; handles single-object JSON and empty output.
  5. **`bin/evil-ctf.rb` half-dead (P0-5):** reduced to a thin launcher (removed unreachable preflight/profile/multi-host/session code). Implemented `--hosts` multi-host in `cli.rb` (parse + per-host `Session.run_session`). Fixed `Session.parse_hosts_file` `ensure` `NameError` (P1-6) by removing bogus cleanup referencing undefined `shell`/`conn`/`logger`.
- **Verification:** `ruby -c` passes on all 8 edited files (session_logger, async_worker, session, config/profiles, tools, command_dispatcher, cli, bin). Profile save/load round-trip asserted (no password/hash on disk).
- **Next (not done):** P1 items remain (unsafe `YAML.load_file` in config/profiles.rb, tool_registry.rb, session.rb; `connection.rb` UA branch; `tools.rb:5` dead Integer shim). Spec suite targets Ruby 4.0 (vendor/bundle) — box is 3.3.8, so add a CI Ruby matrix (3.3/4.0).

## MAP — Project Map and Symbol Index
- Keep only stable files, symbols, entry points, tests, and runtime commands.
- Prefer paths plus purpose; remove stale implementation trivia.

## LAW — Learned Agent Warnings
- Format: `LAW-001: Trigger -> Rule -> Verify`.
- Use for hard project invariants that must stay true on future edits.

## BAN — Forbidden Actions
- Format: `BAN-001: Never <action>; because <failure>; verify <check>`.
- Use for known-dangerous actions, not generic caution.

## HABIT — User and Project Preferences
- Format: `HABIT-001: When <situation>, prefer <style/workflow>`.
- Use for user/project preferences that affect future choices.

## WHY — Why History Yells (Decision Rationale)
- Record decision rationale only: `Decision -> Why -> Tradeoff`.
- Do not duplicate changelog, NOW, or RAW evidence.

## OMM — Oh My Mistake (Failure Retrospectives)
OMM entries are operational mistake-prevention rules, not apologies.
Use this exact shape:
### OMM-001: Short title
- Trigger: When this rule must be recalled.
- Mistake: What failed before, concretely.
- Rule: What must/never happen next time.
- Required action: What to inspect or change before proceeding.
- Verify: Command, test, log, or observable check.

## RAW — Raw Evidence Pointers
- Evidence pointers only: date, request, files changed, commands run, test result, turn id if known.
- Do not paste transcripts or long explanations here.


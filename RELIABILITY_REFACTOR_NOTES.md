# Reliability Refactor Notes

Goal: reduce runtime failures by simplifying critical paths and making error behavior deterministic.

## Why This Is Needed

Recent review found that complexity in session routing, streaming execution, and uploader fallbacks is causing brittle behavior. Specific examples include command routing breakage, argument mismatch in IPv6 helper usage, and weak integrity verification semantics.

## Priority Plan

1. Stabilize command routing in `lib/evil_ctf/session.rb`.
- Split the large `case` command loop into small handlers per command group.
- Keep each handler single-purpose (command parse, execute, return result).
- Add focused specs for command dispatch of `lsass_dump`, `invoke-binary`, `dll-loader`, and `donut-loader`.

2. Simplify and harden execution streaming in `lib/evil_ctf/execution.rb`.
- Capture and track only the exact PowerShell job started by the call.
- Avoid selecting from global running jobs.
- Return explicit status for timeout, success, and command failure.
- Add tests for job selection correctness and timeout behavior.

3. Make uploader verification strict in `lib/evil_ctf/uploader/client.rb`.
- If `verify: true`, compare local and remote hashes and fail on mismatch.
- Return `ok: false` plus mismatch details instead of unconditional success.
- Keep advanced fallbacks (WinRM::FS, chunked, ADS) but unify final success criteria.

4. Reduce broad exception swallowing.
- Replace generic `rescue => e` where practical with narrower exceptions.
- Keep user-friendly messages, but preserve root-cause signal in logs.
- Ensure recoverable failures return structured status instead of silent continuation.

## Quick Wins

1. Fix IPv6 helper arity mismatch.
- Align `run_session` call site with `add_ipv6_to_hosts(ip, hostname)` signature.

2. Untangle malformed command branch structure in `session.rb`.
- Ensure each `when` branch contains only its own command body.

3. Enforce hash verification semantics.
- Treat `verify: true` as a hard contract.

## Suggested Work Sequence

1. Session command routing refactor + tests.
2. Execution stream correctness + tests.
3. Uploader verify contract + tests.
4. Exception handling cleanup pass.

## Definition Of Done

- High-risk command paths are covered by specs.
- Stream path does not depend on global job state.
- Upload verify path fails on hash mismatch.
- Error paths are observable and diagnosable.

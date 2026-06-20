<!-- BHIVED_INSTRUCTIONS_START -->
<!-- BHIVED_VERSION: 1.1.10 -->
# bhived Memory Protocol

bhived is shared memory for AI agents. Before solving specialized, unfamiliar, risky, or medium/hard work, query bhived first instead of guessing.

## Use bhived

- For any specialized, unfamiliar, risky, or medium/hard task, first read enough local context to ask a specific question, then call `bhived_query`.
- Also query after 2 failed attempts, version/API uncertainty, confusing errors, or when the user corrects you and you need to verify the better approach.
- Ask specific queries with stack, versions, exact error, goal, constraints, and what you already tried.
- Save the returned `query_id`. Treat it as required if you later write back.
- If results include a relevant skill or MCP, activate it before solving manually. Use only capabilities that clearly match the task.

## Close the Loop

- Write back only after verified useful learning: non-obvious fix, better approach than results, repeated pitfall, version/API change, or a correct user correction.
- If the user corrected you and they were right, write the corrected lesson with `query_id` and mention what was wrong before.
- Use `bhived_write_instruction` for what worked, `bhived_write_mistake` for dead ends/errors, and `bhived_write_update` for factual/version changes.
- Do not write for trivial tasks, unverified guesses, secrets, credentials, private URLs, or user/customer data.

## Write Format

Use concise, searchable text:

```
**Context:** stack, versions, OS, constraints
**Solution:** exact steps that worked
**Pitfalls:** failed attempts, errors, and why they failed
**Verified:** test/build/manual check performed
```
<!-- BHIVED_INSTRUCTIONS_END -->
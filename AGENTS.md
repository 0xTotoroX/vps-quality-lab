# VPS Quality Lab

Product code is in `src/vps_quality_lab`; this directory also contains historical private data.
Never add `private`, `.runtime`, `results`, `reports`, `legacy`, `vendor` or `scripts` to Git or packages.
Do not move those directories or their external compatibility links.

`docs/cli-contract.md` defines commands, states, exits and side effects. Update it when contracts change.
Keep stdin/stdout credentials private, machine stdout JSON-only, progress on stderr, and subprocesses bounded.
Fail closed on unknown SSH identities, existing configuration ownership and unexpected egress.
Tests must cover observable failures and recovery; test fixtures use documentation IP ranges.
Do not change a system proxy or Shadowrocket selection during verification.
Use Python + Typer and preserve the runtime/config boundary in the model and executor.

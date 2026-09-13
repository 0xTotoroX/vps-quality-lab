---
name: vps-quality-lab
description: Bootstrap SSH access, adopt or deploy a VLESS REALITY VPS node, verify its fixed egress through an independent client, and deliver an evidence-based report with original terminal screenshots. Use when a user provides a VPS for Shadowrocket and quality assessment; not for generic proxy-account management.
---

# VPS Quality Lab

Use the `vps-lab` CLI as the execution and state owner. Read [references/workflow.md](references/workflow.md) for installation, config examples and recovery. Use `vps-lab --help`, `plan` and `schema` to check the installed contract; avoid recreating its workflow in ad-hoc shell scripts.

Collect the VPS host, SSH port/user and authorized initial login, a trusted host fingerprint or existing known_hosts, the intended fixed exit IP, physical client interface, purpose and package specifications. Keep SSH credentials in memory/environment or a protected key file. Host inventory labels do not prove the delivered IP. Resolve actual entry DNS in every batch. Optional airport/upstream access changes the entry leg; the VPS remains the final exit.

Use existing authorization. For an authorized new server, enable `mode=deploy` and `allow_deploy=true`; for an active Xray service use `adopt`. `run` starts by establishing/reusing a dedicated SSH key and validating a fresh public-key connection, then performs the selected deployment and assessment. Missing host identity, login or required parameters must be resolved before dependent steps. Do not disable passwords/root, change sshd ports/firewalls, switch the system proxy or alter a live client route as incidental work.

Prefer `--json` for orchestration and inspect both process exit and stage states. Check the attempt's recovery record for retained remote evidence, then resume the recorded run after interruption; a new time-of-day or changed test shape needs a new labeled batch. Do not mutate a saved config snapshot to make resume accept it. Exit mismatch, missing JSON and failed upstream probes cannot be promoted to success or used in rankings. Partial or skipped is a valid honest outcome; explain the specific missing evidence.

Deliver the private node URI and QR separately from the report. Request native Shadowrocket import only when authorized and safe; reread the archive with `client-check`. Independent sing-box verification proves that test path, not that Shadowrocket selected/imported the node. To mark the client verified, also test a confirmed Shadowrocket-owned loopback listener. Preserve current nodes and iCloud state.

Export the full report to the actual currently open Obsidian vault with `report --obsidian`, or an explicit directory. Inspect the generated Markdown and rendered original terminal PNGs. The CLI replays original ANSI in xterm.js and takes browser screenshots; no OCR or reconstructed text substitutes for those images. If capturing or a tool fails, retain raw evidence and explain the partial result. Never include a credential QR or private key in a shareable report. Use `--share` for an identifier-redacted summary without original screenshots.

Explain the purpose-specific conclusion with comparable TTFB, single-flow, aggregate throughput, upload and distinct route observations. IP reputation sources may disagree and do not prove account safety. HTTPS probes do not establish successful account login, an AI conversation, video playback, UDP quality or all-day stability. Complete requested real application checks separately when authorized and available, and distinguish them from the CLI's measurements.

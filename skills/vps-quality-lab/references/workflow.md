# Installation and operator workflow

Repository: https://github.com/0xTotoroX/vps-quality-lab (private; use the authenticated user's access).

For a checkout, use Python 3.11+:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[screenshots]'
.venv/bin/python -m playwright install chromium
.venv/bin/vps-lab --version
```

For a release, download the wheel and Skill ZIP from the repository's Releases page with `gh release download --repo 0xTotoroX/vps-quality-lab`. Install the wheel in a venv, adding the `screenshots` extra; run its Python's `-m playwright install chromium`. The CLI also needs OpenSSH, curl and sing-box on the client. Servers require Debian/Ubuntu, Python 3, bash, curl, timeout and systemd. Do not infer that dependencies exist from a successful Python package installation; `doctor` checks the live environment.

Use a trusted fingerprint (from the VPS console/provider) before first authentication:

```sh
vps-lab trust-host --host 192.0.2.10 --port 22 --fingerprint SHA256:TRUSTED_FINGERPRINT --output /private/location/known_hosts
vps-lab init --host 192.0.2.10 --ssh-port 22 --expected-exit 192.0.2.10 --interface en0 --known-hosts /private/location/known_hosts --password-env VPS_LAB_SSH_PASSWORD --output /private/location/vps.json
vps-lab --json plan --config /private/location/vps.json
vps-lab --json run --config /private/location/vps.json --label daytime
```

The documentation IP and fingerprint above are illustrative; replace them with actual verified values. Pass the password through the named process environment, not command arguments, files in the repository or terminal output. If an existing key already works, set `ssh.key_file` instead. `ssh-bootstrap` can run independently and returns the dedicated alias/config path; `ssh-status` rechecks it. Connect with `ssh -F <ssh_config> <alias>`; the alias is not installed into the user's global SSH config.

If the server explicitly disables public-key authentication and automatic SSH setup is authorized, set `ssh.enable_public_key=true`. For standard Debian/Ubuntu root administration the CLI adds a user-scoped public-key setting, compares protected effective authentication settings, validates with sshd, reloads without dropping the existing connection and verifies a fresh public-key connection. It restores its policy change if that connection fails. It does not disable passwords/root or change ports. A nonstandard SSH config or incompatible Match policy remains an explicit precondition failure.

`init` defaults to adopt. For a new empty server edit the private config to `mode: deploy` and `allow_deploy: true` after confirming deployment is authorized. Other settings: profile `ai|video|balanced`; `plan` records package specs; `resolver` plus `source_address` selects independently bound DNS; `upstream_file` is a private sing-box outbound with the airport credentials. Optional `external_tools` are `ip`, `net`, `hardware`; hardware needs `allow_stress`, dependency installation needs `allow_external_install`. Use CLI JSON Schema for all limits and allowed fields; `schema --kind network|verify|contract` describes the current typed evidence and comparison inputs. These flags record required capabilities, not grants of authority.

```sh
vps-lab status /path/to/run
vps-lab resume /path/to/run
vps-lab node-export /path/to/run --output /private/location/node
vps-lab client-import /path/to/run
vps-lab client-check /path/to/run --proxy socks5h://127.0.0.1:CLIENT_PORT
vps-lab report /path/to/run --obsidian
vps-lab report /path/to/run --output /path/to/export --share
vps-lab compare /path/to/daytime-run /path/to/evening-run
```

Do not guess CLIENT_PORT; inspect the active app listener. `client-check` verifies listener ownership before egress. Import is explicitly separate from route selection, and a native app confirmation may still be needed. If the in-use client cannot be safely tested, deliver the generated credentials and independently verified path, keeping client delivery incomplete.

Results: code 0 success, 1 failed essential stage, 2 input, 3 partial/skipped, 4 precondition, 5 lock, 130 interruption. stdout remains one JSON object with `--json`; progress is stderr. Examine `ssh_delivery`, `node_delivery`, `ranking_eligible` and each stage. State `complete` means this invocation ended; it does not mean every probe succeeded.

Run files default to `~/.local/share/vps-quality-lab`; `VPS_LAB_HOME` overrides this. A run's immutable config and node artifacts are under `private`; original evidence is in separate attempt directories. SSH keys/config live under `identities`. Original authorized_keys backups live under the user's Documents/Backups-archive/vps-quality-lab on macOS or .local/state/vps-quality-lab/backups on Linux. Restore only after comparing later keys; never blindly overwrite concurrent additions. Fresh managed Xray pending keys and ownership are under /var/lib/vps-quality-lab; adopt never replaces existing config.

Recovery: inspect `<tool>-recovery.json` in the attempt directory when an external diagnostic is interrupted. If `remote_cleaned=false`, preserve/retrieve the recorded remote scratch before cleanup. ANSI already received is saved locally. A failed report can be retried with `resume RUN --stages report` after resolving storage errors; that command alone does not revalidate the route. `compare` excludes interrupted/unverified attempts and legacy measurements without a comparison contract; use a full resume with `--rerun` for new comparable evidence.

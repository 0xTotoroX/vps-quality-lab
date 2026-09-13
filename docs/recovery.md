# Recovery and state ownership

Use `vps-lab status RUN` to find the failed or interrupted stage, then `vps-lab resume RUN`. This rechecks live SSH, service ownership and egress. Keep the original config snapshot intact; a new profile, entry, exit or budget belongs to a new run. All prior evidence attempts remain present.

SSH bootstrap creates a dedicated key only when necessary. A newly generated local key can remain after a failed first login; the next attempt reuses it. The server's original login, keys, port and authentication policy remain unchanged. Before adding the public key, the original authorized_keys is saved under `~/Documents/Backups-archive/vps-quality-lab/ssh-<host digest>/<time>/` on macOS, or `~/.local/state/vps-quality-lab/backups/` on Linux. `restore.json` records origin and existence. If later keys were added, remove only this tool's tagged key rather than blindly restoring the whole file. A second fresh public-key connection must succeed before connection.json becomes ready.

Use the exact path returned by `ssh-bootstrap`: `ssh -F /path/to/ssh_config vps-lab-<id>`. The tool never edits the user's global SSH configuration. Back up the protected identity directory before moving machines. A password environment variable can be removed after the key is verified. Encrypted existing keys must already be unlocked in the SSH agent.

When public-key authentication is disabled, `ssh.enable_public_key=true` permits a narrowly scoped `Match User` block in the standard server sshd_config. The original file and protected effective policy are backed up first. The CLI checks candidate syntax and proves password/root/port/authentication-method settings remain unchanged, reloads SSH while retaining the old session, and then tests the new key. Failed verification rolls the policy change back. Existing conflicting Match policy or a nonstandard sshd config is not overwritten. `sshd-restore.json` contains compare-before-restore hashes.

Fresh Xray deployment uses `/var/lib/vps-quality-lab/owner.json` and `pending.json`. These contain ownership and credentials and stay private. If the official installer fails, resume uses those pending keys and repeats installation until an `install-complete.json` receipt exists; a partly copied binary does not count as a completed installation. Changed requested ports/REALITY targets or a diverged managed config stop deployment instead of overwriting it. The pre-activation config is retained there as `pre-config.json`. On a new installation only, an administrator can stop it with `systemctl disable --now xray`; inspect ownership before removing files. Existing adopted services are not modified by the CLI.

A terminated local independent client is cleaned up by PID/process group. External measurements use uniquely named bounded systemd units; inspect `systemctl list-units 'vps-lab-*'` if a remote transport fails. Do not stop any unrelated service. No persistent local SOCKS listener is left behind.

A native client import request is not proof of import or routing. `client-check` rereads the current archive and optionally verifies a Shadowrocket-owned loopback listener. Never overwrite an iCloud archive to force import. If a requested import cannot be completed in the app, keep the private link and QR and report the delivery as generated/import_requested.

Full reports can include public IPs and local paths; only `report --share` is intended as a redacted summary. It excludes original terminal images because those can contain identifying information. The ordinary Obsidian export preserves the original screenshots in the user's private vault.

## Interrupted diagnostics and report failures

ANSI is streamed into the attempt directory even when the SSH command is interrupted. Check `<tool>-recovery.json`: `remote_cleaned=false` identifies scratch that was retained because JSON recovery or cleanup did not complete. Retrieve that exact directory through the existing authenticated SSH connection before manual cleanup; never remove another run's scratch. A fresh attempt does not overwrite previous ANSI/JSON or its pre-resume state snapshot.

If report writing fails, fix the destination/storage problem and use `resume RUN --stages report`. This regenerates artifacts and records the outcome; it does not claim fresh network verification. Use a full resume to revalidate a current route. Legacy measurements without `contract` remain available in reports but require `--rerun` before comparison.

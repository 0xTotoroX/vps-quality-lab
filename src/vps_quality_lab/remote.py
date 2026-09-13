"""SSH with known-host enforcement and finite remote commands."""

import os
import shlex
import time
import uuid

import paramiko

from .models import SSH
from .process import CommandResult
from .storage import LabError, write_private


class Remote:
    def __init__(self, config: SSH):
        self.config = config
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

    def __enter__(self):
        c = self.config
        if not c.known_hosts.is_file():
            raise LabError("SSH known_hosts missing; verify the server fingerprint first", 4)
        if c.password_env and not os.environ.get(c.password_env):
            raise LabError(f"Required password environment variable {c.password_env} is not set", 2)
        try:
            self.client.load_host_keys(str(c.known_hosts))
            self.client.connect(c.host, port=c.port, username=c.user,
                                key_filename=str(c.key_file) if c.key_file else None,
                                password=os.environ.get(c.password_env) if c.password_env else None,
                                look_for_keys=not bool(c.password_env),
                                allow_agent=not bool(c.password_env),
                                timeout=c.connect_timeout, banner_timeout=c.connect_timeout,
                                auth_timeout=c.connect_timeout, channel_timeout=c.connect_timeout)
        except (paramiko.SSHException, OSError, ValueError) as exc:
            self.client.close()
            # Exception text can contain credentials or untrusted server messages.
            raise LabError(f"SSH connection rejected ({type(exc).__name__}); check host key and login", 4) from exc
        return self

    def __exit__(self, *_):
        self.client.close()

    def run(self, command: str, timeout: int = 30, data: bytes | None = None,
            pty: bool = False, resource_scope: bool = False, output_path=None) -> CommandResult:
        unit = "vps-lab-" + uuid.uuid4().hex[:16]
        bounded = f"timeout -k 3s {timeout}s bash -c {shlex.quote(command)}"
        if resource_scope:
            bounded = (f"systemd-run --quiet --wait --pipe --collect --unit={unit} "
                       "-p CPUQuota=100% -p MemoryMax=512M -p TasksMax=256 "
                       "-p RuntimeMaxSec=" + str(timeout + 5) + " " + bounded)
        channel = self.client.get_transport().open_session(timeout=10)
        out, err = bytearray(), bytearray()
        output = None
        try:
            if output_path is not None:
                write_private(output_path, b"")
                output = output_path.open("ab", buffering=0)
            if pty:
                channel.get_pty(term="xterm-256color", width=160, height=60)
            channel.exec_command(bounded)
            if data:
                channel.sendall(data)
            channel.shutdown_write()
            deadline = time.monotonic() + timeout + 10
            while True:
                while channel.recv_ready():
                    chunk = channel.recv(65536)
                    out.extend(chunk)
                    if output:
                        output.write(chunk)
                while channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(65536)
                    err.extend(chunk)
                    if output:
                        output.write(chunk)
                if len(out) + len(err) > 8_000_000:
                    raise LabError("Remote output exceeded 8 MB limit")
                if channel.exit_status_ready() and not channel.recv_ready():
                    code = channel.recv_exit_status()
                    return CommandResult(code, bytes(out), bytes(err), code in (124, 137))
                if time.monotonic() > deadline:
                    raise LabError("SSH transport timed out; remote timeout remains enforced")
                time.sleep(0.02)
        except BaseException:
            if resource_scope:
                try:
                    _, stdout, _ = self.client.exec_command(f"systemctl stop {unit}", timeout=10)
                    stdout.channel.recv_exit_status()
                except Exception:
                    pass
            raise
        finally:
            channel.close()
            if output:
                try:
                    os.fsync(output.fileno())
                finally:
                    output.close()

    def read(self, path: str, maximum: int = 8_000_000) -> bytes:
        with self.client.open_sftp() as sftp:
            sftp.get_channel().settimeout(self.config.connect_timeout)
            with sftp.open(path, "rb") as stream:
                data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise LabError("Remote evidence exceeds size limit")
        return data

    def write(self, path: str, data: bytes, mode: int = 0o600):
        with self.client.open_sftp() as sftp:
            with sftp.open(path, "wx") as stream:
                stream.write(data)
            sftp.chmod(path, mode)

    def mkdir(self, path: str):
        with self.client.open_sftp() as sftp:
            sftp.mkdir(path, mode=0o700)

    def python(self, script: str, timeout: int = 30) -> CommandResult:
        return self.run("python3 -", timeout, script.encode())

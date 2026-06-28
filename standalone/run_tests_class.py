#!/usr/bin/env python3

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


class ParallelSubprocessRunner:
    def __init__(self, commands, timeout=10, max_workers=None):
        """
        commands format:
        {
            "hostname": ["hostname"],
            "kernel": ["uname", "-r"],
            "interfaces": ["ip", "-j", "addr", "show"]
        }
        """
        self.commands = commands
        self.timeout = timeout
        self.max_workers = max_workers or len(commands)

    def run_command(self, name, command):
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )

            return {
                "name": name,
                "command": command,
                "success": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }

        except subprocess.TimeoutExpired as exc:
            return {
                "name": name,
                "command": command,
                "success": False,
                "returncode": None,
                "stdout": exc.stdout or "",
                "stderr": f"Command timed out after {self.timeout}s",
            }

    def parse_result(self, result):
        name = result["name"]

        if not result["success"]:
            return {
                "name": name,
                "status": "failed",
                "error": result["stderr"],
                "returncode": result["returncode"],
            }

        stdout = result["stdout"]

        if name == "hostname":
            return {
                "name": name,
                "status": "ok",
                "hostname": stdout,
            }

        if name == "kernel":
            return {
                "name": name,
                "status": "ok",
                "kernel_version": stdout,
            }

        if name == "interfaces":
            return {
                "name": name,
                "status": "ok",
                "interfaces": json.loads(stdout),
            }

        return {
            "name": name,
            "status": "ok",
            "raw_output": stdout,
        }

    def run_all(self):
        results = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.run_command, name, command): name
                for name, command in self.commands.items()
            }

            for future in as_completed(futures):
                name = futures[future]

                try:
                    raw_result = future.result()
                    results[name] = self.parse_result(raw_result)
                except Exception as exc:
                    results[name] = {
                        "name": name,
                        "status": "failed",
                        "error": str(exc),
                    }

        return results


if __name__ == "__main__":
    commands = {
        "hostname": ["hostname"],
        "kernel": ["uname", "-r"],
        "disk_usage": ["df", "-h", "/"],
        "memory": ["free", "-m"],
        "interfaces": ["ip", "-j", "addr", "show"],
    }

    runner = ParallelSubprocessRunner(
        commands=commands,
        timeout=10,
        max_workers=5,
    )

    results = runner.run_all()

    print(json.dumps(results, indent=2))




# 4:39 PM


# Default permissions

# 5.5
# Extra High


# Work locally
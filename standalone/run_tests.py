#!/usr/bin/env python3

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMANDS = {
    "hostname": ["hostname"],
    "kernel": ["uname", "-r"],
    "disk_usage": ["df", "-h", "/"],
    "memory": ["free", "-m"],
    "interfaces": ["ip", "-j", "addr", "show"],
}


def run_command(name, command, timeout=10):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
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
            "stderr": f"Command timed out after {timeout}s",
        }


def parse_result(result):
    name = result["name"]

    if not result["success"]:
        return {
            "name": name,
            "status": "failed",
            "error": result["stderr"],
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


def run_parallel_commands(commands):
    parsed_results = {}

    with ThreadPoolExecutor(max_workers=len(commands)) as executor:
        futures = {
            executor.submit(run_command, name, command): name
            for name, command in commands.items()
        }

        for future in as_completed(futures):
            name = futures[future]
            raw_result = future.result()
            parsed_results[name] = parse_result(raw_result)

    return parsed_results


def main():
    results = run_parallel_commands(COMMANDS)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
Example output shape:

json

{
  "hostname": {
    "name": "hostname",
    "status": "ok",
    "hostname": "raspberrypi"
  },
  "kernel": {
    "name": "kernel",
    "status": "ok",
    "kernel_version": "6.6.20+rpt-rpi-v8"
  }
}

For subprocesses that produce JSON, parse with json.loads(stdout). For plain text commands, parse line-by-line or with regex depending on the format.
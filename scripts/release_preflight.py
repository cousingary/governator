#!/usr/bin/env python3
"""scripts/release_preflight.py -- Sol11 rc5 Session 3 (P1-5): records the
host conditions a release attempt started under, BEFORE any test tier runs.

None of these probes is release-blocking -- this is diagnostic evidence, not
a gate. On a host that can't answer a given probe (no systemd, no Docker
CLI, no /proc, sandboxed container without Landlock introspection), the
field records "unknown" rather than raising, so a benign host difference
never turns preflight collection itself into a release failure. What it
buys: on an abnormal termination, whatever was already written to
$OUT_DIR/preflight.json when the process died lets a human reconstruct
"was this host under memory/disk pressure, was Docker running, what
GOMAXPROCS/-parallel was this attempt using" without having to guess.
"""
from __future__ import annotations

import argparse
import json
import platform
import resource
import shutil
import subprocess
import sys


def safe(fn):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - preflight must never raise
        return f"unknown ({exc.__class__.__name__}: {exc})"


def disk_and_mem():
    disk = safe(lambda: dict(zip(("total", "used", "free"), shutil.disk_usage("."))))
    if isinstance(disk, dict):
        disk = {k: int(v) for k, v in disk.items()}

    def read_meminfo():
        out = {}
        with open("/proc/meminfo", encoding="utf-8") as f:
            for line in f:
                key, _, rest = line.partition(":")
                rest = rest.strip()
                if rest.endswith("kB"):
                    out[key] = int(rest[:-2].strip()) * 1024
        return {
            "mem_total_bytes": out.get("MemTotal"),
            "mem_available_bytes": out.get("MemAvailable"),
            "swap_total_bytes": out.get("SwapTotal"),
            "swap_free_bytes": out.get("SwapFree"),
        }

    mem = safe(read_meminfo)
    return disk, mem


def ulimits():
    def collect():
        limits = {}
        for name, res in (("nofile", resource.RLIMIT_NOFILE), ("nproc", getattr(resource, "RLIMIT_NPROC", None))):
            if res is None:
                limits[name] = "unavailable"
                continue
            soft, hard = resource.getrlimit(res)
            limits[name] = {"soft": soft, "hard": hard}
        return limits

    return safe(collect)


def run_ok(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=5)
        return proc.stdout.strip() or ("ok" if proc.returncode == 0 else f"exit {proc.returncode}")
    except FileNotFoundError:
        return "unavailable (binary not found)"
    except Exception as exc:  # noqa: BLE001
        return f"unknown ({exc.__class__.__name__}: {exc})"


def docker_systemd_state():
    docker = "unavailable"
    if shutil.which("docker"):
        docker = run_ok(["docker", "info", "--format", "{{.ServerVersion}}"])
    systemd = "unavailable"
    if shutil.which("systemctl"):
        systemd = run_ok(["systemctl", "is-system-running"])
    return docker, systemd


def landlock_capability():
    try:
        with open("/proc/sys/kernel/osrelease", encoding="utf-8") as f:
            osrelease = f.read().strip()
    except OSError:
        osrelease = "unknown"
    # Landlock ABI introspection requires a syscall this pure-stdlib probe
    # cannot make portably; recording the kernel release is the best-effort
    # signal a human can cross-reference against Landlock ABI version
    # tables without this script depending on a Go/cgo helper.
    return {"kernel_release": osrelease, "landlock_abi": "unknown (best-effort: cross-reference kernel_release)"}


def kernel_wsl():
    uname = safe(lambda: " ".join(platform.uname()))
    is_wsl = "unknown"
    try:
        with open("/proc/version", encoding="utf-8") as f:
            content = f.read()
        is_wsl = "microsoft" in content.lower() or "wsl" in content.lower()
    except OSError:
        pass
    return uname, is_wsl


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--release-attempt-id", required=True)
    p.add_argument("--go-test-parallelism", required=True)
    p.add_argument("--platforms", required=True)
    p.add_argument("--go-bin", required=True, help="approved Go executable from release-tool policy")
    args = p.parse_args(argv)

    disk, mem = disk_and_mem()
    docker, systemd = docker_systemd_state()
    uname, is_wsl = kernel_wsl()
    go_version = run_ok([args.go_bin, "version"])
    python_version = platform.python_version()

    data = {
        "release_attempt_id": args.release_attempt_id,
        "disk": disk,
        "memory": mem,
        "ulimits": ulimits(),
        "docker_server_version": docker,
        "systemd_state": systemd,
        "landlock": landlock_capability(),
        "go_version": go_version,
        "python_version": python_version,
        "cpu_concurrency": {
            "go_test_parallelism": args.go_test_parallelism,
            "cpu_count": safe(lambda: __import__("os").cpu_count()),
            "platforms": args.platforms.split(),
        },
        "uname": uname,
        "is_wsl": is_wsl,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"release_preflight: wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

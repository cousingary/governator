#!/usr/bin/env python3
"""Emit the tri-state capability evidence used by the red-team release gate."""

from __future__ import annotations

import datetime
import json
import os
import platform
import subprocess


def env_flag(name: str) -> bool:
    return os.environ.get(name, "") == "1"


def record(present: bool, probe: str, result: str = "") -> dict[str, str]:
    return {
        "state": "present" if present else "absent",
        "probe": probe,
        "result": result,
        "host_identity": platform.node(),
        "platform": f"{platform.system().lower()}/{go_arch()}",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }


def docker_daemon_reachable(docker: str) -> bool:
    if not docker:
        return False
    try:
        return subprocess.run([docker, "info"], capture_output=True, timeout=5).returncode == 0
    except OSError:
        return False


def go_arch() -> str:
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine().lower(), platform.machine().lower())


def systemd_user_reachable(systemctl: str) -> bool:
    if not os.path.exists(f"/run/user/{os.getuid()}/bus"):
        return False
    try:
        return subprocess.run([systemctl, "--user", "show-environment"], capture_output=True, timeout=5).returncode == 0
    except OSError:
        return False


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--git-bin", default="git")
    parser.add_argument("--docker-bin", default="")
    parser.add_argument("--systemctl-bin", default="systemctl")
    args = parser.parse_args()
    has_systemd_user = systemd_user_reachable(args.systemctl_bin)
    proc1_unreadable = os.path.isdir("/proc/1") and not os.access("/proc/1/fd", os.R_OK)
    system = platform.system()
    docker = docker_daemon_reachable(args.docker_bin)
    print(json.dumps({
        "linux": record(system == "Linux", "platform.system()", system),
        "has_systemd_user": record(has_systemd_user, "systemctl --user show-environment with live /run/user/<uid>/bus (5s timeout)", str(has_systemd_user)),
        "no_systemd_user": record(not has_systemd_user, "complement of has_systemd_user", str(not has_systemd_user)),
        "has_second_uid": record(env_flag("GOV_REDTEAM_HAS_SECOND_UID"), "env GOV_REDTEAM_HAS_SECOND_UID"),
        "has_kernel_landlock_full_abi": record(env_flag("GOV_REDTEAM_HAS_LANDLOCK_FULL_ABI"), "env GOV_REDTEAM_HAS_LANDLOCK_FULL_ABI"),
        "case8_hangfuse_extinction_fixture": record(os.environ.get("GOV_REDTEAM_CASE8_HANGFUSE", "0") == "1", "env GOV_REDTEAM_CASE8_HANGFUSE (operator attests kernel keeps FUSE-blocked readers unkillable)"),
        "git_trusted": record(os.path.isfile(args.git_bin), "explicit --git-bin", args.git_bin),
        "proc1_fd_unreadable": record(proc1_unreadable, "os.access(/proc/1/fd, R_OK)", str(proc1_unreadable)),
        "has_docker_daemon": record(docker, "docker info (5s timeout)", str(docker)),
        "has_darwin_native_host": record(system == "Darwin", "platform.system()", system),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
